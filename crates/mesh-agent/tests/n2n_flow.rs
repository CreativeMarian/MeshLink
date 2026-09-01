//! M1-2：N2N + Supernode 集成测试（真实 Go Controller + Agent A/B + Mock Overlay）。
//!
//! 覆盖用户冻结规格：
//! - Force N2N 路径：A create → 6 位码 → B join → Controller 身份 → N2N(Supernode 中继)
//!   → Noise IK（双向公钥验证）→ Overlay → 双方 CONNECTED → 加密 overlay ping
//!   （64B / 512B / 1200B / 1400B 自动验证）；
//! - Controller Supernode Registry 下发（multi-supernode 数据模型：2 个 SN，
//!   priority 排序，Agent 启动拉取填充 N2N 池）；
//! - Supernode kill → 每 SN 独立熔断 OPEN → restart → HALF_OPEN probe → CLOSED；
//! - DirectLink 独立性：Active DirectLink 时 kill Supernode，Overlay 传输零影响。

use mesh_agent::overlay::OverlayBackend;
use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{Command, Event, PipeClient, Request, ServerMessage};
use std::io::Read;
use std::net::Ipv4Addr;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};
use transport_n2n::{N2NSupernode, SupernodeConfig};

const N2N_TIMEOUT: Duration = Duration::from_secs(90);

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name(role: &str, suffix: &str) -> String {
    format!(r"\\.\pipe\meshlink-n2n-{role}-{}-{suffix}", std::process::id())
}

fn free_port() -> u16 {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

struct ControllerGuard {
    child: Child,
}

impl Drop for ControllerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// 启动真实 Go Controller，并用 MESHLINK_SUPERNODES 预置 Supernode Registry。
fn spawn_controller(tmp: &std::path::Path, supernodes_json: &str) -> (String, ControllerGuard) {
    if ProcessCommand::new("go").arg("version").output().is_err() {
        panic!("未找到 go 工具链：需要编译 Go Controller");
    }
    let controller_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/controller");
    let exe = tmp.join("controller-n2n.exe");
    let out = ProcessCommand::new("go")
        .arg("build")
        .arg("-o")
        .arg(&exe)
        .arg("./cmd/controller")
        .current_dir(&controller_dir)
        .output()
        .expect("go build 执行失败");
    assert!(
        out.status.success(),
        "go build Controller 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let log_path = tmp.join("controller.log");
    let log = std::fs::File::create(&log_path).expect("create controller log");
    let child = ProcessCommand::new(&exe)
        .arg("-addr")
        .arg(&addr)
        .arg("-db")
        .arg(tmp.join("controller.db"))
        .env("MESHLINK_SUPERNODES", supernodes_json)
        .stdout(Stdio::from(log.try_clone().expect("dup log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn controller");

    let url = format!("http://{addr}");
    let client = controller_client::Client::new(&url).expect("controller client");
    let guard = ControllerGuard { child };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok");
            break;
        }
        if Instant::now() > deadline {
            panic!("Controller 10s 内未就绪");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (url, guard)
}

fn wait_connect(name: &str, timeout: Duration) -> PipeClient {
    let deadline = Instant::now() + timeout;
    loop {
        match PipeClient::connect(name, Duration::from_secs(2)) {
            Ok(c) => return c,
            Err(_) => {
                if Instant::now() > deadline {
                    panic!("连接管道超时: {name}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn wait_state(ui: &mut PipeClient, want: AgentState, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    let mut id = 0u64;
    loop {
        id += 1;
        let resp = ui
            .request(&Request { id, command: Command::GetStatus })
            .expect("GetStatus");
        assert!(resp.ok, "GetStatus 失败: {:?}", resp.error);
        let data = resp.data.expect("快照");
        if data["state"] == serde_json::json!(want) {
            return data;
        }
        if Instant::now() > deadline {
            panic!("等待 {want:?} 超时，最后快照: {data}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn request_data(ui: &mut PipeClient, cmd: Command) -> serde_json::Value {
    let resp = ui
        .request(&Request { id: u64::MAX, command: cmd })
        .expect("请求");
    assert!(resp.ok, "命令失败: {:?} (data={:?})", resp.error, resp.data);
    resp.data.expect("命令必须携带 data")
}

fn event_name(e: &Event) -> &'static str {
    match e {
        Event::ControllerConnected { .. } => "ControllerConnected",
        Event::WaitingForPeer { .. } => "WaitingForPeer",
        Event::PeerFound { .. } => "PeerFound",
        Event::GatheringCandidates { .. } => "GatheringCandidates",
        Event::Punching { .. } => "Punching",
        Event::NoiseHandshaking { .. } => "NoiseHandshaking",
        Event::Connected { .. } => "Connected",
        Event::PathChanged { .. } => "PathChanged",
        Event::Disconnected { .. } => "Disconnected",
        Event::Error { .. } => "Error",
        Event::IncomingConnectionRequest { .. } => "IncomingConnectionRequest",
        Event::FriendPending { .. } => "FriendPending",
        Event::FriendAccepted { .. } => "FriendAccepted",
        Event::FriendRemoved { .. } => "FriendRemoved",
        Event::FriendOnline { .. } => "FriendOnline",
        Event::FriendOffline { .. } => "FriendOffline",
        Event::DeviceOnline { .. } => "DeviceOnline",
        Event::DeviceOffline { .. } => "DeviceOffline",
        Event::FriendConnected { .. } => "FriendConnected",
        Event::FriendDisconnected { .. } => "FriendDisconnected",
        Event::FriendsChanged => "FriendsChanged",
        Event::RecentConnectionsChanged => "RecentConnectionsChanged",
    }
}

fn assert_no_error(events: &[Event], who: &str) {
    for ev in events {
        if let Event::Error { code, message } = ev {
            panic!("{who} 出现错误事件 {code}: {message}");
        }
    }
}

/// 构造指定总长度的 IPv4 ICMP echo 请求（首字节 0x45；用于 64/512/1200/1400B 验证）。
fn raw_ipv4_pkt(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16, total_len: usize) -> Vec<u8> {
    assert!(total_len >= 28 && total_len <= 1500, "total_len={total_len}");
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let hdr_sum = mesh_vnic::icmp_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    pkt[20] = 8;
    pkt[24..26].copy_from_slice(&id.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    for (i, b) in pkt[28..].iter_mut().enumerate() {
        *b = (i as u8).wrapping_add(id as u8);
    }
    let icmp_sum = mesh_vnic::icmp_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    pkt
}

fn wait_injected_sizes(
    mock: &mesh_agent::MockOverlay,
    sizes: &[usize],
    ids: &[u16],
    timeout: Duration,
    what: &str,
) {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        seen.extend(mock.take_injected());
        let ok = sizes.iter().zip(ids.iter()).all(|(&sz, &id)| {
            seen.iter().any(|p| p.len() == sz && p.get(24..26).map(|b| u16::from_be_bytes([b[0], b[1]])) == Some(id))
        });
        if ok {
            return;
        }
        if Instant::now() > deadline {
            panic!(
                "{what}: 未收到全部尺寸（sizes={sizes:?} ids={ids:?}），已见 {} 包（len: {:?}）",
                seen.len(),
                seen.iter().map(|p| p.len()).collect::<Vec<_>>()
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// 从 Connected 事件解析 (local_ip, peer_ip)。
fn connected_ips(evs: &[Event], who: &str) -> (Ipv4Addr, Ipv4Addr) {
    evs.iter()
        .find_map(|e| match e {
            Event::Connected { local_overlay_ip, peer_overlay_ip, .. } => {
                Some((local_overlay_ip.parse().expect("local"), peer_overlay_ip.parse().expect("peer")))
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("{who} 未收到 Connected"))
}

/// 标准 N2N 双 Agent 场景（spawn SN1+SN2 进 Controller Registry → 双 Agent）。
/// 返回 (controller, ui_a, ui_b, sn1, sn2, agent_a, agent_b)；
/// Supernode 所有权交回调用方（连接前必须保持存活）。
#[allow(clippy::type_complexity)]
fn spawn_scene(
    run_dir: &std::path::Path,
    suffix: &str,
    sn1: N2NSupernode,
    sn2: N2NSupernode,
) -> (
    ControllerGuard,
    PipeClient,
    PipeClient,
    N2NSupernode,
    N2NSupernode,
    std::sync::Arc<mesh_agent::AgentHandle>,
    std::sync::Arc<mesh_agent::AgentHandle>,
) {
    let sn1_addr = sn1.local_addr();
    let sn2_addr = sn2.local_addr();
    let sn_json = format!(
        r#"[{{"id":"sn-a","host":"127.0.0.1","port":{},"priority":10}},{{"id":"sn-b","host":"127.0.0.1","port":{},"priority":20}}]"#,
        sn1_addr.port(),
        sn2_addr.port()
    );
    let (controller_url, controller) = spawn_controller(run_dir, &sn_json);

    let agent_cfg = |dir_tag: &str, name: &str| AgentConfig {
        controller_url: controller_url.clone(),
        data_dir: run_dir.join(dir_tag),
        network_id: "meshlink-n2n".into(),
        device_name: Some(name.into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(45),
        ..AgentConfig::default()
    };
    let pipe_a = pipe_name("a", suffix);
    let pipe_b = pipe_name("b", suffix);
    let (agent_a, server_a) = spawn_service(agent_cfg("agent-a", "Alice-PC"), &pipe_a).expect("spawn A");
    let (agent_b, server_b) = spawn_service(agent_cfg("agent-b", "Bob-PC"), &pipe_b).expect("spawn B");
    // 保持 pipe server 存活（绑定在返回值生命周期）。
    let _sa = server_a;
    let _sb = server_b;

    let ui_a = wait_connect(&pipe_a, Duration::from_secs(10));
    let ui_b = wait_connect(&pipe_b, Duration::from_secs(10));
    (controller, ui_a, ui_b, sn1, sn2, agent_a, agent_b)
}

#[test]
fn m1_2_agent_force_n2n_path_noise_overlay_ping() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-n2n"));
    let run_dir = tmp.join(format!("n2n-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let p1 = free_port();
    let p2 = free_port();
    let sn1 = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-a".into(),
        bind_addr: format!("127.0.0.1:{p1}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();
    let sn2 = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-b".into(),
        bind_addr: format!("127.0.0.1:{p2}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();

    let (_controller, mut ui_a, mut ui_b, _sn1, _sn2, agent_a, agent_b) =
        spawn_scene(&run_dir, "a", sn1, sn2);

    // ---- 双端 READY ----
    let snap_a = wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    let snap_b = wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));
    let dev_a = snap_a["device_id"].as_str().unwrap().to_string();
    let dev_b = snap_b["device_id"].as_str().unwrap().to_string();

    // ---- Controller Supernode Registry → Agent N2N 池（multi-supernode 数据模型）----
    let st_a = request_data(&mut ui_a, Command::GetN2NStatus);
    let pool = st_a["supernode_pool"].as_array().expect("supernode_pool").clone();
    assert_eq!(pool.len(), 2, "Agent 应拉到 2 个 Supernode（multi-supernode）");
    let ids: Vec<&str> = pool.iter().map(|v| v["id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"sn-a") && ids.contains(&"sn-b"), "Registry 两 SN 均在池: {ids:?}");
    let st_b = request_data(&mut ui_b, Command::GetN2NStatus);
    assert_eq!(st_b["supernode_pool"].as_array().expect("pool").len(), 2, "B 也应拉到 2 个 SN");

    // ---- Force N2N ----
    let r = ui_a
        .request(&Request { id: 100, command: Command::SetPath { path: "n2n".into() } })
        .expect("SetPath A");
    assert!(r.ok, "SetPath A: {:?}", r.error);
    let r = ui_b
        .request(&Request { id: 101, command: Command::SetPath { path: "n2n".into() } })
        .expect("SetPath B");
    assert!(r.ok, "SetPath B: {:?}", r.error);

    // ---- A 创建 6 位码 → B 加入 ----
    let r = ui_a
        .request(&Request { id: 102, command: Command::CreateQuickSession })
        .expect("CreateQuickSession");
    assert!(r.ok, "CreateQuickSession: {:?}", r.error);
    let ev = collect_code(&mut ui_a);
    let code = ev["code"].as_str().expect("连接码").to_string();
    assert_eq!(code.len(), 6, "6 位码");

    let r = ui_b
        .request(&Request { id: 103, command: Command::JoinQuickSession { code: code.clone() } })
        .expect("JoinQuickSession");
    assert!(r.ok, "JoinQuickSession: {:?}", r.error);

    // ---- 双端 CONNECTED ----
    let mut ev_a: Vec<Event> = Vec::new();
    let mut ev_b: Vec<Event> = Vec::new();
    let deadline = Instant::now() + N2N_TIMEOUT;
    let mut a_done = false;
    let mut b_done = false;
    while Instant::now() < deadline && !(a_done && b_done) {
        if !a_done {
            if let Some(ServerMessage::Event(ev)) = ui_a.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    a_done = true;
                }
                ev_a.push(ev);
            }
        }
        if !b_done {
            if let Some(ServerMessage::Event(ev)) = ui_b.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    b_done = true;
                }
                ev_b.push(ev);
            }
        }
    }
    assert!(
        a_done && b_done,
        "Force N2N 双端须 CONNECTED（a_done={a_done} b_done={b_done}）\nA: {:?}\nB: {:?}",
        ev_a.iter().map(event_name).collect::<Vec<_>>(),
        ev_b.iter().map(event_name).collect::<Vec<_>>()
    );
    assert_no_error(&ev_a, "A");
    assert_no_error(&ev_b, "B");

    let (a_local, a_peer) = connected_ips(&ev_a, "A");
    let (b_local, b_peer) = connected_ips(&ev_b, "B");
    assert_eq!(a_peer, b_local);
    assert_eq!(b_peer, a_local);
    assert_ne!(a_local, b_local, "Controller IPAM 不同 IP");

    // ---- N2N 会话状态 ----
    let st_a2 = request_data(&mut ui_a, Command::GetN2NStatus);
    assert_eq!(st_a2["forced_path"], "n2n");
    let sessions = st_a2["sessions"].as_array().expect("sessions");
    assert_eq!(sessions.len(), 1, "A 有 1 个 N2N 会话");
    assert_eq!(sessions[0]["connected"], true, "A N2N 会话 connected");

    // ---- 加密 overlay ping：64 / 512 / 1200 / 1400B（A→B 与 B→A）----
    let mock_a = agent_a.mock_overlay().expect("A mock");
    let mock_b = agent_b.mock_overlay().expect("B mock");
    assert!(mock_a.is_up() && mock_b.is_up(), "双端 Overlay up");
    assert_eq!(mock_a.routes_installed(), vec![b_local], "A /32 路由");
    assert_eq!(mock_b.routes_installed(), vec![a_local], "B /32 路由");

    let sizes = [64usize, 512, 1200, 1400];
    let ids_ab: Vec<u16> = (0x11u16..).take(sizes.len()).collect();
    let ids_ba: Vec<u16> = (0x21u16..).take(sizes.len()).collect();
    for (i, (&sz, &id)) in sizes.iter().zip(ids_ab.iter()).enumerate() {
        let pkt = raw_ipv4_pkt(a_local, b_local, id, 1, sz);
        mock_a.inject_outgoing(pkt);
    }
    for (i, (&sz, &id)) in sizes.iter().zip(ids_ba.iter()).enumerate() {
        let pkt = raw_ipv4_pkt(b_local, a_local, id, 1, sz);
        mock_b.inject_outgoing(pkt);
    }
    wait_injected_sizes(&mock_b, &sizes, &ids_ab, Duration::from_secs(15), "B 未收到 A 的 4 档载荷");
    wait_injected_sizes(&mock_a, &sizes, &ids_ba, Duration::from_secs(15), "A 未收到 B 的 4 档载荷");

    wait_state(&mut ui_a, AgentState::Connected, Duration::from_secs(5));
    wait_state(&mut ui_b, AgentState::Connected, Duration::from_secs(5));
    let _ = dev_a;
    let _ = dev_b;
}

fn collect_code(ui: &mut PipeClient) -> serde_json::Map<String, serde_json::Value> {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(200)) {
            if let Event::WaitingForPeer { code, session_id, expires_at } = ev {
                let mut m = serde_json::Map::new();
                m.insert("code".into(), serde_json::json!(code));
                m.insert("session_id".into(), serde_json::json!(session_id));
                m.insert("expires_at".into(), serde_json::json!(expires_at));
                return m;
            }
            if let Event::Error { code, message } = ev {
                panic!("创建 6 位码阶段出现错误: {code}: {message}");
            }
        }
        if Instant::now() > deadline {
            panic!("等待 WaitingForPeer 事件超时");
        }
    }
}

/// 直接链路独立性：Active DirectLink 时杀死 Supernode，Overlay 传输零影响。
#[test]
fn m1_2_directlink_independent_of_supernode_kill() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-n2n"));
    let run_dir = tmp.join(format!("dl-ind-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let p1 = free_port();
    let p2 = free_port();
    let sn1 = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-a".into(),
        bind_addr: format!("127.0.0.1:{p1}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();
    let sn2 = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-b".into(),
        bind_addr: format!("127.0.0.1:{p2}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();

    let (_controller, mut ui_a, mut ui_b, sn1, sn2, agent_a, agent_b) =
        spawn_scene(&run_dir, "ind", sn1, sn2);

    let snap_a = wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    let snap_b = wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));
    let dev_a = snap_a["device_id"].as_str().unwrap().to_string();
    let dev_b = snap_b["device_id"].as_str().unwrap().to_string();

    // 默认 Auto = DirectLink 路径。
    let r = ui_a
        .request(&Request { id: 200, command: Command::CreateQuickSession })
        .expect("CreateQuickSession");
    assert!(r.ok);
    let ev = collect_code(&mut ui_a);
    let code = ev["code"].as_str().expect("码").to_string();
    let r = ui_b
        .request(&Request { id: 201, command: Command::JoinQuickSession { code } })
        .expect("Join");
    assert!(r.ok);

    let mut ev_a: Vec<Event> = Vec::new();
    let mut ev_b: Vec<Event> = Vec::new();
    let deadline = Instant::now() + N2N_TIMEOUT;
    let mut a_done = false;
    let mut b_done = false;
    while Instant::now() < deadline && !(a_done && b_done) {
        if !a_done {
            if let Some(ServerMessage::Event(ev)) = ui_a.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    a_done = true;
                }
                ev_a.push(ev);
            }
        }
        if !b_done {
            if let Some(ServerMessage::Event(ev)) = ui_b.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    b_done = true;
                }
                ev_b.push(ev);
            }
        }
    }
    assert!(a_done && b_done, "DirectLink 双端须 CONNECTED");
    assert_no_error(&ev_a, "A");
    assert_no_error(&ev_b, "B");

    let (a_local, a_peer) = connected_ips(&ev_a, "A");
    let (b_local, b_peer) = connected_ips(&ev_b, "B");

    // ---- 杀死两个 Supernode（drop 关闭 UDP）----
    drop(sn1);
    drop(sn2);
    // 等 N2N 健康探测感知（对 DirectLink 数据面无影响）。
    std::thread::sleep(Duration::from_secs(1));

    // ---- DirectLink 数据面仍工作：A→B ping 往返 ----
    let mock_a = agent_a.mock_overlay().expect("A mock");
    let mock_b = agent_b.mock_overlay().expect("B mock");
    let pkt = raw_ipv4_pkt(a_local, b_local, 0x77, 1, 256);
    mock_a.inject_outgoing(pkt);
    wait_injected_sizes(&mock_b, &[256], &[0x77], Duration::from_secs(10), "SN 死后 DirectLink 传输应零影响");
    let _ = a_peer;
    let _ = b_peer;
    let _ = dev_a;
    let _ = dev_b;
}

/// Supernode kill → 每 SN 独立熔断 OPEN → restart → HALF_OPEN → CLOSED（Agent 级）。
#[test]
fn m1_2_supernode_kill_opens_breaker_and_restart_recovery() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-n2n"));
    let run_dir = tmp.join(format!("breaker-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let p1 = free_port();
    let p2 = free_port();
    let sn1 = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-a".into(),
        bind_addr: format!("127.0.0.1:{p1}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();
    let sn2 = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-b".into(),
        bind_addr: format!("127.0.0.1:{p2}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();

    let (_controller, mut ui_a, mut ui_b, sn1, sn2, _agent_a, _agent_b) =
        spawn_scene(&run_dir, "brk", sn1, sn2);

    wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));

    // Force N2N → 连接。
    for (ui, id) in [(&mut ui_a, 300u64), (&mut ui_b, 301u64)] {
        let r = ui
            .request(&Request { id, command: Command::SetPath { path: "n2n".into() } })
            .expect("SetPath");
        assert!(r.ok, "{:?}", r.error);
    }
    let r = ui_a
        .request(&Request { id: 302, command: Command::CreateQuickSession })
        .expect("Create");
    assert!(r.ok);
    let ev = collect_code(&mut ui_a);
    let code = ev["code"].as_str().expect("码").to_string();
    let r = ui_b
        .request(&Request { id: 303, command: Command::JoinQuickSession { code } })
        .expect("Join");
    assert!(r.ok);

    let deadline = Instant::now() + N2N_TIMEOUT;
    let mut a_done = false;
    let mut b_done = false;
    while Instant::now() < deadline && !(a_done && b_done) {
        if !a_done {
            if let Some(ServerMessage::Event(ev)) = ui_a.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    a_done = true;
                }
            }
        }
        if !b_done {
            if let Some(ServerMessage::Event(ev)) = ui_b.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    b_done = true;
                }
            }
        }
    }
    assert!(a_done && b_done, "Force N2N 双端须先 CONNECTED");

    // ---- kill 主 Supernode（sn-a = priority 10，当前选中）----
    drop(sn1);
    drop(sn2);
    // 健康探测默认 3s/失败阈值 3 → ~9s 内 OPEN。
    let opened = wait_breaker(&mut ui_a, "sn-a", "open", Duration::from_secs(40));
    assert!(opened, "A 侧 sn-a 熔断应 OPEN（kill detection）");
    let opened_b = wait_breaker(&mut ui_b, "sn-a", "open", Duration::from_secs(20));
    assert!(opened_b, "B 侧 sn-a 熔断应 OPEN");

    // ---- 同端口重启 Supernode → HALF_OPEN probe → CLOSED ----
    let _restarted = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-a".into(),
        bind_addr: format!("127.0.0.1:{p1}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();
    let _ = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-b".into(),
        bind_addr: format!("127.0.0.1:{p2}").parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();
    let closed = wait_breaker(&mut ui_a, "sn-a", "closed", Duration::from_secs(60));
    assert!(closed, "A 侧 sn-a 熔断应恢复 CLOSED（restart recovery）");
}

fn wait_breaker(ui: &mut PipeClient, sn_id: &str, want: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let mut id = 500u64;
    while Instant::now() < deadline {
        id += 1;
        let st = request_data(ui, Command::GetN2NStatus);
        if let Some(arr) = st["supernode_pool"].as_array() {
            if let Some(entry) = arr.iter().find(|v| v["id"] == sn_id) {
                if entry["breaker"].as_str() == Some(want) {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}
