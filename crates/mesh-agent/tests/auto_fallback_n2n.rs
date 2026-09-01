//! M1-2：DirectLink 建链失败 → Auto 路径自动回退 N2N Supernode Relay（集成测试）。
//!
//! 覆盖用户最新规格：
//! - 保留 DirectLink 架构不破坏（默认 Auto 仍先尝试 DirectLink）；
//! - `MESHLINK_FORCE_DIRECTLINK_FAIL` 注入模拟 DirectLink 建链失败（creator Noise
//!   握手超时 / joiner 打洞失败）→ Auto 路径自动尝试 N2N Supernode Relay；
//! - 回退后：Controller 身份 → N2N(SN 中继) → Noise IK（双向公钥验证）→ Overlay
//!   → 双方 CONNECTED → 加密 overlay ping（64/512/1200/1400B 自动验证）；
//! - Connected 事件携带实际路径 `n2n`，GetStatus.current_path == "n2n"，
//!   recent_connection.last_path == "n2n"（Auto+实际 N2N 不再误标 directlink）；
//! - Force N2N（非 Auto）保持不回退语义；DirectLink 成功仍走 directlink。

use mesh_agent::overlay::OverlayBackend;
use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{Command, Event, PipeClient, Request, ServerMessage};
use std::net::Ipv4Addr;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use transport_n2n::{N2NSupernode, SupernodeConfig};

const N2N_TIMEOUT: Duration = Duration::from_secs(90);

/// 同文件两用例各自拉起独立 Controller + Supernode + 双 Agent，且 DirectLink 打洞在
/// 127.0.0.1 回环上运行——workspace 并行时两用例会互相争用回环 UDP 打洞资源，偶发
/// DirectLink 建链失败误触发回退（force 用例被干扰）。强制本文件用例串行执行。
static SERIAL: Mutex<()> = Mutex::new(());

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name(role: &str, suffix: &str) -> String {
    format!(r"\\.\pipe\meshlink-fb-{role}-{}-{suffix}", std::process::id())
}

fn free_port() -> u16 {
    // 用 UDP 探测空闲端口（Supernode 绑定的是 UDP；TCP 空闲端口不代表 UDP 可用）。
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("udp bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    port
}

/// 绑定一个 N2N Supernode；端口被占用（Windows 独占绑定）时换端口重试。
fn bind_sn(id: &str, tag: &str) -> N2NSupernode {
    for _ in 0..30 {
        let p = free_port();
        if let Ok(sn) = N2NSupernode::bind(SupernodeConfig {
            sn_id: id.into(),
            bind_addr: format!("127.0.0.1:{p}").parse().unwrap(),
            ..SupernodeConfig::default()
        }) {
            return sn;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("{tag}: 无法绑定 N2N Supernode UDP 端口");
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
    let exe = tmp.join("controller-fb.exe");
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
    let log_path = tmp.join("controller-fb.log");
    let log = std::fs::File::create(&log_path).expect("create controller log");
    let child = ProcessCommand::new(&exe)
        .arg("-addr")
        .arg(&addr)
        .arg("-db")
        .arg(tmp.join("controller-fb.db"))
        .env("MESHLINK_SUPERNODES", supernodes_json)
        .stdout(Stdio::from(log.try_clone().expect("dup log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn controller");

    let url = format!("http://{addr}");
    let client = controller_client::Client::new(&url).expect("controller client");
    let guard = ControllerGuard { child };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok");
            break;
        }
        if Instant::now() > deadline {
            panic!("Controller 30s 内未就绪");
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

/// 从 Connected 事件解析 (local_ip, peer_ip, path)。
fn connected_info(evs: &[Event], who: &str) -> (Ipv4Addr, Ipv4Addr, String) {
    evs.iter()
        .find_map(|e| match e {
            Event::Connected { local_overlay_ip, peer_overlay_ip, path, .. } => Some((
                local_overlay_ip.parse().expect("local"),
                peer_overlay_ip.parse().expect("peer"),
                path.clone(),
            )),
            _ => None,
        })
        .unwrap_or_else(|| panic!("{who} 未收到 Connected"))
}

/// 构造指定总长度的 IPv4 ICMP echo 请求（首字节 0x45）。
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

fn collect_code(ui: &mut PipeClient) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(200)) {
            if let Event::WaitingForPeer { code, .. } = ev {
                return code;
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

/// 创建双 SN Registry + 双 Agent 场景（force_directlink_fail 注入）。
/// 返回所有权（SN 必须在连接期间保持存活——drop 会关闭 UDP socket）。
#[allow(clippy::type_complexity)]
fn spawn_scene(
    run_dir: &std::path::Path,
    suffix: &str,
    sn1: N2NSupernode,
    sn2: N2NSupernode,
    force_fail: bool,
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
        network_id: "meshlink-fb".into(),
        device_name: Some(name.into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(45),
        force_directlink_fail: force_fail,
        ..AgentConfig::default()
    };
    let pipe_a = pipe_name("a", suffix);
    let pipe_b = pipe_name("b", suffix);
    let (agent_a, server_a) = spawn_service(agent_cfg("agent-a", "Alice-PC"), &pipe_a).expect("spawn A");
    let (agent_b, server_b) = spawn_service(agent_cfg("agent-b", "Bob-PC"), &pipe_b).expect("spawn B");
    let _sa = server_a;
    let _sb = server_b;

    let ui_a = wait_connect(&pipe_a, Duration::from_secs(10));
    let ui_b = wait_connect(&pipe_b, Duration::from_secs(10));
    (controller, ui_a, ui_b, sn1, sn2, agent_a, agent_b)
}

/// 双端收事件直到双方 CONNECTED 或出现 Error；返回双端事件序列。
fn collect_until_connected(
    ui_a: &mut PipeClient,
    ui_b: &mut PipeClient,
) -> (Vec<Event>, Vec<Event>) {
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
        "双端须 CONNECTED（a_done={a_done} b_done={b_done}）\nA: {:?}\nB: {:?}",
        ev_a.iter().map(event_name).collect::<Vec<_>>(),
        ev_b.iter().map(event_name).collect::<Vec<_>>()
    );
    (ev_a, ev_b)
}

/// Auto 路径 + DirectLink 失败注入 → 自动回退 N2N → CONNECTED（path=n2n）→ 加密 ping。
#[test]
fn m1_2_auto_fallback_n2n_on_directlink_failure() {
    let _serial = SERIAL.lock().unwrap();
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug,n2n=debug,transport_n2n=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-n2n"));
    let run_dir = tmp.join(format!("fb-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let sn1 = bind_sn("sn-a", "test1");
    let sn2 = bind_sn("sn-b", "test1");

    let (_controller, mut ui_a, mut ui_b, _sn1, _sn2, agent_a, agent_b) =
        spawn_scene(&run_dir, "auto", sn1, sn2, true);

    // ---- 双端 READY（路径默认 Auto）----
    wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));
    let st_a = request_data(&mut ui_a, Command::GetN2NStatus);
    assert_eq!(st_a["forced_path"], "auto", "默认路径应为 Auto");
    assert_eq!(
        st_a["supernode_pool"].as_array().expect("pool").len(),
        2,
        "Supernode Registry 应下发到 Agent N2N 池"
    );

    // ---- A 创建 6 位码 → B 加入（Auto 路径）----
    let r = ui_a
        .request(&Request { id: 100, command: Command::CreateQuickSession })
        .expect("CreateQuickSession");
    assert!(r.ok, "CreateQuickSession: {:?}", r.error);
    let code = collect_code(&mut ui_a);
    assert_eq!(code.len(), 6, "6 位码");
    let r = ui_b
        .request(&Request { id: 101, command: Command::JoinQuickSession { code } })
        .expect("JoinQuickSession");
    assert!(r.ok, "JoinQuickSession: {:?}", r.error);

    // ---- DirectLink 失败注入 → 自动回退 N2N → 双端 CONNECTED ----
    let (ev_a, ev_b) = collect_until_connected(&mut ui_a, &mut ui_b);
    assert_no_error(&ev_a, "A");
    assert_no_error(&ev_b, "B");

    // 回退必须真实发生：双端都出现 PathChanged(n2n-fallback)。
    let fb_a = ev_a.iter().any(|e| matches!(e, Event::PathChanged { detail } if detail == "n2n-fallback"));
    let fb_b = ev_b.iter().any(|e| matches!(e, Event::PathChanged { detail } if detail == "n2n-fallback"));
    assert!(fb_a, "A 应发出 N2N 回退 PathChanged（实际事件: {:?}）", ev_a.iter().map(event_name).collect::<Vec<_>>());
    assert!(fb_b, "B 应发出 N2N 回退 PathChanged（实际事件: {:?}）", ev_b.iter().map(event_name).collect::<Vec<_>>());

    let (a_local, a_peer, a_path) = connected_info(&ev_a, "A");
    let (b_local, b_peer, b_path) = connected_info(&ev_b, "B");
    assert_eq!(a_path, "n2n", "A Connected 事件 path 应为 n2n（实际 {a_path}）");
    assert_eq!(b_path, "n2n", "B Connected 事件 path 应为 n2n（实际 {b_path}）");
    assert_eq!(a_peer, b_local);
    assert_eq!(b_peer, a_local);
    assert_ne!(a_local, b_local, "Controller IPAM 不同 IP");

    // ---- GetStatus.current_path == "n2n"（UI 据此显示 N2N Relay）----
    let snap_a = wait_state(&mut ui_a, AgentState::Connected, Duration::from_secs(5));
    assert_eq!(snap_a["current_path"], "n2n", "GetStatus.current_path 应为 n2n");

    // ---- recent_connection.last_path == "n2n"（Auto+实际 N2N 不再误标 directlink）----
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut seen_n2n = false;
    while Instant::now() < deadline && !seen_n2n {
        let rec = request_data(&mut ui_a, Command::ListRecentConnections);
        if let Some(arr) = rec["recent_connections"].as_array() {
            for r in arr {
                if r["remote_device_id"] == snap_a["session"]["peers"][0]["device_id"] {
                    seen_n2n = r["last_path"] == "n2n";
                    if !seen_n2n {
                        assert_eq!(
                            r["last_path"], "n2n",
                            "recent_connection.last_path 应记录实际路径 n2n（Auto+实际 N2N）"
                        );
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(seen_n2n, "recent_connection 应出现 last_path=n2n");

    // ---- 加密 overlay ping：64 / 512 / 1200 / 1400B（A→B 与 B→A）----
    let mock_a = agent_a.mock_overlay().expect("A mock");
    let mock_b = agent_b.mock_overlay().expect("B mock");
    assert!(mock_a.is_up() && mock_b.is_up(), "双端 Overlay up");
    assert_eq!(mock_a.routes_installed(), vec![b_local], "A /32 路由");
    assert_eq!(mock_b.routes_installed(), vec![a_local], "B /32 路由");

    let sizes = [64usize, 512, 1200, 1400];
    let ids_ab: Vec<u16> = (0x31u16..).take(sizes.len()).collect();
    let ids_ba: Vec<u16> = (0x41u16..).take(sizes.len()).collect();
    for (&sz, &id) in sizes.iter().zip(ids_ab.iter()) {
        let pkt = raw_ipv4_pkt(a_local, b_local, id, 1, sz);
        mock_a.inject_outgoing(pkt);
    }
    for (&sz, &id) in sizes.iter().zip(ids_ba.iter()) {
        let pkt = raw_ipv4_pkt(b_local, a_local, id, 1, sz);
        mock_b.inject_outgoing(pkt);
    }
    wait_injected_sizes(&mock_b, &sizes, &ids_ab, Duration::from_secs(15), "B 未收到 A 的 4 档载荷");
    wait_injected_sizes(&mock_a, &sizes, &ids_ba, Duration::from_secs(15), "A 未收到 B 的 4 档载荷");

    // ---- N2N 会话已建立（数据面走 SN 中继）----
    let st_a2 = request_data(&mut ui_a, Command::GetN2NStatus);
    let sessions = st_a2["sessions"].as_array().expect("sessions");
    assert_eq!(sessions.len(), 1, "A 有 1 个 N2N 会话");
    assert_eq!(sessions[0]["connected"], true, "A N2N 会话 connected");
}

/// 兼容性：Force N2N（非 Auto）保持原语义；DirectLink 未失败时不回退、仍走 directlink。
#[test]
fn m1_2_force_directlink_success_stays_directlink_no_fallback() {
    let _serial = SERIAL.lock().unwrap();
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-n2n"));
    let run_dir = tmp.join(format!("dl-fb-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let sn1 = bind_sn("sn-a", "test2");
    let sn2 = bind_sn("sn-b", "test2");

    // force_directlink_fail = false：DirectLink 正常建链。
    let (_controller, mut ui_a, mut ui_b, _sn1, _sn2, agent_a, agent_b) =
        spawn_scene(&run_dir, "dl", sn1, sn2, false);

    wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));

    let r = ui_a
        .request(&Request { id: 200, command: Command::CreateQuickSession })
        .expect("Create");
    assert!(r.ok);
    let code = collect_code(&mut ui_a);
    let r = ui_b
        .request(&Request { id: 201, command: Command::JoinQuickSession { code } })
        .expect("Join");
    assert!(r.ok);

    let (ev_a, ev_b) = collect_until_connected(&mut ui_a, &mut ui_b);
    assert_no_error(&ev_a, "A");
    assert_no_error(&ev_b, "B");

    // 未触发回退：不应出现 n2n-fallback PathChanged。
    assert!(
        !ev_a.iter().any(|e| matches!(e, Event::PathChanged { detail } if detail == "n2n-fallback")),
        "DirectLink 成功时不应回退 N2N"
    );

    let (a_local, a_peer, a_path) = connected_info(&ev_a, "A");
    let (_b_local, _b_peer, b_path) = connected_info(&ev_b, "B");
    assert_eq!(a_path, "directlink", "DirectLink 成功 → path=directlink");
    assert_eq!(b_path, "directlink", "DirectLink 成功 → path=directlink");

    // 数据面仍工作（DirectLink）。
    let mock_a = agent_a.mock_overlay().expect("A mock");
    let mock_b = agent_b.mock_overlay().expect("B mock");
    let pkt = raw_ipv4_pkt(a_local, a_peer, 0x51, 1, 256);
    mock_a.inject_outgoing(pkt);
    wait_injected_sizes(&mock_b, &[256], &[0x51], Duration::from_secs(10), "DirectLink 传输");
}
