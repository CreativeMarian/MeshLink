//! MVP Gate E2E（用户规格十三：自动化全链路 Gate，无人工步骤）。
//!
//! 模拟真实用户路径：真实 Go Controller + Agent A（creator）+ Agent B（joiner）
//! + Mock Overlay（模拟 Windows TCP/IP 栈：任意发给本机 Overlay IP 的 ICMP
//! Echo Request 自动应答）。
//!
//! 链路：A 经 IPC 管道 CreateQuickSession → 6 位码（WaitingForPeer 事件）→
//! B 经 IPC 管道 JoinQuickSession → Controller Device Registry 公钥分发 →
//! 候选交换 → DirectLink UDP 打洞 → Noise IK（expected key = Controller 分发
//! 注册公钥）→ Mock Overlay + 对端 /32 路由 → Agent 加密冒烟 → 双方
//! Connected（规格十二 8 条件全部满足）。
//!
//! Gate 断言（对应用户规格十七 MVP FLOW 的 PASS/FAIL 项）：
//! - 事件序列与顺序（规格九：UI 只消费 Agent 事件，不自行推断状态）；
//! - 双向 Device Identity 验证经 Controller（Connected 字段 + 诊断公钥指纹）；
//! - 加密 overlay 双向用户 ping：A→B 与 B→A（非冒烟 id，与 Agent 冒烟区分）
//!   经 Noise 加密往返且收到应答；
//! - /32 路由恰好一条（规格八：不劫持默认路由 / DNS）；
//! - 全部交互经 Named Pipe（规格三/四：UI 不触碰私钥 / socket / Wintun）。

use mesh_agent::overlay::OverlayBackend;
use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{Command, Event, PipeClient, Request, Response, ServerMessage};
use std::io::Read;
use std::net::Ipv4Addr;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

const GATE_TIMEOUT: Duration = Duration::from_secs(60);

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name(role: &str) -> String {
    format!(
        r"\\.\pipe\meshlink-gate-{role}-{}-{}",
        std::process::id(),
        tag()
    )
}

// ---------------------------------------------------------------------------
// Controller（真实 Go 进程）
// ---------------------------------------------------------------------------

struct ControllerGuard {
    child: Child,
}

impl Drop for ControllerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_controller(tmp: &std::path::Path) -> (String, ControllerGuard) {
    if ProcessCommand::new("go").arg("version").output().is_err() {
        panic!("未找到 go 工具链：MVP Gate 需要编译 Go Controller（server/controller）");
    }
    let controller_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/controller");
    let exe = tmp.join("controller-gate.exe");
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

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let addr = format!("127.0.0.1:{port}");
    let log_path = tmp.join("controller.log");
    let log = std::fs::File::create(&log_path).expect("create controller log");
    let child = ProcessCommand::new(&exe)
        .arg("-addr")
        .arg(&addr)
        .arg("-db")
        .arg(tmp.join("controller.db"))
        .stdout(Stdio::from(log.try_clone().expect("dup log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn controller");

    let url = format!("http://{addr}");
    let client = controller_client::Client::new(&url).expect("controller client");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok", "healthz 应答 ok");
            break;
        }
        if Instant::now() > deadline {
            let mut log_text = String::new();
            if let Ok(mut f) = std::fs::File::open(&log_path) {
                let _ = f.read_to_string(&mut log_text);
            }
            panic!(
                "Controller 30s 内未就绪，日志尾部:\n{}",
                &log_text[log_text.len().saturating_sub(2000)..]
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (url, ControllerGuard { child })
}

// ---------------------------------------------------------------------------
// UI（真实 IPC 管道客户端）
// ---------------------------------------------------------------------------

fn wait_connect(name: &str, timeout: Duration) -> PipeClient {
    let deadline = Instant::now() + timeout;
    loop {
        match PipeClient::connect(name, Duration::from_secs(2)) {
            Ok(c) => return c,
            Err(_) => {
                if Instant::now() > deadline {
                    panic!("UI 连接管道超时: {name}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// 轮询 GetStatus 直到 state 达到目标（期间到达的事件进入 pending，不丢失）。
fn wait_state(ui: &mut PipeClient, want: AgentState, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    let mut id = 0u64;
    loop {
        id += 1;
        let resp = ui
            .request(&Request { id, command: Command::GetStatus })
            .expect("GetStatus 请求");
        assert!(resp.ok, "GetStatus 不应失败: {:?}", resp.error);
        let data = resp.data.expect("GetStatus 必须携带快照");
        if data["state"] == serde_json::json!(want) {
            return data;
        }
        if Instant::now() > deadline {
            panic!("等待状态 {want:?} 超时，最后快照: {data}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn request_data(ui: &mut PipeClient, cmd: Command) -> serde_json::Value {
    let resp = ui.request(&Request { id: u64::MAX, command: cmd }).expect("请求");
    assert!(resp.ok, "命令失败: {:?} (data={:?})", resp.error, resp.data);
    resp.data.expect("命令必须携带 data")
}

/// 收集事件直到出现 stop 条件或 deadline。
fn collect_until(ui: &mut PipeClient, timeout: Duration, stop: impl Fn(&Event) -> bool) -> Vec<Event> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(200)) {
            let hit = stop(&ev);
            out.push(ev);
            if hit {
                break;
            }
        }
    }
    out
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

/// expected 必须是 events 的有序子序列（事件间允许插入其它事件）。
fn assert_subsequence(events: &[Event], expected: &[&'static str], who: &str) {
    let mut search_from = 0usize;
    for want in expected {
        let names: Vec<&'static str> = events[search_from..].iter().map(event_name).collect();
        match names.iter().position(|n| n == want) {
            Some(p) => search_from += p + 1,
            None => panic!(
                "{who} 事件序列缺少（按序）{want}，实际序列: {:?}",
                events.iter().map(event_name).collect::<Vec<_>>()
            ),
        }
    }
}

fn connected_of(events: &[Event], who: &str) -> (String, String, String) {
    let c = events.iter().find_map(|e| match e {
        Event::Connected { peer_device_id, local_overlay_ip, peer_overlay_ip, .. } => {
            Some((peer_device_id.clone(), local_overlay_ip.clone(), peer_overlay_ip.clone()))
        }
        _ => None,
    });
    c.unwrap_or_else(|| {
        panic!(
            "{who} 必须收到 Connected 事件（规格十二），事件流: {}",
            serde_json::to_string(events).unwrap()
        )
    })
}

fn assert_no_error(events: &[Event], who: &str) {
    for ev in events {
        if let Event::Error { code, message } = ev {
            panic!("{who} 出现错误事件 {code}: {message}（事件流: {}）",
                serde_json::to_string(events).unwrap());
        }
    }
}

// ---------------------------------------------------------------------------
// 用户 ping（非冒烟 id——与 Agent 冒烟区分，模拟 `ping <对端虚拟 IP>`）
// ---------------------------------------------------------------------------

const USER_PING_PAYLOAD: &[u8] = b"meshlink-user-ping-v1";

fn user_ping(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let icmp_len = 8 + USER_PING_PAYLOAD.len();
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let hdr_sum = mesh_vnic::icmp_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    pkt[20] = 8; // echo request
    pkt[24..26].copy_from_slice(&id.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..total].copy_from_slice(USER_PING_PAYLOAD);
    let icmp_sum = mesh_vnic::icmp_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    pkt
}

fn is_echo_reply(pkt: &[u8], id: u16, seq: u16) -> bool {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let icmp = &pkt[ihl..];
    icmp[0] == 0
        && u16::from_be_bytes([icmp[4], icmp[5]]) == id
        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
        && &icmp[8..] == USER_PING_PAYLOAD
}

fn pkt_src_dst(pkt: &[u8]) -> (Ipv4Addr, Ipv4Addr) {
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    (src, dst)
}

/// 轮询注入队列直到**全部**谓词都被命中过（take_injected 清空语义 →
/// 轮询累积；多个断言共用一次等待，避免先到包被早退等待吞掉）。
fn wait_injected_all(
    mock: &mesh_agent::MockOverlay,
    preds: Vec<Box<dyn Fn(&[u8]) -> bool>>,
    timeout: Duration,
    what: &str,
) {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        seen.extend(mock.take_injected());
        let satisfied: Vec<bool> = (0..preds.len())
            .map(|i| seen.iter().any(|p| preds[i](p)))
            .collect();
        if satisfied.iter().all(|&s| s) {
            return;
        }
        if Instant::now() > deadline {
            panic!("{what}：注入队列未满足全部条件（{} 个条件命中 {:?}，已见 {} 包）",
                preds.len(), satisfied, seen.len());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---------------------------------------------------------------------------
// MVP Gate 主测试
// ---------------------------------------------------------------------------

#[test]
fn mvp_gate_six_digit_code_to_encrypted_overlay_ping() {
    // 可见性：Gate 失败诊断（级别可经 RUST_LOG 覆盖）。
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-mvp-gate"));
    let run_dir = tmp.join(format!("gate-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    // ---- 1. 真实 Go Controller ----
    let (controller_url, _controller) = spawn_controller(&run_dir);

    // ---- 2. Agent A（creator）+ Agent B（joiner），Mock Overlay ----
    let agent_cfg = |dir_tag: &str, name: &str| AgentConfig {
        controller_url: controller_url.clone(),
        data_dir: run_dir.join(dir_tag),
        network_id: "meshlink-gate".into(),
        device_name: Some(name.into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(45), // 失败快速暴露（默认 600s）
        ..AgentConfig::default()
    };
    let pipe_a = pipe_name("a");
    let pipe_b = pipe_name("b");
    let (agent_a, server_a) = spawn_service(agent_cfg("agent-a", "Gate-Machine-A"), &pipe_a)
        .expect("spawn Agent A");
    let (agent_b, server_b) = spawn_service(agent_cfg("agent-b", "Gate-Machine-B"), &pipe_b)
        .expect("spawn Agent B");

    // UI（真实 Named Pipe 客户端——规格三/四：唯一交互通道）。
    let mut ui_a = wait_connect(&pipe_a, Duration::from_secs(10));
    let mut ui_b = wait_connect(&pipe_b, Duration::from_secs(10));

    // ---- 3. 双端 READY（Controller healthz + 注册 + 传输层 start）----
    let snap_a = wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    let snap_b = wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));
    assert_eq!(snap_a["user_facing"], "已就绪");
    let dev_a = snap_a["device_id"].as_str().unwrap().to_string();
    let dev_b = snap_b["device_id"].as_str().unwrap().to_string();
    assert_ne!(dev_a, dev_b, "双端独立身份");
    assert!(dev_a.starts_with("dev-") && dev_b.starts_with("dev-"));

    // ---- 4. A 创建 6 位码（用户规格二/三：响应本身必须携带合法 6 位码，不依赖后续事件）----
    let resp: Response = ui_a
        .request(&Request { id: 100, command: Command::CreateQuickSession })
        .expect("CreateQuickSession 请求");
    assert!(resp.ok, "创建命令必须被接受: {:?}", resp.error);
    let data = resp.data.expect("CreateQuickSession 必须携带 data");
    assert_eq!(data["status"], "WAITING", "响应 status 应为 WAITING");
    assert!(
        data["session_id"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "响应必须携带 session_id: {data}"
    );
    let resp_code = data["code"].as_str().expect("code 必须是 string（用户规格一）").to_string();
    assert_eq!(resp_code.len(), 6, "code 固定宽度 6: {resp_code}");
    assert!(resp_code.bytes().all(|b| b.is_ascii_digit()), "code 纯数字: {resp_code}");
    eprintln!("CreateQuickSession 响应 code={resp_code}（UI 应直接显示此码）");

    let events_a1 = collect_until(&mut ui_a, Duration::from_secs(30), |e| {
        matches!(e, Event::WaitingForPeer { .. } | Event::Error { .. })
    });
    assert_no_error(&events_a1, "A 创建阶段");
    let code = events_a1
        .iter()
        .find_map(|e| match e {
            Event::WaitingForPeer { code, .. } => Some(code.clone()),
            _ => None,
        })
        .expect("A 必须收到 WaitingForPeer（含 6 位码）");
    assert_eq!(code.len(), 6, "6 位码长度");
    assert!(code.bytes().all(|b| b.is_ascii_digit()), "6 位数字码: {code}");
    assert_eq!(resp_code, code, "响应 code 与 WaitingForPeer 事件 code 必须一致（同码不漂移）");

    // ---- 4.1 GetStatus 顶层 active_session 保留 code（用户规格四：页面切换不丢码）----
    let snap_wait = wait_state(&mut ui_a, AgentState::WaitingForPeer, Duration::from_secs(10));
    let active = snap_wait["active_session"].as_object().expect("GetStatus 必须有 active_session");
    assert_eq!(active["code"], serde_json::json!(resp_code), "active_session.code 必须等于创建码");
    assert_eq!(active["status"], "WAITING_FOR_PEER");

    // ---- 5. B 凭 6 位码加入（使用响应中的 code，验证响应码直接可用）----
    let resp = ui_b
        .request(&Request { id: 200, command: Command::JoinQuickSession { code: resp_code } })
        .expect("JoinQuickSession 请求");
    assert!(resp.ok, "加入命令必须被接受: {:?}", resp.error);

    // ---- 6. 双端全流程：候选交换 → 打洞 → Noise → Overlay → 冒烟 → Connected ----
    // 交替轮询双端（任一侧卡死不隐藏另一侧的事件流）。
    let deadline = Instant::now() + GATE_TIMEOUT;
    let mut events_b: Vec<Event> = Vec::new();
    let mut events_a2: Vec<Event> = Vec::new();
    let mut a_done = false;
    let mut b_done = false;
    while Instant::now() < deadline && !(a_done && b_done) {
        if !a_done {
            if let Some(ServerMessage::Event(ev)) = ui_a.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    a_done = true;
                }
                events_a2.push(ev);
            }
        }
        if !b_done {
            if let Some(ServerMessage::Event(ev)) = ui_b.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    b_done = true;
                }
                events_b.push(ev);
            }
        }
    }
    eprintln!(
        "Gate 事件收集结束: a_done={a_done} b_done={b_done}（超时 = 任一侧未达终态）\n  A: {:?}\n  B: {:?}",
        events_a2.iter().map(event_name).collect::<Vec<_>>(),
        events_b.iter().map(event_name).collect::<Vec<_>>()
    );
    let mut events_a = events_a1;
    events_a.extend(events_a2);

    assert_no_error(&events_b, "B");
    assert_no_error(&events_a, "A");

    // 事件序列（规格九：状态机权威在 Agent，UI 只消费事件流）。
    assert_subsequence(
        &events_a,
        &[
            "GatheringCandidates",
            "WaitingForPeer",
            "PeerFound",
            "Punching",
            "NoiseHandshaking",
            "Connected",
        ],
        "A(creator)",
    );
    assert_subsequence(
        &events_b,
        &["GatheringCandidates", "PeerFound", "Punching", "NoiseHandshaking", "Connected"],
        "B(joiner)",
    );

    // Connected 字段：双向身份 + Controller IPAM 分配的 Overlay IP。
    let (a_peer_dev, a_local, a_peer_ip) = connected_of(&events_a, "A");
    let (b_peer_dev, b_local, b_peer_ip) = connected_of(&events_b, "B");
    assert_eq!(a_peer_dev, dev_b, "A 的对端 = B（Controller Registry）");
    assert_eq!(b_peer_dev, dev_a, "B 的对端 = A（Controller Registry）");
    assert_eq!(a_peer_ip, b_local, "A 看到的对端 IP = B 本机 IP");
    assert_eq!(b_peer_ip, a_local, "B 看到的对端 IP = A 本机 IP");
    let a_ip: Ipv4Addr = a_local.parse().expect("A Overlay IP 合法");
    let b_ip: Ipv4Addr = b_local.parse().expect("B Overlay IP 合法");
    assert_ne!(a_ip, b_ip, "Controller IPAM 必须分配互不相同的 IP（规格六）");
    assert_eq!(
        a_ip.octets()[..3],
        b_ip.octets()[..3],
        "双端须在同一会话独占网段（Controller overlay_subnet）"
    );

    // ---- 7. GetStatus：CONNECTED + 会话视图（经管道）----
    let snap_a = wait_state(&mut ui_a, AgentState::Connected, Duration::from_secs(5));
    let snap_b = wait_state(&mut ui_b, AgentState::Connected, Duration::from_secs(5));
    assert_eq!(snap_a["user_facing"], "已连接");
    assert_eq!(snap_b["user_facing"], "已连接");
    for (snap, who, role, local, peer) in [
        (&snap_a, "A", "creator", &a_local, &b_local),
        (&snap_b, "B", "joiner", &b_local, &a_local),
    ] {
        let sess = snap["session"].as_object().expect(&format!("{who} session 视图"));
        assert_eq!(sess["role"], role, "{who} 角色");
        assert_eq!(sess["network_id"], "meshlink-gate", "{who} network_id");
        assert!(sess["overlay_subnet"].is_string(), "{who} Controller 下发 overlay_subnet");
        let peers = sess["peers"].as_array().expect("{who} peers");
        assert_eq!(peers.len(), 1, "快速一对一恰好 1 个 peer");
        assert_eq!(peers[0]["connected"], true, "{who} peer connected");
        assert_eq!(peers[0]["local_overlay_ip"].as_str(), Some(local.as_str()), "{who} 本机 Overlay IP");
        assert_eq!(peers[0]["peer_overlay_ip"].as_str(), Some(peer.as_str()), "{who} 对端 Overlay IP");
    }

    // ---- 8. GetDiagnostics（规格十一：高级诊断页数据源）----
    let diag_a = request_data(&mut ui_a, Command::GetDiagnostics);
    let diag_b = request_data(&mut ui_b, Command::GetDiagnostics);
    for (diag, who, peer_ip) in [(&diag_a, "A", &b_local), (&diag_b, "B", &a_local)] {
        assert_eq!(diag["state"], "CONNECTED", "{who} 诊断状态");
        assert_eq!(diag["noise"]["established"], true, "{who} Noise transport ready");
        let fp = diag["noise"]["remote_static_fingerprint"].as_str().expect(&format!("{who} 对端指纹"));
        assert_eq!(fp.len(), 64, "{who} 对端公钥指纹（32 字节 hex）");
        let routes = diag["overlay"]["peer_routes"].as_array().expect(&format!("{who} peer_routes"));
        assert_eq!(routes.len(), 1, "规格八：恰好一条对端 /32 路由（不得劫持默认路由/DNS）");
        assert_eq!(routes[0].as_str(), Some(peer_ip.as_str()), "{who} 路由目标 = 对端 Overlay IP");
        let sel = diag["selected_pair"].as_object().expect(&format!("{who} selected_pair"));
        assert!(sel["local"].is_string() && sel["remote"].is_string(), "{who} 直连路径已选定");
    }

    // ---- 9. 加密 overlay 双向用户 ping（MVP FLOW 最后一步）----
    let mock_a = agent_a.mock_overlay().expect("A Mock Overlay 句柄");
    let mock_b = agent_b.mock_overlay().expect("B Mock Overlay 句柄");
    assert!(mock_a.is_up() && mock_b.is_up(), "双端 Overlay 已 up");
    assert_eq!(mock_a.routes_installed(), vec![b_ip], "A 侧 /32 路由");
    assert_eq!(mock_b.routes_installed(), vec![a_ip], "B 侧 /32 路由");

    // A→B 与 B→A 同时发起（双向并发，非先后串行）。
    let id_ab = 0x0A0B;
    let id_ba = 0x0B0A;
    mock_a.inject_outgoing(user_ping(a_ip, b_ip, id_ab, 1));
    mock_b.inject_outgoing(user_ping(b_ip, a_ip, id_ba, 1));

    // A 协议栈必须同时见到：A 用户 ping 的应答（B 内核语义）+ B 的用户 ping 请求。
    wait_injected_all(
        &mock_a,
        vec![
            Box::new(move |p| is_echo_reply(p, id_ab, 1) && pkt_src_dst(p) == (b_ip, a_ip)),
            Box::new(move |p| is_request(p, id_ba) && pkt_src_dst(p) == (b_ip, a_ip)),
        ],
        Duration::from_secs(10),
        "A 未完成加密 ping 往返",
    );
    // B 协议栈必须同时见到：B 用户 ping 的应答（A 内核语义）+ A 的用户 ping 请求。
    wait_injected_all(
        &mock_b,
        vec![
            Box::new(move |p| is_echo_reply(p, id_ba, 1) && pkt_src_dst(p) == (a_ip, b_ip)),
            Box::new(move |p| is_request(p, id_ab) && pkt_src_dst(p) == (a_ip, b_ip)),
        ],
        Duration::from_secs(10),
        "B 未完成加密 ping 往返",
    );

    // ---- 10. 会话取消：资源回收（/32 路由随 Overlay teardown）----
    let resp = ui_a
        .request(&Request { id: 300, command: Command::CancelSession })
        .expect("CancelSession 请求");
    assert!(resp.ok);
    // Disconnected 事件 + 回 READY。
    let events_a3 = collect_until(&mut ui_a, Duration::from_secs(10), |e| {
        matches!(e, Event::Disconnected { .. })
    });
    if !events_a3.iter().any(|e| matches!(e, Event::Disconnected { .. })) {
        let probe = ui_a.request(&Request { id: 301, command: Command::GetStatus });
        eprintln!("[cancel-diag] 事件未达（{:?}），取消后管道探测: {:?}", events_a3.iter().map(event_name).collect::<Vec<_>>(), probe.as_ref().map(|r| r.ok));
    }
    assert!(
        events_a3.iter().any(|e| matches!(e, Event::Disconnected { reason } if reason == "cancelled")),
        "取消必须产生 Disconnected 事件: {events_a3:?}"
    );
    assert!(!mock_a.is_up(), "取消后 A Overlay 必须拆除");
    assert!(mock_a.routes_installed().is_empty(), "取消后 A /32 路由必须回收");
    wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(5));

    // ---- 清理 ----
    agent_a.shutdown();
    agent_b.shutdown();
    server_a.stop();
    server_b.stop();
    let _ = std::fs::remove_dir_all(&run_dir);
}

/// 用户 ping 请求判定（type 8 + id/seq/载荷匹配）。
fn is_request(pkt: &[u8], id: u16) -> bool {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let icmp = &pkt[ihl..];
    icmp[0] == 8
        && u16::from_be_bytes([icmp[4], icmp[5]]) == id
        && u16::from_be_bytes([icmp[6], icmp[7]]) == 1
        && &icmp[8..] == USER_PING_PAYLOAD
}
