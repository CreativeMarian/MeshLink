//! M1-2.x Session 生命周期集成测试：
//! 1. CreateQuickSession 的 6 位码必须来自 Controller（响应携带 session_id/code/expires_at，
//!    前端/Agent 均不自行生成——用户规格「禁止前端自行生成连接码」）。
//! 2. JoinQuickSession 用不存在的码 → 透传 Controller 真实业务码 SESSION_CODE_INVALID
//!    （不得再硬编码 SESSION_NOT_FOUND，掩盖真实原因——用户反馈的 Bug）。
//! 3. 用 Controller 返回的同一 code 正确加入 → 双端 PeerFound → DirectLink → Noise →
//!    Overlay → Connected（证明错误码透传修复未破坏正常链路）。

use mesh_agent::overlay::OverlayBackend;
use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{Command, Event, PipeClient, Request, Response, ServerMessage};
use std::io::Read;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name(role: &str) -> String {
    format!(
        r"\\.\pipe\meshlink-sess-{role}-{}-{}",
        std::process::id(),
        tag()
    )
}

// ---- 真实 Go Controller ----
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
        panic!("未找到 go 工具链（需编译 Go Controller）");
    }
    let controller_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/controller");
    let exe = tmp.join("controller-sess.exe");
    let out = ProcessCommand::new("go")
        .arg("build")
        .arg("-o")
        .arg(&exe)
        .arg("./cmd/controller")
        .current_dir(&controller_dir)
        .output()
        .expect("go build 执行失败");
    assert!(out.status.success(), "go build Controller 失败: {}", String::from_utf8_lossy(&out.stderr));

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let addr = format!("127.0.0.1:{port}");
    let log_path = tmp.join("controller-sess.log");
    let log = std::fs::File::create(&log_path).expect("create controller log");
    let child = ProcessCommand::new(&exe)
        .arg("-addr")
        .arg(&addr)
        .arg("-db")
        .arg(tmp.join("controller-sess.db"))
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

// ---- UI（真实 IPC 管道客户端）----
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

fn wait_state(ui: &mut PipeClient, want: AgentState, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    let mut id = 0u64;
    loop {
        id += 1;
        let resp = ui.request(&Request { id, command: Command::GetStatus }).expect("GetStatus");
        assert!(resp.ok, "GetStatus 失败: {:?}", resp.error);
        let data = resp.data.expect("GetStatus 快照");
        if data["state"] == serde_json::json!(want) {
            return data;
        }
        if Instant::now() > deadline {
            panic!("等待状态 {want:?} 超时，最后快照: {data}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

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

fn assert_no_error(events: &[Event], who: &str) {
    for ev in events {
        if let Event::Error { code, message } = ev {
            panic!("{who} 出现错误事件 {code}: {message}（事件流: {}）", serde_json::to_string(events).unwrap());
        }
    }
}

#[test]
fn session_lifecycle_code_source_and_join_error_passthrough() {
    mesh_common::logging::init_logging("info,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-session-lifecycle"));
    let run_dir = tmp.join(format!("sess-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    // ---- 1. 真实 Go Controller ----
    let (controller_url, _controller) = spawn_controller(&run_dir);

    let agent_cfg = |dir_tag: &str, name: &str| AgentConfig {
        controller_url: controller_url.clone(),
        data_dir: run_dir.join(dir_tag),
        network_id: "meshlink-sess".into(),
        device_name: Some(name.into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(45),
        ..AgentConfig::default()
    };
    let pipe_a = pipe_name("a");
    let pipe_b = pipe_name("b");
    let (agent_a, _server_a) = spawn_service(agent_cfg("agent-a", "Sess-Machine-A"), &pipe_a)
        .expect("spawn Agent A");
    let (agent_b, _server_b) = spawn_service(agent_cfg("agent-b", "Sess-Machine-B"), &pipe_b)
        .expect("spawn Agent B");

    let mut ui_a = wait_connect(&pipe_a, Duration::from_secs(10));
    let mut ui_b = wait_connect(&pipe_b, Duration::from_secs(10));

    let _ = wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    let _ = wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));

    // ---- 2. A 创建：6 位码必须来自 Controller 创建结果 ----
    let resp: Response = ui_a
        .request(&Request { id: 100, command: Command::CreateQuickSession })
        .expect("CreateQuickSession 请求");
    assert!(resp.ok, "创建命令必须被接受: {:?}", resp.error);
    let data = resp.data.expect("CreateQuickSession 必须携带 data");
    let session_id = data["session_id"].as_str().expect("响应必须携带 session_id").to_string();
    assert!(!session_id.is_empty(), "session_id 非空");
    let code = data["code"].as_str().expect("code 必须是 string（用户规格一）").to_string();
    assert_eq!(code.len(), 6, "code 固定宽度 6: {code}");
    assert!(code.bytes().all(|b| b.is_ascii_digit()), "code 纯数字: {code}");
    let expires_at = data["expires_at"].as_str().unwrap_or("");
    assert!(!expires_at.is_empty(), "expires_at 必须来自 Controller");
    eprintln!("[CHECK] CreateQuickSession 响应来自 Controller: session_id={session_id} code={code} expires_at={expires_at}");

    // WaitingForPeer 事件中的 code 与响应一致（同码不漂移）。
    let events_a1 = collect_until(&mut ui_a, Duration::from_secs(20), |e| {
        matches!(e, Event::WaitingForPeer { .. } | Event::Error { .. })
    });
    assert_no_error(&events_a1, "A 创建阶段");
    let ev_code = events_a1
        .iter()
        .find_map(|e| match e {
            Event::WaitingForPeer { code, .. } => Some(code.clone()),
            _ => None,
        })
        .expect("A 必须收到 WaitingForPeer（含 6 位码）");
    assert_eq!(ev_code, code, "响应 code 与 WaitingForPeer 事件 code 必须一致");

    // ---- 3. B 用不存在的码加入：必须透传 Controller 真实码 SESSION_CODE_INVALID ----
    let bad_code = "000000".to_string();
    let _ = ui_b
        .request(&Request { id: 200, command: Command::JoinQuickSession { code: bad_code.clone() } })
        .expect("JoinQuickSession 请求");
    let events_b_bad = collect_until(&mut ui_b, Duration::from_secs(15), |e| matches!(e, Event::Error { .. }));
    let err = events_b_bad
        .iter()
        .find_map(|e| match e {
            Event::Error { code, message } => Some((code.clone(), message.clone())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("B 用无效码加入必须收到 Error 事件，事件流: {:?}", events_b_bad));
    assert_eq!(
        err.0, "SESSION_CODE_INVALID",
        "无效码加入应透传 Controller 业务码 SESSION_CODE_INVALID（而非硬编码 SESSION_NOT_FOUND），实际: {:?}",
        err
    );
    eprintln!("[CHECK] 无效码 join → 透传错误码 SESSION_CODE_INVALID（reason: {}）", err.1);

    // ---- 4. B 用 Controller 返回的同一 code 正确加入 → 双端最终 Connected ----
    let _ = ui_b
        .request(&Request { id: 201, command: Command::JoinQuickSession { code: code.clone() } })
        .expect("JoinQuickSession 请求");
    let deadline = Instant::now() + Duration::from_secs(60);
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
    assert!(a_done, "A 未达终态，事件流: {:?}", events_a2);
    assert!(b_done, "B 未达终态，事件流: {:?}", events_b);
    assert_no_error(&events_a2, "A");
    assert_no_error(&events_b, "B");
    assert!(
        events_b.iter().any(|e| matches!(e, Event::PeerFound { .. })),
        "B 正确码加入必须 PeerFound，事件流: {:?}",
        events_b.iter().map(event_name).collect::<Vec<_>>()
    );
    eprintln!("[CHECK] 正确码加入链路完成: A/B 均 Connected（code={code} 来自 Controller）");

    let _ = agent_a;
    let _ = agent_b;
}
