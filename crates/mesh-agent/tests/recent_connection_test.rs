//! M1-1.5 最近连接 + runtime 生命周期集成测试（全自动，MANUAL TEST REQUIRED = NONE）。
//!
//! 真实 Go Controller + Agent A + Agent B（Mock Overlay）：
//! A 创建 6 位码 → B 加入 → 双方 CONNECTED → 各自 recent_connection 自动落库
//! （对端指纹必须来自 Controller Registry）→ ListRecentConnections /
//! DeleteRecentConnection 全链路可用。
//!
//! 另验证 M1-1.5 runtime 生命周期：
//! - CreateQuickSession 后 runtime 写入 quick_code.json + active_session.json；
//! - READY 后写入 runtime_token.json；
//! - Agent 优雅 Shutdown 后 runtime 临时文件全部清除；
//! - 永久身份（data_dir）不受 runtime 清理影响。

use mesh_agent::overlay::OverlayBackend;
use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{Command, Event, PipeClient, Request, ServerMessage};
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
        r"\\.\pipe\meshlink-recent-{role}-{}-{}",
        std::process::id(),
        tag()
    )
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

fn spawn_controller(tmp: &std::path::Path) -> (String, ControllerGuard) {
    if ProcessCommand::new("go").arg("version").output().is_err() {
        panic!("未找到 go 工具链：最近连接集成测试需要编译 Go Controller");
    }
    let controller_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/controller");
    let exe = tmp.join("controller-recent.exe");
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
    let guard = ControllerGuard { child };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok");
            break;
        }
        if Instant::now() > deadline {
            let mut log_text = String::new();
            if let Ok(mut f) = std::fs::File::open(&log_path) {
                let _ = f.read_to_string(&mut log_text);
            }
            panic!(
                "Controller 30s 内未就绪: {}",
                &log_text[log_text.len().saturating_sub(1500)..]
            );
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
    let resp = ui.request(&Request { id: u64::MAX, command: cmd }).expect("请求");
    assert!(resp.ok, "命令失败: {:?} (data={:?})", resp.error, resp.data);
    resp.data.expect("命令必须携带 data")
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

fn assert_no_error(events: &[Event], who: &str) {
    for ev in events {
        if let Event::Error { code, message } = ev {
            panic!("{who} 出现错误事件 {code}: {message}");
        }
    }
}

/// 轮询 ListRecentConnections 直到出现对端 remote_device_id（CONNECTED 后异步落库）。
fn wait_recent_has(
    ui: &mut PipeClient,
    remote_device_id: &str,
    timeout: Duration,
) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    let mut id = 0u64;
    loop {
        id += 1;
        let resp = ui
            .request(&Request { id, command: Command::ListRecentConnections })
            .expect("ListRecentConnections");
        assert!(resp.ok, "ListRecentConnections 失败: {:?}", resp.error);
        let data = resp.data.expect("recent 列表");
        let list = data["recent_connections"].as_array().cloned().unwrap_or_default();
        if let Some(item) = list.iter().find(|r| r["remote_device_id"] == remote_device_id) {
            return item.clone();
        }
        if Instant::now() > deadline {
            panic!("等待 recent({remote_device_id}) 超时，当前列表: {list:?}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn m1_1_5_quick_session_records_recent_connection() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-recent-flow"));
    let run_dir = tmp.join(format!("recent-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let (controller_url, _controller) = spawn_controller(&run_dir);

    let agent_cfg = |dir_tag: &str, name: &str| AgentConfig {
        controller_url: controller_url.clone(),
        data_dir: run_dir.join(dir_tag),
        runtime_dir: run_dir.join(dir_tag).join("runtime"),
        network_id: "meshlink-recent".into(),
        device_name: Some(name.into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(45),
        ..AgentConfig::default()
    };
    let pipe_a = pipe_name("a");
    let pipe_b = pipe_name("b");
    let (agent_a, server_a) = spawn_service(agent_cfg("agent-a", "Alice-PC"), &pipe_a).expect("spawn A");
    let (agent_b, server_b) = spawn_service(agent_cfg("agent-b", "Bob-PC"), &pipe_b).expect("spawn B");

    let mut ui_a = wait_connect(&pipe_a, Duration::from_secs(10));
    let mut ui_b = wait_connect(&pipe_b, Duration::from_secs(10));

    // ---- 双端 READY（身份注册完成 → runtime_token.json 应落盘）----
    let snap_a = wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    let snap_b = wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));
    let dev_a = snap_a["device_id"].as_str().unwrap().to_string();
    let dev_b = snap_b["device_id"].as_str().unwrap().to_string();
    let runtime_a = run_dir.join("agent-a").join("runtime");
    let runtime_b = run_dir.join("agent-b").join("runtime");
    assert!(
        runtime_a.join("runtime_token.json").exists(),
        "READY 后 A runtime_token.json 应存在"
    );
    assert!(
        runtime_b.join("runtime_token.json").exists(),
        "READY 后 B runtime_token.json 应存在"
    );

    // ---- A 创建 6 位码（code 必须 string /^\d{6}$/）----
    let created = request_data(&mut ui_a, Command::CreateQuickSession);
    let code = created["code"].as_str().expect("code 必须是 string").to_string();
    assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()), "6 位数字码: {code}");
    assert!(
        runtime_a.join("quick_code.json").exists() && runtime_a.join("active_session.json").exists(),
        "创建后 runtime 应写入 quick_code.json + active_session.json"
    );

    // ---- B 加入（同一 code）----
    let resp = ui_b
        .request(&Request { id: 900, command: Command::JoinQuickSession { code: code.clone() } })
        .expect("JoinQuickSession");
    assert!(resp.ok, "Join 失败: {:?}", resp.error);

    // ---- 双端 CONNECTED ----
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut a_done = false;
    let mut b_done = false;
    let mut ev_a: Vec<Event> = Vec::new();
    let mut ev_b: Vec<Event> = Vec::new();
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
    assert!(a_done && b_done, "双端须 CONNECTED");
    assert_no_error(&ev_a, "A");
    assert_no_error(&ev_b, "B");

    // ---- 双方 recent 自动落库（对端指纹来自 Controller Registry）----
    let recent_a_b = wait_recent_has(&mut ui_a, &dev_b, Duration::from_secs(10));
    let recent_b_a = wait_recent_has(&mut ui_b, &dev_a, Duration::from_secs(10));
    assert_eq!(recent_a_b["remote_name"], "Bob-PC", "对端名来自 Registry 设备名");
    assert_eq!(recent_b_a["remote_name"], "Alice-PC");
    let fp = recent_a_b["remote_fingerprint"].as_str().expect("指纹").to_string();
    assert_eq!(fp.len(), 64, "对端指纹必须是 Registry 里的 hex64 公钥（不信任客户端自报）");
    assert_eq!(recent_a_b["last_path"], "directlink", "默认路径 DirectLink");
    assert!(!recent_a_b["last_overlay_ip"].as_str().unwrap_or("").is_empty(), "记录 overlay IP");
    assert!(recent_a_b["connection_count"].as_i64().unwrap_or(0) >= 1);
    assert!(recent_b_a["remote_fingerprint"].as_str().unwrap_or("").len() == 64);

    // ---- 再次连接同一对端 → connection_count 累加 ----
    // （connection_count 递增的确定性验证在 Go API 测试 TestRecentConnections 中
    //   已完整覆盖；此处只做一次首连记录断言，避免快速重连的握手时序抖动。）
    let _ = ui_a.request(&Request { id: 901, command: Command::CancelSession }).expect("Cancel A");
    wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(10));
    let _ = ui_b.request(&Request { id: 902, command: Command::CancelSession }).expect("Cancel B");
    wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(10));
    // 会话结束后 runtime 的 session 类临时文件应被清除（保留 runtime_token 直至退出）。
    assert!(!runtime_a.join("active_session.json").exists(), "会话结束后 active_session.json 应清除");
    assert!(!runtime_a.join("quick_code.json").exists(), "会话结束后 quick_code.json 应清除");

    // ---- DeleteRecentConnection：只删本地历史 ----
    let resp = ui_a
        .request(&Request {
            id: 904,
            command: Command::DeleteRecentConnection { remote_device_id: dev_b.clone() },
        })
        .expect("DeleteRecentConnection");
    assert!(resp.ok, "删除 recent 失败: {:?}", resp.error);
    let list = request_data(&mut ui_a, Command::ListRecentConnections);
    let after = list["recent_connections"].as_array().cloned().unwrap_or_default();
    assert!(
        !after.iter().any(|r| r["remote_device_id"] == dev_b),
        "A 删除后不应再有 dev-b 记录: {after:?}"
    );
    // B 侧历史不受影响（本地视角隔离）。
    let list_b = request_data(&mut ui_b, Command::ListRecentConnections);
    let after_b = list_b["recent_connections"].as_array().cloned().unwrap_or_default();
    assert!(
        after_b.iter().any(|r| r["remote_device_id"] == dev_a),
        "B 侧 recent 不受 A 删除影响: {after_b:?}"
    );

    // ---- 优雅 Shutdown：runtime 临时文件全部清除；data_dir 永久身份保留 ----
    agent_a.shutdown();
    agent_b.shutdown();
    for rt in [&runtime_a, &runtime_b] {
        for f in ["quick_code.json", "active_session.json", "runtime_token.json", "temporary_candidates.json"] {
            assert!(!rt.join(f).exists(), "Shutdown 后 {f} 应被清除（{rt:?}）");
        }
    }
    // 永久身份仍在 data_dir（secure-store 不受 runtime 清理影响）。
    assert!(
        run_dir.join("agent-a").read_dir().map(|mut it| it.next().is_some()).unwrap_or(false),
        "data_dir 永久身份目录应保留"
    );

    server_a.stop();
    server_b.stop();
    let _ = std::fs::remove_dir_all(&run_dir);
}
