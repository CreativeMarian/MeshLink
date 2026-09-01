//! 默认端口对齐集成测试（防默认值再次漂移）。
//!
//! 复现并验证用户发现的真实 Bug：Controller 默认 `127.0.0.1:8080` 而
//! MeshAgent 默认 `http://127.0.0.1:18080` → CONTROLLER_UNREACHABLE
//! (os error 10061)。修复后：
//! - `controller.exe` **无 `-addr`** 启动 → 默认监听 127.0.0.1:18080（Go DefaultAddr）；
//! - `mesh-agent` **无 Controller URL 覆盖**（`AgentConfig::default`）→ 默认
//!   `mesh_ipc::DEFAULT_CONTROLLER_URL`（http://127.0.0.1:18080）；
//! - 双方天然匹配 → Agent 进入 READY（ControllerConnected）。
//!
//! 任何一侧默认值漂移都会让本测试失败（连接 18080 或 READY 断言）。
//! 固定占用 18080：本测试与其它 Controller 测试（随机端口）不冲突。

use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{Command, PipeClient, Request, ServerMessage, DEFAULT_CONTROLLER_URL};
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
        r"\\.\pipe\meshlink-default-port-{role}-{}-{}",
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

/// 以「无 -addr」方式启动 Go Controller：必须落在 Go DefaultAddr（127.0.0.1:18080）。
fn spawn_controller_default(tmp: &std::path::Path) -> ControllerGuard {
    if ProcessCommand::new("go").arg("version").output().is_err() {
        panic!("未找到 go 工具链：默认端口对齐测试需要编译 Go Controller");
    }
    let controller_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/controller");
    let exe = tmp.join("controller-default.exe");
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

    let log_path = tmp.join("controller-default.log");
    let log = std::fs::File::create(&log_path).expect("create controller log");
    let child = ProcessCommand::new(&exe)
        // 只传 -db，绝不传 -addr：验证 Go 侧默认值。
        .arg("-db")
        .arg(tmp.join("controller-default.db"))
        .env_remove("CONTROLLER_LISTEN") // 排除外部环境干扰，测真实默认。
        // 只重定向 stderr：Controller 的 listen= 启动日志在 stderr。
        // （stdout 与 stderr 指向同一文件的 Windows 双句柄写入会互相覆盖导致日志为空，
        //   故 stdout 丢弃，断言只依赖 stderr。）
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn controller");

    let guard = ControllerGuard { child };

    // 等 Controller 就绪：必须能从 DEFAULT_CONTROLLER_URL（18080）healthz 通过。
    let client = controller_client::Client::new(DEFAULT_CONTROLLER_URL).expect("client 18080");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok", "healthz 非 ok: {v}");
            break;
        }
        if Instant::now() > deadline {
            let mut text = String::new();
            if let Ok(mut f) = std::fs::File::open(&log_path) {
                let _ = f.read_to_string(&mut text);
            }
            panic!(
                "默认端口 Controller 10s 未在 {} 就绪：\n{}",
                DEFAULT_CONTROLLER_URL,
                &text[text.len().saturating_sub(2000)..]
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 双保险：读启动日志确认 Controller 确实监听 127.0.0.1:18080（而非恰好别处）。
    let mut text = String::new();
    if let Ok(mut f) = std::fs::File::open(&log_path) {
        let _ = f.read_to_string(&mut text);
    }
    assert!(
        text.contains("127.0.0.1:18080"),
        "Controller 未按默认 127.0.0.1:18080 监听（默认值漂移？）。日志：\n{}",
        &text[text.len().saturating_sub(2000)..]
    );
    guard
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

#[test]
fn default_ports_align_controller_and_agent() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-default-port"));
    let run_dir = tmp.join(format!("align-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    // 1) Controller 无 -addr：默认必须监听 127.0.0.1:18080。
    let _controller = spawn_controller_default(&run_dir);

    // 2) Agent 无 Controller URL 覆盖：AgentConfig::default() 使用
    //    mesh_ipc::DEFAULT_CONTROLLER_URL（18080）。二者天然匹配。
    let pipe = pipe_name("agent");
    let (agent, server) = spawn_service(
        AgentConfig {
            data_dir: run_dir.join("agent"),
            device_name: Some("default-port-agent".into()),
            overlay: OverlayKind::Mock,
            ..AgentConfig::default()
        },
        &pipe,
    )
    .expect("spawn agent");
    let _server = server;

    let mut ui = wait_connect(&pipe, Duration::from_secs(10));

    // 3) Agent 必须无任何手动地址即可 READY（证明默认值对齐，非手动补救）。
    let snap = wait_state(&mut ui, AgentState::Ready, Duration::from_secs(40));
    assert_eq!(
        snap["controller"].as_str().unwrap_or(""),
        DEFAULT_CONTROLLER_URL,
        "Agent 快照 controller 应等于规范默认值"
    );
    assert!(
        snap["device_id"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "READY 快照应含 device_id"
    );

    // 4) 事件流应含 ControllerConnected（而非 Error CONTROLLER_UNREACHABLE）。
    let events = collect_until(&mut ui, Duration::from_secs(5), |e| {
        matches!(e, ServerMessage::Event(_))
    });
    drop(agent);
    for m in &events {
        if let ServerMessage::Event(ev) = m {
            match ev {
                mesh_ipc::Event::ControllerConnected { .. } => return, // 期望路径
                mesh_ipc::Event::Error { code, message } => {
                    panic!("Agent 连接默认 Controller 失败 {code}: {message}（默认值未对齐？）")
                }
                _ => {}
            }
        }
    }
    // 事件可能已消费完；READY 断言已是充分证据。
}

fn collect_until(ui: &mut PipeClient, timeout: Duration, _: impl Fn(&ServerMessage) -> bool) -> Vec<ServerMessage> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        if let Some(m) = ui.wait_message(Duration::from_millis(200)) {
            let done = matches!(m, ServerMessage::Event(mesh_ipc::Event::ControllerConnected { .. }))
                || matches!(m, ServerMessage::Event(mesh_ipc::Event::Error { .. }));
            out.push(m);
            if done {
                break;
            }
        }
    }
    out
}
