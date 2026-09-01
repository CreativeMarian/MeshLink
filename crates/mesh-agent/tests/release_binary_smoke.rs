//! Release 二进制默认端口冒烟（用户规格：先 `controller.exe`（无 -addr），
//! 再 `mesh-agent.exe`（无 MESHLINK_CONTROLLER_URL），要求 ControllerConnected + READY）。
//!
//! 与 `default_port_alignment.rs` 的区别：
//! - 前者用 `go build` 到 TMP + debug agent，跑在普通 `cargo test --workspace`；
//! - 本测试直接执行 **dist 打包产物** `dist/controller.exe` / `dist/mesh-agent.exe`，
//!   是「重新打包 dist 后」的 release 冒烟。默认 `#[ignore]`，需显式运行：
//!   `cargo test -p mesh-agent --test release_binary_smoke -- --ignored --nocapture`
//!
//! 任何一侧默认端口漂移（8080 vs 18080）都会让本测试失败。

use mesh_agent::AgentState;
use mesh_ipc::{Command, PipeClient, Request, ServerMessage, DEFAULT_CONTROLLER_URL};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

fn dist_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../dist")
        .canonicalize()
        .expect("dist 目录不存在，请先执行 release 构建并打包 dist")
}

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name() -> String {
    format!(
        r"\\.\pipe\meshlink-release-smoke-{}-{}",
        std::process::id(),
        tag()
    )
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
impl Guard {
    fn child_mut(&mut self) -> &mut Child {
        &mut self.0
    }
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
#[ignore = "release 冒烟：需先构建 dist 并显式运行"]
fn release_binaries_align_on_default_18080() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let dist = dist_dir();
    let ctrl_exe = dist.join("controller.exe");
    let agent_exe = dist.join("mesh-agent.exe");
    assert!(ctrl_exe.exists(), "缺少 dist/controller.exe");
    assert!(agent_exe.exists(), "缺少 dist/mesh-agent.exe");

    let tmp = std::env::temp_dir().join(format!("meshlink-release-smoke-{}", tag()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mkdir tmp");

    // 1) controller.exe 无 -addr → 默认监听 127.0.0.1:18080。
    let _ctrl = Guard(
        ProcessCommand::new(&ctrl_exe)
            .arg("-db")
            .arg(tmp.join("ctrl.db"))
            .env_remove("CONTROLLER_LISTEN")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dist/controller.exe"),
    );

    let client = controller_client::Client::new(DEFAULT_CONTROLLER_URL).expect("client");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok", "healthz 非 ok: {v}");
            break;
        }
        if Instant::now() > deadline {
            panic!("dist/controller.exe 无 -addr 10s 内未在 {DEFAULT_CONTROLLER_URL} 就绪");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 2) mesh-agent.exe 无 MESHLINK_CONTROLLER_URL → 默认连 18080。
    let pipe = pipe_name();
    let mut agent = Guard(
        ProcessCommand::new(&agent_exe)
            .env("MESHLINK_OVERLAY", "mock")
            .env("MESHLINK_DATA_DIR", tmp.join("agent"))
            .env("MESHLINK_PIPE_NAME", &pipe)
            .env_remove("MESHLINK_CONTROLLER_URL")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dist/mesh-agent.exe"),
    );

    let mut ui = wait_connect(&pipe, Duration::from_secs(10));

    // 3) 必须 READY（ControllerConnected）。
    let snap = wait_state(&mut ui, AgentState::Ready, Duration::from_secs(40));
    assert_eq!(
        snap["controller"].as_str().unwrap_or(""),
        DEFAULT_CONTROLLER_URL,
        "快照 controller 应等于规范默认值"
    );

    // 4) 确定性 ControllerConnected 证明：GetControllerStatus 必须 connected 且 url=默认。
    //    （ControllerConnected 事件在 agent 独立进程 READY 时广播，测试客户端未必赶得上
    //    订阅；READY 快照 controller 字段 + 本命令的 connected=true 即为等价权威证明。）
    let resp = ui
        .request(&Request {
            id: 999,
            command: Command::GetControllerStatus,
        })
        .expect("GetControllerStatus");
    assert!(resp.ok, "GetControllerStatus 失败: {:?}", resp.error);
    let ctl = resp.data.expect("controller status");
    assert_eq!(ctl["connected"], serde_json::json!(true), "agent 未连上默认 Controller: {ctl}");
    assert_eq!(
        ctl["url"].as_str().unwrap_or(""),
        DEFAULT_CONTROLLER_URL,
        "controller url 应等于规范默认值"
    );

    // 5) 顺带确认事件流无 CONTROLLER_UNREACHABLE（有则必为默认值漂移）。
    let deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < deadline {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(200)) {
            if let mesh_ipc::Event::Error { code, message } = ev {
                panic!("release 冒烟出现错误事件 {code}: {message}")
            }
        }
    }
    assert!(
        !agent.child_mut().try_wait().expect("try_wait").is_some(),
        "mesh-agent 提前退出"
    );

    tracing::info!("release 冒烟 PASS：controller 无 -addr 监听 18080 ↔ agent 默认连 18080 → READY");
}
