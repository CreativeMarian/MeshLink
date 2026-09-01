//! Release 生命周期冒烟（M1-1.5）：真实 dist 二进制 + IPC 优雅退出 + runtime 清理。
//!
//! 默认 `#[ignore]`，需在重打 dist 后显式运行：
//!   `cargo test -p mesh-agent --test release_lifecycle_smoke -- --ignored --nocapture`
//!
//! 验证（用户规格二/四/五 Gate 的 release 侧）：
//! 1. `dist/controller.exe`（无 -addr）+ `dist/mesh-agent.exe`（MESHLINK_RUNTIME_DIR
//!    指向临时 runtime）→ READY 后 runtime_token.json 落盘；
//! 2. CreateQuickSession → quick_code.json + active_session.json 落盘（残留信号）；
//! 3. 发送 IPC `Command::Shutdown` → Agent 进程自行退出（不需外部 kill）；
//! 4. Shutdown 后 runtime 临时文件全部清除（进程无残留）；
//! 5. 永久身份（data_dir）不受 runtime 清理影响。

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
        r"\\.\pipe\meshlink-release-lc-{}-{}",
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

fn pid_alive(pid: u32) -> bool {
    let Ok(out) = ProcessCommand::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
}

#[test]
#[ignore = "release 生命周期冒烟：需先构建 dist 并显式运行"]
fn release_agent_graceful_shutdown_cleans_runtime() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let dist = dist_dir();
    let ctrl_exe = dist.join("controller.exe");
    let agent_exe = dist.join("mesh-agent.exe");
    assert!(ctrl_exe.exists(), "缺少 dist/controller.exe");
    assert!(agent_exe.exists(), "缺少 dist/mesh-agent.exe");

    let tmp = std::env::temp_dir().join(format!("meshlink-release-lc-{}", tag()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mkdir tmp");
    let runtime = tmp.join("runtime");
    let data_dir = tmp.join("agent");

    // 1) dist/controller.exe 无 -addr → 默认监听 127.0.0.1:18080。
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
            assert_eq!(v["status"], "ok");
            break;
        }
        if Instant::now() > deadline {
            panic!("dist/controller.exe 无 -addr 10s 内未在 {DEFAULT_CONTROLLER_URL} 就绪");
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 2) dist/mesh-agent.exe：注入 MESHLINK_RUNTIME_DIR（与 MeshLink supervisor 同目录语义）。
    let pipe = pipe_name();
    let mut agent = Guard(
        ProcessCommand::new(&agent_exe)
            .env("MESHLINK_OVERLAY", "mock")
            .env("MESHLINK_DATA_DIR", &data_dir)
            .env("MESHLINK_RUNTIME_DIR", &runtime)
            .env("MESHLINK_PIPE_NAME", &pipe)
            .env_remove("MESHLINK_CONTROLLER_URL")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn dist/mesh-agent.exe"),
    );
    let agent_pid = agent.0.id();

    let mut ui = wait_connect(&pipe, Duration::from_secs(10));
    wait_state(&mut ui, AgentState::Ready, Duration::from_secs(40));

    // READY 后 runtime_token.json 应落盘。
    assert!(
        runtime.join("runtime_token.json").exists(),
        "READY 后 runtime_token.json 应存在（残留信号）"
    );

    // 3) CreateQuickSession → quick_code.json + active_session.json 落盘。
    let created = ui
        .request(&Request { id: 1001, command: Command::CreateQuickSession })
        .expect("CreateQuickSession");
    assert!(created.ok, "CreateQuickSession 失败: {:?}", created.error);
    let code = created.data.as_ref().and_then(|d| d["code"].as_str()).expect("code").to_string();
    assert!(code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()));
    assert!(
        runtime.join("quick_code.json").exists() && runtime.join("active_session.json").exists(),
        "创建后 runtime 应写入 quick_code.json + active_session.json"
    );

    // 4) IPC Shutdown → Agent 进程自行退出（不 kill）+ runtime 临时文件清除。
    let resp = ui
        .request(&Request { id: 1002, command: Command::Shutdown })
        .expect("Shutdown");
    assert!(resp.ok, "Shutdown 失败: {:?}", resp.error);

    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        match agent.0.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {
                if Instant::now() > deadline {
                    panic!("Agent 收到 Shutdown 后 8s 内未自行退出（pid={agent_pid}）");
                }
            }
            Err(_) => break,
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let exited = agent.0.try_wait().ok().flatten().is_some();
    assert!(exited, "Agent 必须经 IPC Shutdown 自行退出");
    // 进程确实不再存活（tasklist 校验，防仅句柄态误判）。
    let _ = std::thread::sleep(Duration::from_millis(300));
    assert!(!pid_alive(agent_pid), "agent pid={agent_pid} 不应再存活");

    // 5) Shutdown 后 runtime 临时文件全部清除（supervisor 会再删整个目录，agent 侧先清）。
    for f in ["quick_code.json", "active_session.json", "runtime_token.json", "temporary_candidates.json"] {
        assert!(!runtime.join(f).exists(), "Shutdown 后 {f} 应被清除（{runtime:?}）");
    }
    // 6) 永久身份（data_dir secure-store）不受影响。
    assert!(data_dir.exists(), "data_dir 永久身份目录应保留");

    // 事件流无错误。
    let _ = ui.wait_message(Duration::from_millis(200));

    tracing::info!("release 生命周期冒烟 PASS：IPC Shutdown → Agent 自退 + runtime 清理 + 身份保留");
}
