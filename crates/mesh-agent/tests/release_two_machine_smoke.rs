//! Release 双机等价冒烟（真实 Release 流程的本机等价验证）。
//!
//! **背景（真实双机 Bug）**：两台机器都使用默认 `http://127.0.0.1:18080` 时，
//! 各自拉起**独立的本机 Controller + 独立 SQLite DB**。机器 A 创建的 6 位码写入
//! A 的 DB；机器 B 输入的码查询 B 自己的 DB → 必然 `SESSION_CODE_INVALID (404)`
//! （SESSION_NOT_FOUND 已被上一轮修复为透传真实业务码）。
//!
//! 本测试用**真实 dist 二进制**（`dist/controller.exe` × 2 + `dist/mesh-agent.exe` × 3，
//! 独立端口/DB/data_dir/管道，等价于两台独立机器）验证：
//! 1. **复现根因**：A 在 Controller-A 创建 code；B 连 Controller-B 用同一 code 加入
//!    → 必须返回 `SESSION_CODE_INVALID`（证明"code 不在同一个 Controller = 404"）。
//! 2. **正确拓扑**：C 连与 A 相同的 Controller-A，用同一 code 加入 → PeerFound/Connected
//!    （证明 A 创建的 code 确实存在于 Controller-A；双机必须指向同一 Controller）。
//! 3. **安全约束仍生效**：controller.exe 明文监听公网地址 → 拒绝启动（exit≠0）。
//!
//! 真实物理双机部署步骤见 `dist/README.md`（一台机器 `-addr <私网IP>:18080
//! -allow-lan-plaintext` 跑 Controller，两台 MeshLink 都配置同一 Controller 地址）。
//!
//! 默认 `#[ignore]`（需先构建并打包 dist），显式运行：
//! `cargo test -p mesh-agent --test release_two_machine_smoke -- --ignored --nocapture`

use mesh_agent::AgentState;
use mesh_ipc::{build_request, PipeClient, ServerMessage};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn dist_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../dist")
        .canonicalize()
        .expect("dist 目录不存在，请先构建并打包 dist")
}

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name(suffix: &str) -> String {
    format!(
        r"\\.\pipe\meshlink-2m-{}-{}-{}",
        std::process::id(),
        tag(),
        suffix
    )
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    let p = std::net::TcpListener::bind("127.0.0.1:0").expect("probe");
    p.local_addr().expect("addr").port()
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

/// 启动一个独立 Controller（等价于"一台机器上的 Controller"）。
fn spawn_controller(ctrl_exe: &std::path::Path, tmp: &std::path::Path, tag: &str) -> (String, Guard) {
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    let child = ProcessCommand::new(ctrl_exe)
        .arg("-addr")
        .arg(&addr)
        .arg("-db")
        .arg(tmp.join(format!("ctrl-{tag}.db")))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dist/controller.exe");
    let guard = Guard(child);
    let url = format!("http://{addr}");
    let client = controller_client::Client::new(&url).expect("client");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok", "healthz");
            break;
        }
        if Instant::now() > deadline {
            panic!("controller {addr} 15s 内未就绪");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (url, guard)
}

/// 启动一个独立 mesh-agent（等价于"一台机器上的 MeshLink 后台服务"）。
fn spawn_agent(
    agent_exe: &std::path::Path,
    tmp: &std::path::Path,
    name: &str,
    controller_url: &str,
    pipe: &str,
) -> (PipeClient, Guard) {
    let child = ProcessCommand::new(agent_exe)
        .env("MESHLINK_OVERLAY", "mock")
        .env("MESHLINK_DATA_DIR", tmp.join(format!("agent-{name}")))
        .env("MESHLINK_PIPE_NAME", pipe)
        .env("MESHLINK_CONTROLLER_URL", controller_url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dist/mesh-agent.exe");
    let ui = wait_connect(pipe, Duration::from_secs(10));
    (ui, Guard(child))
}

fn wait_ready(ui: &mut PipeClient, next_id: &AtomicU64, who: &str) {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let req = build_request(next_id, "GetStatus", None).expect("bridge GetStatus");
        let resp = ui.request(&req).expect("GetStatus");
        assert!(resp.ok, "{who} GetStatus 失败: {:?}", resp.error);
        let snap = resp.data.expect("快照");
        if snap["state"] == serde_json::json!(AgentState::Ready) {
            return;
        }
        if Instant::now() > deadline {
            panic!("等 {who} READY 超时，最后快照: {snap}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// 收集事件直到出现 Error 或 deadline，返回首个 Error 的 (code, message)。
fn collect_error(ui: &mut PipeClient, timeout: Duration, what: &str) -> (String, String) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(200)) {
            if let mesh_ipc::Event::Error { code, message } = ev {
                return (code, message);
            }
        }
    }
    panic!("{what} 未在 {timeout:?} 内收到 Error 事件");
}

#[test]
#[ignore = "release 双机冒烟：需先构建并打包 dist 后显式运行"]
fn release_two_machine_separate_controllers_and_shared_controller() {
    mesh_common::logging::init_logging("info,agent=debug", false);

    let dist = dist_dir();
    let ctrl_exe = dist.join("controller.exe");
    let agent_exe = dist.join("mesh-agent.exe");
    assert!(ctrl_exe.exists(), "缺少 dist/controller.exe");
    assert!(agent_exe.exists(), "缺少 dist/mesh-agent.exe");

    let tmp = std::env::temp_dir().join(format!("meshlink-2m-{}", tag()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mkdir tmp");

    // ---- 两个独立 Controller（等价双机各自 controller）----
    let (url_a, _ctrl_a) = spawn_controller(&ctrl_exe, &tmp, "a");
    let (url_b, _ctrl_b) = spawn_controller(&ctrl_exe, &tmp, "b");
    assert_ne!(url_a, url_b, "双机 Controller 必须不同（独立 DB）");

    // ---- 机器 A：连 Controller-A（创建连接码）----
    let pipe_a = pipe_name("a");
    let (mut ui_a, _agent_a) = spawn_agent(&agent_exe, &tmp, "a", &url_a, &pipe_a);
    let id_a = AtomicU64::new(1);
    wait_ready(&mut ui_a, &id_a, "A");

    let req = build_request(&id_a, "CreateQuickSession", None).expect("bridge CreateQuickSession");
    let resp = ui_a.request(&req).expect("CreateQuickSession A");
    assert!(resp.ok, "A 创建失败: {:?}", resp.error);
    let data = resp.data.expect("创建 data");
    let code = data["code"].as_str().expect("code 必须 string").to_string();
    assert_eq!(code.len(), 6, "code 长度 6: {code}");
    eprintln!("[2M] A 在 {url_a} 创建 code={code}");

    // ---- 机器 B：连 Controller-B（另一台 Controller），用 A 的 code 加入 ----
    // 这是用户双机 Bug 的直接复现：B 查的是自己的 DB，A 的 code 不存在 → 404。
    let pipe_b = pipe_name("b");
    let (mut ui_b, _agent_b) = spawn_agent(&agent_exe, &tmp, "b", &url_b, &pipe_b);
    let id_b = AtomicU64::new(1);
    wait_ready(&mut ui_b, &id_b, "B");

    let req = build_request(&id_b, "JoinQuickSession", Some(&serde_json::json!({ "code": code })))
        .expect("bridge JoinQuickSession");
    let resp = ui_b.request(&req).expect("JoinQuickSession B");
    assert!(resp.ok, "B join 命令应被接受（异步失败以 Error 事件呈现）: {:?}", resp.error);
    let (err_code, _msg) = collect_error(&mut ui_b, Duration::from_secs(15), "B 在独立 Controller 上 join");
    assert_eq!(
        err_code, "SESSION_CODE_INVALID",
        "B 连接不同 Controller 时必须 SESSION_CODE_INVALID（复现双机 404 根因），实际 {err_code}"
    );
    eprintln!("[2M] 复现根因：B 连独立 Controller-B join code={code} → {err_code}（404，code 不在 B 的 DB）");

    // ---- 机器 C：连与 A 相同的 Controller-A，用同一 code 加入 ----
    // 证明：code 确实存在于 Controller-A；双机指向同一 Controller 时互通。
    let pipe_c = pipe_name("c");
    let (mut ui_c, _agent_c) = spawn_agent(&agent_exe, &tmp, "c", &url_a, &pipe_c);
    let id_c = AtomicU64::new(1);
    wait_ready(&mut ui_c, &id_c, "C");

    let req = build_request(&id_c, "JoinQuickSession", Some(&serde_json::json!({ "code": code })))
        .expect("bridge JoinQuickSession");
    let resp = ui_c.request(&req).expect("JoinQuickSession C");
    assert!(resp.ok, "C join 命令应被接受: {:?}", resp.error);

    // A / C 双端 PeerFound（同一 Controller 下的同一 code）。
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut a_found = false;
    let mut c_found = false;
    while Instant::now() < deadline && !(a_found && c_found) {
        if !a_found {
            if let Some(ServerMessage::Event(ev)) = ui_a.wait_message(Duration::from_millis(100)) {
                match ev {
                    mesh_ipc::Event::PeerFound { .. } | mesh_ipc::Event::Connected { .. } => a_found = true,
                    mesh_ipc::Event::Error { code, message } => panic!("A 错误事件 {code}: {message}"),
                    _ => {}
                }
            }
        }
        if !c_found {
            if let Some(ServerMessage::Event(ev)) = ui_c.wait_message(Duration::from_millis(100)) {
                match ev {
                    mesh_ipc::Event::PeerFound { .. } | mesh_ipc::Event::Connected { .. } => c_found = true,
                    mesh_ipc::Event::Error { code, message } => panic!("C 错误事件 {code}: {message}"),
                    _ => {}
                }
            }
        }
    }
    assert!(
        a_found && c_found,
        "同一 Controller 下同一 code 必须 A/C 都 PeerFound（a={a_found} c={c_found}）"
    );
    eprintln!("[2M] 正确拓扑：C 连与 A 相同的 {url_a} join code={code} → PeerFound（code 存在于 Controller-A）");

    // ---- 安全约束：controller 明文监听公网地址必须拒绝启动 ----
    let out = ProcessCommand::new(&ctrl_exe)
        .arg("-addr")
        .arg("8.8.8.8:18080")
        .arg("-db")
        .arg(tmp.join("ctrl-public.db"))
        .output()
        .expect("运行 controller 公网明文");
    assert!(
        !out.status.success(),
        "controller 明文监听公网地址必须拒绝启动（安全约束）"
    );
    eprintln!("[2M] 安全约束仍生效：公网明文监听被 controller 拒绝启动");

    tracing::info!("release 双机冒烟 PASS：独立 Controller 复现 SESSION_CODE_INVALID；共享 Controller 同一 code PeerFound；公网明文拒绝");
}
