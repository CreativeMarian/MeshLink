//! Release GUI Bridge Smoke（用户规格十一：release gate 不再只验证「启动→ControllerConnected」）。
//!
//! **命名校准（用户规格）**：本测试名为 **Release GUI Bridge Smoke**，**不是**
//! "Full GUI Automated E2E"——它驱动的是真实 `dist/controller.exe` +
//! `dist/mesh-agent.exe` + 与 Tauri `ipc_request` 完全相同的 bridge wire
//! （`mesh_ipc::build_request`），**不操作真实 WebView**。真实 `app.js` 的
//! 错误契约由 `apps/meshlink-ui/tests/ui_error_contract.test.js`（JS contract
//! tests）覆盖，二者互补即足够，不阻塞开发。
//!
//! 驱动命令：GetStatus / ListDevices / GetDiagnostics / CreateFriendInvite /
//! ListInvites / ListFriends / GetControllerStatus——全部要求 ok:true、字段齐全、
//! 无「undefined / 空错误 / IPC_UNKNOWN_COMMAND / schema mismatch」。
//!
//! 默认 `#[ignore]`（需先构建并打包 dist），显式运行：
//! `cargo test -p mesh-agent --test release_gui_smoke -- --ignored --nocapture`

use mesh_agent::AgentState;
use mesh_ipc::{build_request, PipeClient, ServerMessage, DEFAULT_CONTROLLER_URL};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::atomic::AtomicU64;
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

fn pipe_name() -> String {
    format!(
        r"\\.\pipe\meshlink-release-gui-{}-{}",
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

#[test]
#[ignore = "release GUI 冒烟：需先构建 dist 并显式运行"]
fn release_gui_bridge_smoke() {
    mesh_common::logging::init_logging("info,agent=debug", false);

    let dist = dist_dir();
    let ctrl_exe = dist.join("controller.exe");
    let agent_exe = dist.join("mesh-agent.exe");
    assert!(ctrl_exe.exists(), "缺少 dist/controller.exe");
    assert!(agent_exe.exists(), "缺少 dist/mesh-agent.exe");

    let tmp = std::env::temp_dir().join(format!("meshlink-release-gui-{}", tag()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mkdir tmp");

    // controller.exe 无 -addr → 默认 18080（默认端口对齐的 release 证明）。
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

    let pipe = pipe_name();
    let _agent = Guard(
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
    let next_id = AtomicU64::new(1);

    // ---- READY ----
    let deadline = Instant::now() + Duration::from_secs(40);
    let device_id = loop {
        let req = build_request(&next_id, "GetStatus", None).expect("bridge GetStatus");
        let resp = ui.request(&req).expect("GetStatus");
        assert!(resp.ok, "GetStatus 失败: {:?}", resp.error);
        let snap = resp.data.expect("快照");
        if snap["state"] == serde_json::json!(AgentState::Ready) {
            break snap["device_id"].as_str().unwrap_or("").to_string();
        }
        if Instant::now() > deadline {
            panic!("等 READY 超时，最后快照: {snap}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert!(!device_id.is_empty());

    // ---- 逐条经 bridge 驱动 GUI 命令，全部要求 ok:true 且字段齐全 ----
    let mut run = |cmd: &str, payload: Option<serde_json::Value>| -> serde_json::Value {
        let req = build_request(&next_id, cmd, payload.as_ref())
            .unwrap_or_else(|e| panic!("bridge 构造 {cmd} 失败: {e}"));
        let resp = ui.request(&req).unwrap_or_else(|e| panic!("bridge 发送 {cmd} 失败: {e}"));
        assert!(resp.ok, "{cmd} 在 release 二进制上失败: {:?} (data={:?})", resp.error, resp.data);
        resp.data.expect("成功必须带 data")
    };

    let ctl = run("GetControllerStatus", None);
    assert_eq!(ctl["connected"], serde_json::json!(true), "release agent 未连上默认 Controller");
    assert_eq!(ctl["url"].as_str().unwrap_or(""), DEFAULT_CONTROLLER_URL);

    let devs = run("ListDevices", None);
    let list = devs["devices"].as_array().expect("devices");
    assert!(!list.is_empty(), "设备列表为空");
    assert_eq!(list[0]["device_id"].as_str().unwrap_or(""), device_id);
    assert!(list[0].get("device_name").is_some() && list[0].get("online").is_some());

    let diag = run("GetDiagnostics", None);
    assert_eq!(diag["device_id"].as_str().unwrap_or(""), device_id);
    assert_eq!(diag["controller"].as_str().unwrap_or(""), DEFAULT_CONTROLLER_URL);

    let inv = run("CreateFriendInvite", Some(serde_json::json!({ "ttl": "7d", "max_uses": 0 })));
    assert!(inv["invite_id"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(inv["invite_token"].as_str().is_some_and(|s| s.starts_with("mli_")));
    assert!(!inv["expires_at"].is_null(), "release 也应返回 expires_at");
    assert_eq!(inv["max_uses"], serde_json::json!(0));

    let invites = run("ListInvites", None);
    assert_eq!(invites["invites"].as_array().expect("invites").len(), 1);

    let friends = run("ListFriends", None);
    assert_eq!(friends["friendships"].as_array().expect("friendships").len(), 0);

    // ---- 6 位码全链路（用户规格十二）：Release dist 真实使用同一码 ----
    // Creator 创建 → 响应 code 必须是 string /^\d{6}$/ → 用同一码在第二个
    // release mesh-agent.exe 上 Join → PeerFound，证明 Controller→Agent→IPC 字段不漂移。
    let created = run("CreateQuickSession", None);
    assert_eq!(created["status"], "WAITING", "release 创建响应 status 应为 WAITING: {created}");
    assert!(created["session_id"].as_str().is_some_and(|s| !s.is_empty()));
    let code = created["code"]
        .as_str()
        .expect("release code 必须是 string（用户规格一）")
        .to_string();
    assert_eq!(code.len(), 6, "code 长度 6: {code}");
    assert!(code.bytes().all(|b| b.is_ascii_digit()), "code 纯数字: {code}");
    // GetStatus 顶层 active_session 保留 code
    let snap_after = run("GetStatus", None);
    assert_eq!(
        snap_after["active_session"]["code"], serde_json::json!(code),
        "release GetStatus active_session 必须保留 code"
    );

    // 第二个 release agent 作为 Joiner
    let pipe_b = format!(r"\\.\pipe\meshlink-release-gui-{}-{}-b", std::process::id(), tag());
    let _agent_b = Guard(
        ProcessCommand::new(&agent_exe)
            .env("MESHLINK_OVERLAY", "mock")
            .env("MESHLINK_DATA_DIR", tmp.join("agent-b"))
            .env("MESHLINK_PIPE_NAME", &pipe_b)
            .env_remove("MESHLINK_CONTROLLER_URL")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn 第二个 dist/mesh-agent.exe"),
    );
    let mut ui_b = wait_connect(&pipe_b, Duration::from_secs(10));
    let id_b = AtomicU64::new(1);
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let req = build_request(&id_b, "GetStatus", None).expect("bridge GetStatus");
        let resp = ui_b.request(&req).expect("GetStatus B");
        assert!(resp.ok, "GetStatus B 失败: {:?}", resp.error);
        let snap = resp.data.expect("快照 B");
        if snap["state"] == serde_json::json!(AgentState::Ready) {
            break;
        }
        if Instant::now() > deadline {
            panic!("等 B READY 超时，最后快照: {snap}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let req = build_request(&id_b, "JoinQuickSession", Some(&serde_json::json!({ "code": code })))
        .expect("bridge JoinQuickSession");
    let resp = ui_b.request(&req).expect("JoinQuickSession B");
    assert!(resp.ok, "release B JoinQuickSession 失败: {:?}", resp.error);

    // 双方 PeerFound（同一 code 匹配）
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut a_found = false;
    let mut b_found = false;
    while Instant::now() < deadline && !(a_found && b_found) {
        if !a_found {
            if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(100)) {
                match ev {
                    mesh_ipc::Event::PeerFound { .. } | mesh_ipc::Event::Connected { .. } => a_found = true,
                    mesh_ipc::Event::Error { code, message } => panic!("release A 错误事件 {code}: {message}"),
                    _ => {}
                }
            }
        }
        if !b_found {
            if let Some(ServerMessage::Event(ev)) = ui_b.wait_message(Duration::from_millis(100)) {
                match ev {
                    mesh_ipc::Event::PeerFound { .. } | mesh_ipc::Event::Connected { .. } => b_found = true,
                    mesh_ipc::Event::Error { code, message } => panic!("release B 错误事件 {code}: {message}"),
                    _ => {}
                }
            }
        }
    }
    assert!(a_found && b_found, "release 同一 code 必须 A/B 都 PeerFound（a={a_found} b={b_found}）");

    // 事件流无 Error。
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(150)) {
            if let mesh_ipc::Event::Error { code, message } = ev {
                panic!("release GUI 冒烟出现错误事件 {code}: {message}");
            }
        }
    }

    tracing::info!("release GUI 冒烟 PASS：dist/controller.exe + dist/mesh-agent.exe + bridge wire → 设备/诊断/邀请/6 位码 Create→Join→PeerFound 全部 ok:true");
}
