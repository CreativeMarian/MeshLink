//! M1-1 GUI Bridge 集成测试（用户规格四：从 Tauri bridge 层进入 Agent IPC，
//! 禁止直连 AgentCore 绕过 UI bridge）。
//!
//! 关键：所有命令**不**直接构造 `Request`，而是经 `mesh_ipc::build_request`——
//! 与 Tauri `ipc_request`（`apps/meshlink-ui/src/ipc.rs`）完全同一条 wire 构造路径：
//! `{"cmd": <name>, ...payload}` → 反序列化内部标签 `Command` → 生成 id → `Request`。
//! 随后经真实 Named Pipe（PipeClient）到达 mesh-agent 真实命令处理。
//!
//! 覆盖（用户规格四清单）：GetStatus / ListDevices / GetDiagnostics /
//! CreateFriendInvite（7天+不限 / 永久+1次 / 24小时+5次）/ ListInvites /
//! ListFriendships / 未知命令拒绝 / 非法 ttl——全部断言「有真实错误、无 undefined
//! 语义」（ok:false 时 error.message 非空；ok:true 时字段齐全）。
//!
//! 与 `release_gui_smoke.rs` 互补：本测试跑普通 `cargo test --workspace`；
//! release 冒烟用 dist 真实三件套并显式运行。

use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{build_request, PipeClient, Response, ServerMessage};
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::sync::atomic::AtomicU64;
use std::time::{Duration, Instant};

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name() -> String {
    format!(
        r"\\.\pipe\meshlink-gui-bridge-{}-{}",
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
        panic!("未找到 go 工具链：GUI Bridge 集成测试需要编译 Go Controller");
    }
    let controller_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/controller");
    let exe = tmp.join("controller-gui-bridge.exe");
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
    let child = ProcessCommand::new(&exe)
        .arg("-addr")
        .arg(&addr)
        .arg("-db")
        .arg(tmp.join("controller.db"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

/// 经 **bridge 路径**（build_request）发送命令并返回响应。
/// 与 Tauri `ipc_request` 使用同一构造函数；payload 以 `serde_json::Value` 给出
/// （UI 侧由 JS 对象序列化而来，语义等价）。
fn bridge(ui: &mut PipeClient, next_id: &AtomicU64, cmd: &str, payload: Option<serde_json::Value>) -> Response {
    let req = build_request(next_id, cmd, payload.as_ref())
        .unwrap_or_else(|e| panic!("bridge 构造 {cmd} 失败（应能解析）: {e}"));
    // 30s 而非默认 15s：workspace 并行跑多组 controller+agent 时首次请求可能变慢，避免偶发超时 flake
    ui.request_timeout(&req, Duration::from_secs(30))
        .unwrap_or_else(|e| panic!("bridge 发送 {cmd} 失败: {e}"))
}

/// bridge 发送后要求 ok:true，返回 data。
fn bridge_ok(
    ui: &mut PipeClient,
    next_id: &AtomicU64,
    cmd: &str,
    payload: Option<serde_json::Value>,
) -> serde_json::Value {
    let resp = bridge(ui, next_id, cmd, payload);
    assert!(resp.ok, "{cmd} 应成功: {:?} (data={:?})", resp.error, resp.data);
    resp.data.expect("成功命令必须携带 data")
}

#[test]
fn m1_1_gui_bridge_integration() {
    mesh_common::logging::init_logging("info,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-gui-bridge"));
    let run_dir = tmp.join(format!("bridge-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let (controller_url, _controller) = spawn_controller(&run_dir);

    let cfg = AgentConfig {
        controller_url: controller_url.clone(),
        data_dir: run_dir.join("agent"),
        network_id: "meshlink-gui-bridge".into(),
        device_name: Some("Alice-PC".into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(30),
        ..AgentConfig::default()
    };
    let pipe = pipe_name();
    let (_agent, _server) = spawn_service(cfg, &pipe).expect("spawn agent");
    let mut ui = wait_connect(&pipe, Duration::from_secs(10));
    let next_id = AtomicU64::new(1);

    // ---- READY ----
    let deadline = Instant::now() + Duration::from_secs(30);
    let snap = loop {
        let data = bridge_ok(&mut ui, &next_id, "GetStatus", None);
        if data["state"] == serde_json::json!(AgentState::Ready) {
            break data;
        }
        if Instant::now() > deadline {
            panic!("等 READY 超时，最后快照: {data}");
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let device_id = snap["device_id"].as_str().expect("device_id").to_string();
    assert!(!device_id.is_empty());

    // ---- GetControllerStatus：connected + url 与 Controller 一致 ----
    let ctl = bridge_ok(&mut ui, &next_id, "GetControllerStatus", None);
    assert_eq!(ctl["connected"], serde_json::json!(true), "Controller 应已连接: {ctl}");
    assert_eq!(ctl["url"].as_str().unwrap_or(""), controller_url, "生效地址应等于 Controller URL");

    // ---- ListDevices：真实返回本机设备（设备页数据源）----
    let devs = bridge_ok(&mut ui, &next_id, "ListDevices", None);
    let dev_list = devs["devices"].as_array().expect("devices");
    assert!(!dev_list.is_empty(), "设备列表不能为空（本机已注册）");
    let me = &dev_list[0];
    assert_eq!(me["device_id"].as_str().expect("device_id"), device_id, "本机设备 = 已注册 device_id");
    assert_eq!(me["device_name"].as_str().expect("device_name"), "Alice-PC", "设备名");
    assert!(me.get("online").is_some(), "online 字段必须存在");
    assert!(me.get("overlay_ip").is_some(), "overlay_ip 字段必须存在（未连接时为 null）");
    assert!(me.get("last_seen").is_some(), "last_seen 字段必须存在");

    // ---- GetDiagnostics：无 Peer 时仍 ok（"暂无连接数据" ≠ "接口失败"）----
    let diag = bridge_ok(&mut ui, &next_id, "GetDiagnostics", None);
    assert_eq!(diag["state"], snap["state"], "诊断 state");
    assert_eq!(diag["device_id"].as_str().unwrap_or(""), device_id, "诊断 device_id");
    assert_eq!(diag["controller"].as_str().unwrap_or(""), controller_url, "诊断 controller");
    assert!(
        diag.get("selected_pair").is_none() || diag["selected_pair"].is_null(),
        "无 Peer 时 selected_pair 应为 null"
    );

    // ---- CreateFriendInvite：7天 + 不限（UI 录屏首选组合）----
    let inv7 = bridge_ok(
        &mut ui,
        &next_id,
        "CreateFriendInvite",
        Some(serde_json::json!({ "ttl": "7d", "max_uses": 0 })),
    );
    assert!(inv7["invite_id"].as_str().is_some_and(|s| !s.is_empty()), "invite_id");
    assert!(inv7["invite_token"].as_str().is_some_and(|s| s.starts_with("mli_")), "invite_token");
    assert!(!inv7["expires_at"].is_null(), "expires_at 必须返回（UI 展示有效期）");
    assert_eq!(inv7["max_uses"], serde_json::json!(0), "0 = 不限");
    assert_eq!(inv7["ttl"].as_str().unwrap_or(""), "7d");

    // ---- 永久 + 1次 / 24小时 + 5次 ----
    let inv_perm = bridge_ok(
        &mut ui,
        &next_id,
        "CreateFriendInvite",
        Some(serde_json::json!({ "ttl": "permanent", "max_uses": 1 })),
    );
    assert_eq!(inv_perm["max_uses"], serde_json::json!(1));
    assert_eq!(inv_perm["ttl"].as_str().unwrap_or(""), "permanent");
    assert!(inv_perm["expires_at"].is_null(), "permanent 无过期时间（或 null）");

    let inv24 = bridge_ok(
        &mut ui,
        &next_id,
        "CreateFriendInvite",
        Some(serde_json::json!({ "ttl": "24h", "max_uses": 5 })),
    );
    assert_eq!(inv24["max_uses"], serde_json::json!(5));
    assert!(!inv24["expires_at"].is_null(), "24h 必须有过期时间");

    // ---- ListInvites：3 个 ----
    let invites = bridge_ok(&mut ui, &next_id, "ListInvites", None);
    let invites_list = invites["invites"].as_array().expect("invites");
    assert_eq!(invites_list.len(), 3, "3 个邀请");
    assert!(invites_list[0].get("expires_at").is_some(), "invite 应含 expires_at");
    assert!(invites_list[0].get("status").is_some(), "invite 应含 status");

    // ---- ListFriendships：初始为空 ----
    let friends = bridge_ok(&mut ui, &next_id, "ListFriends", None);
    assert_eq!(friends["friendships"].as_array().expect("friendships").len(), 0, "初始无好友");

    // ---- 非法 ttl：ok:false + 真实错误码 + 非空 message（无 undefined 语义）----
    let resp = bridge(&mut ui, &next_id, "CreateFriendInvite", Some(serde_json::json!({ "ttl": "bogus", "max_uses": 0 })));
    assert!(!resp.ok, "非法 ttl 必须失败");
    let err = resp.error.as_ref().expect("错误对象");
    assert_eq!(err.code, "INVITE_TTL_INVALID");
    assert!(!err.message.trim().is_empty(), "错误 message 不能为空（UI formatError 依赖）");

    // ---- 未知命令：bridge 构造拒绝，返回真实错误（非 undefined）----
    match build_request(&next_id, "BogusCommand", None) {
        Err(e) => assert!(e.starts_with("命令非法"), "未知命令应报命令非法: {e}"),
        Ok(_) => panic!("未知命令必须被 bridge 拒绝"),
    }

    // ---- payload 类型错误：同样被 bridge 拒绝并给出真实错误 ----
    match build_request(
        &next_id,
        "CreateFriendInvite",
        Some(&serde_json::json!({ "ttl": "7d", "max_uses": "many" })),
    ) {
        Err(e) => assert!(e.starts_with("命令非法"), "类型错误应报命令非法: {e}"),
        Ok(_) => panic!("max_uses 传字符串必须被 bridge 拒绝"),
    }

    // ---- 事件流无 Error ----
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(150)) {
            if let mesh_ipc::Event::Error { code, message } = ev {
                panic!("GUI Bridge 集成测试出现错误事件 {code}: {message}");
            }
        }
    }

    tracing::info!("M1-1 GUI Bridge 集成测试 PASS：GetStatus/ListDevices/GetDiagnostics/CreateFriendInvite/ListInvites/ListFriendships 全部经 bridge 路径成功，错误均带真实 message");
}

/// 6 位码全链路 Bridge E2E（用户规格九）：经真实 bridge wire（build_request +
/// Named Pipe，与 Tauri `ipc_request` 同路径）执行 CreateQuickSession，断言
/// `code` 是 string / 长度 6 / 纯数字；随后用**同一 code** 在 Agent B 上
/// JoinQuickSession，双方必须 PeerFound——证明 Controller → Agent → IPC → UI
/// 与 UI → IPC → Agent → Controller 字段无漂移。
#[test]
fn quick_code_bridge_e2e() {
    mesh_common::logging::init_logging("info,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-gui-bridge"));
    let run_dir = tmp.join(format!("bridge-qc-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let (controller_url, _controller) = spawn_controller(&run_dir);

    let cfg = |tag_s: &str, name: &str| AgentConfig {
        controller_url: controller_url.clone(),
        data_dir: run_dir.join(tag_s),
        network_id: "meshlink-quick".into(),
        device_name: Some(name.into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(30),
        ..AgentConfig::default()
    };
    let pipe_a = format!(r"\\.\pipe\meshlink-gui-bridge-{}-{}-a", std::process::id(), tag());
    let pipe_b = format!(r"\\.\pipe\meshlink-gui-bridge-{}-{}-b", std::process::id(), tag());
    let (_a, _sa) = spawn_service(cfg("agent-a", "Alice-PC"), &pipe_a).expect("spawn A");
    let (_b, _sb) = spawn_service(cfg("agent-b", "Bob-PC"), &pipe_b).expect("spawn B");
    let mut ui_a = wait_connect(&pipe_a, Duration::from_secs(10));
    let mut ui_b = wait_connect(&pipe_b, Duration::from_secs(10));
    let id_a = AtomicU64::new(1);
    let id_b = AtomicU64::new(1);

    let wait_ready = |ui: &mut PipeClient, id: &AtomicU64| {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let data = bridge_ok(ui, id, "GetStatus", None);
            if data["state"] == serde_json::json!(AgentState::Ready) {
                return;
            }
            if Instant::now() > deadline {
                panic!("等 READY 超时: {data}");
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    };
    wait_ready(&mut ui_a, &id_a);
    wait_ready(&mut ui_b, &id_b);

    // ---- Creator：bridge wire CreateQuickSession → 响应必须携带 string 6 位码 ----
    let created = bridge_ok(&mut ui_a, &id_a, "CreateQuickSession", None);
    assert_eq!(created["status"], "WAITING", "响应 status 应为 WAITING: {created}");
    assert!(
        created["session_id"].as_str().map(|s| !s.is_empty()).unwrap_or(false),
        "响应必须携带 session_id: {created}"
    );
    let code = created["code"]
        .as_str()
        .unwrap_or_else(|| panic!("code 必须是 string（用户规格一），got: {:?}", created["code"]))
        .to_string();
    assert_eq!(code.len(), 6, "code 长度 6: {code}");
    assert!(code.bytes().all(|b| b.is_ascii_digit()), "code 纯数字: {code}");
    eprintln!("Bridge E2E Creator code={code}");

    // ---- GetStatus 顶层 active_session 保留 code（用户规格四）----
    let snap_a = bridge_ok(&mut ui_a, &id_a, "GetStatus", None);
    let active = snap_a["active_session"].as_object().expect("必须有 active_session");
    assert_eq!(active["code"], serde_json::json!(code), "active_session.code == 创建码");

    // ---- Joiner：用同一 code 经 bridge wire JoinQuickSession ----
    let joined = bridge_ok(&mut ui_b, &id_b, "JoinQuickSession", Some(serde_json::json!({ "code": code })));
    assert!(joined["status"].as_str().is_some(), "Join 响应应含 status: {joined}");

    // ---- 双方 PeerFound：证明同一 code 让 A/B 匹配 ----
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut a_found = false;
    let mut b_found = false;
    while Instant::now() < deadline && !(a_found && b_found) {
        if !a_found {
            if let Some(ServerMessage::Event(ev)) = ui_a.wait_message(Duration::from_millis(100)) {
                match ev {
                    mesh_ipc::Event::PeerFound { .. } => a_found = true,
                    mesh_ipc::Event::Connected { .. } => a_found = true,
                    mesh_ipc::Event::Error { code, message } => panic!("A 错误事件 {code}: {message}"),
                    _ => {}
                }
            }
        }
        if !b_found {
            if let Some(ServerMessage::Event(ev)) = ui_b.wait_message(Duration::from_millis(100)) {
                match ev {
                    mesh_ipc::Event::PeerFound { .. } => b_found = true,
                    mesh_ipc::Event::Connected { .. } => b_found = true,
                    mesh_ipc::Event::Error { code, message } => panic!("B 错误事件 {code}: {message}"),
                    _ => {}
                }
            }
        }
    }
    assert!(a_found && b_found, "同一 code 必须让 A/B 都 PeerFound（a={a_found} b={b_found}）");

    tracing::info!("Quick Code Bridge E2E PASS：Create→Join 同一 code，A/B 均 PeerFound");
}
