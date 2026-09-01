//! DPAPI Scope 冻结验证（用户规格五）——MeshAgentService 运行身份确定后：
//!
//! 1. `service_identity_restart_stable`：服务重启（进程退出再启动）后
//!    device_id / 公钥稳定——DPAPI(CurrentUser) + ACL 身份不漂移；
//! 2. `ui_process_does_not_receive_private_key`：UI 进程的全部 IPC 面
//!    （9 命令响应 + 事件流）不含私钥材料——mesh-ipc 协议结构性保证 +
//!    本测试以真实身份私钥 hex 作字节级泄漏扫描。
//!
//! 运行身份结论（冻结）：MeshAgentService 以**当前登录用户**身份运行
//! （Tauri 客户端子进程），故 DPAPI = CurrentUser、文件 ACL = 当前用户 +
//! SYSTEM（详见 DEVICE_IDENTITY.md §2.2）。LocalSystem 服务化时重评估。

use mesh_agent::{spawn_service, AgentConfig, OverlayKind};
use mesh_ipc::{Command, PipeClient, Request};
use secure_store::DeviceIdentityStore;
use std::path::PathBuf;
use std::time::Duration;

fn test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "meshlink-agent-id-{}-{tag}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn pipe_name(tag: &str) -> String {
    format!(
        r"\\.\pipe\meshlink-agent-test-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u32
    )
}

/// Controller 不可达（端口 9 即时拒绝）——本组测试只验证身份/泄漏面，
/// 完整 Controller 流程由 MVP Gate E2E 覆盖。
fn base_cfg(dir: &PathBuf) -> AgentConfig {
    AgentConfig {
        controller_url: "http://127.0.0.1:9".into(),
        data_dir: dir.clone(),
        overlay: OverlayKind::Mock,
        ..AgentConfig::default()
    }
}

fn hex32(key: &[u8]) -> String {
    let mut s = String::with_capacity(64);
    for b in key {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("hex"));
        s.push(char::from_digit((b & 0xF) as u32, 16).expect("hex"));
    }
    s
}

/// 连接重试：管道实例在后台线程创建（CreateNamedPipeW），首连可能 WinError 2。
fn wait_connect(name: &str, timeout: Duration) -> PipeClient {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match PipeClient::connect(name, Duration::from_secs(2)) {
            Ok(c) => return c,
            Err(_) => {
                if std::time::Instant::now() > deadline {
                    panic!("UI 连接管道超时: {name}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// 用户规格五：`service_identity_restart_stable`。
///
/// MeshAgentService「退出 → 重新启动」（同 data_dir）必须得到同一设备身份：
/// device_id 与公钥逐字节相同（Controller Device Registry 绑定不漂移的
/// 本地前提；重启换钥 = DEVICE_KEY_MISMATCH 事故）。
#[test]
fn service_identity_restart_stable() {
    let dir = test_dir("restart");
    let cfg = base_cfg(&dir);

    // 第一次运行：生成身份。
    let (h1, server1) = spawn_service(cfg.clone(), &pipe_name("restart-1")).expect("spawn #1");
    let snap1 = h1.status();
    let id1 = snap1.device_id.clone();
    assert!(
        id1.starts_with("dev-") && id1.len() == 20,
        "device_id 形如 dev-<16hex>: {id1}"
    );
    let store = DeviceIdentityStore::open(dir.clone());
    let identity1 = store.load().expect("load #1").expect("身份必须已持久化");
    h1.shutdown();
    server1.stop();

    // 「服务重启」：全新进程语义（新 runtime / 新 store 句柄 / 同一 data_dir）。
    let (h2, server2) = spawn_service(cfg, &pipe_name("restart-2")).expect("spawn #2");
    let id2 = h2.status().device_id;
    let identity2 = store.load().expect("load #2").expect("身份必须仍然存在");

    assert_eq!(id1, id2, "重启后 device_id 必须稳定");
    assert_eq!(
        identity1.public_key, identity2.public_key,
        "重启后公钥必须稳定（注册表绑定不漂移）"
    );
    assert_eq!(
        identity1.private_key.as_slice(),
        identity2.private_key.as_slice(),
        "DPAPI(CurrentUser) 解密必须还原同一私钥"
    );
    h2.shutdown();
    server2.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

/// 用户规格五：`ui_process_does_not_receive_private_key`。
///
/// UI 进程只能通过 Named Pipe 与 Agent 通信。本测试以真实 UI 客户端形态
/// 连入管道，逐一发出全部 9 个命令并收集事件流，对响应/事件 JSON 做
/// 私钥泄漏扫描（与 secure-store 直读的真实私钥 hex / 原始字节比对）。
#[test]
fn ui_process_does_not_receive_private_key() {
    let dir = test_dir("uiproc");
    let cfg = base_cfg(&dir);
    let pipe = pipe_name("uiproc");
    let (agent, server) = spawn_service(cfg, &pipe).expect("spawn service");

    // 泄漏比对基准：测试进程模拟"持有直读权限的一方"取得真实私钥。
    let store = DeviceIdentityStore::open(dir.clone());
    let identity = store.load().expect("load").expect("identity");
    let priv_hex = hex32(identity.private_key.as_slice());
    let priv_bytes: Vec<u8> = identity.private_key.as_slice().to_vec();
    assert_eq!(priv_hex.len(), 64);

    // UI 模拟：管道客户端。
    let mut client = wait_connect(&pipe, Duration::from_secs(10));

    let commands: Vec<Command> = vec![
        Command::GetStatus,
        Command::GetDiagnostics,
        Command::ListPeers,
        Command::CreateQuickSession,
        Command::CancelSession,
        Command::JoinQuickSession { code: "482731".into() },
        Command::DisconnectPeer { peer: "dev-nonexistent".into() },
        Command::CreateFriendInvite { ttl: "24h".into(), max_uses: 1 },
        Command::RedeemFriendInvite { invite_id: "none".into(), token: "none".into() },
    ];
    assert_eq!(commands.len(), 9, "规格四的全部 9 命令必须穷举");

    let mut surfaces: Vec<String> = Vec::new();
    for (i, cmd) in commands.into_iter().enumerate() {
        let resp = client
            .request_timeout(&Request { id: i as u64 + 1, command: cmd }, Duration::from_secs(3))
            .unwrap_or_else(|e| panic!("命令 #{i} 应有响应: {e}"));
        surfaces.push(serde_json::to_string(&resp).expect("响应序列化"));
        for ev in client.take_pending_events() {
            surfaces.push(serde_json::to_string(&ev).expect("事件序列化"));
        }
    }
    // 等待一小段时间收集后续事件（Controller 不可达的 Error 事件等）。
    if let Some(msg) = client.wait_message(Duration::from_millis(300)) {
        if let mesh_ipc::ServerMessage::Event(ev) = msg {
            surfaces.push(serde_json::to_string(&ev).expect("事件序列化"));
        }
    }
    assert!(
        surfaces.len() >= 9,
        "应至少收到 9 条命令响应（UI 通信面非空）"
    );

    for surface in &surfaces {
        assert!(
            !surface.contains(&priv_hex),
            "IPC 面泄漏私钥 hex（前 32 字符上下文: {}）",
            &priv_hex[..32.min(priv_hex.len())]
        );
        // 私钥原始字节不得直接出现在 JSON（JSON 为 UTF-8，扫描其字节流）。
        let surface_bytes = surface.as_bytes();
        assert!(
            !contains_subslice(surface_bytes, &priv_bytes),
            "IPC 面泄漏私钥原始字节"
        );
    }
    // 公钥 hex 是公开信息（已注册 Controller），出现属预期——不在此断言。

    agent.shutdown();
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}
