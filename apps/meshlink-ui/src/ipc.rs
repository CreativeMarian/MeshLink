//! UI ↔ MeshAgentService IPC 桥（规格三/四）。
//!
//! - UI 进程**不持有**密钥/credential/UDP socket/Wintun（结构性保证：
//!   `ui_process_does_not_receive_private_key`）；一切经 mesh-ipc Named Pipe；
//! - 单独 IPC 线程独占 `PipeClient`（非线程安全）：命令经 job 通道串行转发，
//!   事件经 Tauri event `agent-event` 推给 webview；
//! - 后台服务进程（mesh-agent.exe）由 UI 拉起（MVP 生命周期；后续里程碑
//!   换 Windows Service 时退化为纯 connect）。

use mesh_ipc::{build_request, Command, Event, PipeClient, Request, Response, ServerMessage, DEFAULT_CONTROLLER_URL, DEFAULT_PIPE_NAME};
use serde_json::json;
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

use crate::supervisor::{ProcessSupervisor, RuntimeDir};

/// 全局唯一默认 Controller 端口（与 Go DefaultControllerPort / mesh-ipc URL 一致）。
/// 任何改动需同步三端（Go main.go / mesh-ipc DEFAULT_CONTROLLER_URL / 本常量）。
const DEFAULT_CONTROLLER_PORT: &str = "18080";

/// 默认公网 Controller（综合修复 P0-2：未配置时不回退本机，而连公网 Controller）。
/// 用户已实测可用：Cloudflare Tunnel + HTTPS + Controller 服务正常。
/// 优先级：MESHLINK_CONTROLLER_URL env > 用户保存配置 > 本常量 > 本地（仅 --local-controller）。
const DEFAULT_PUBLIC_CONTROLLER_URL: &str = "https://controller.bpbpanel.cc.cd";

/// UI → IPC 线程的任务。
enum IpcJob {
    Request {
        req: Request,
        reply: Sender<Result<Response, String>>,
    },
}

/// Tauri managed state。
pub struct IpcState {
    job_tx: Mutex<Option<Sender<IpcJob>>>,
    agent: Mutex<Option<Child>>,
    controller: Mutex<Option<Child>>,
    /// M1-2：DEV/自托管 n2n-supernode 子进程（仅本进程拉起时持有 ownership）。
    supernode: Mutex<Option<Child>>,
    connected: Arc<AtomicBool>,
    next_id: AtomicU64,
    /// M1-1.5：runtime 残留检测只做一次。
    residue_checked: AtomicBool,
    /// M1-1.5：supervisor（mesh-agent / DEV controller / DEV supernode 的所有权管理）。
    supervisor: ProcessSupervisor,
}

impl IpcState {
    pub fn new() -> Self {
        Self {
            job_tx: Mutex::new(None),
            agent: Mutex::new(None),
            controller: Mutex::new(None),
            supernode: Mutex::new(None),
            connected: Arc::new(AtomicBool::new(false)),
            next_id: AtomicU64::new(1),
            residue_checked: AtomicBool::new(false),
            supervisor: ProcessSupervisor::new(),
        }
    }
}

impl Default for IpcState {
    fn default() -> Self {
        Self::new()
    }
}

/// UI 命令返回值（与 mesh-ipc Response 同形，JS 直接读 ok/data/error）。
#[derive(serde::Serialize)]
pub struct IpcReply {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<mesh_ipc::IpcError>,
}

impl IpcReply {
    fn ok(data: serde_json::Value) -> Self {
        Self { ok: true, data: Some(data), error: None }
    }

    fn from_response(r: &Response) -> Self {
        Self { ok: r.ok, data: r.data.clone(), error: r.error.clone() }
    }

    fn err(code: &str, msg: impl Into<String>) -> Self {
        Self { ok: false, data: None, error: Some(mesh_ipc::IpcError::new(code, msg)) }
    }
}

// ---------------------------------------------------------------------------
// Tauri 命令（同步：跑在阻塞线程池，不占 UI 主线程）
// ---------------------------------------------------------------------------

/// 启动时连接 Agent：先探测已有管道（服务已运行形态），失败则拉起 mesh-agent.exe。
/// M1-1.5：首次连接前检测并清理 runtime 残留。
/// 综合修复 P0-1/P0-3：正式版本（无 `--local-controller`）**绝不自动拉起 controller.exe**——
/// Controller 是服务端组件（公网 Controller），不是用户电脑组件；MeshLink 只负责自动拉起
/// mesh-agent.exe 并连接生效 Controller。仅开发模式 `--local-controller` 才允许拉起本机
/// controller（127.0.0.1:18080）用于单机/局域网调试。
#[tauri::command]
pub fn agent_connect(app: AppHandle, state: State<'_, IpcState>) -> Result<IpcReply, String> {
    if state.connected.load(Ordering::Acquire) {
        return send_status(&state);
    }

    // 异常退出残留检测（仅一次）：终止上次 MeshLink 遗留的 agent/controller + 清空 runtime。
    if !state.residue_checked.swap(true, Ordering::AcqRel) {
        let killed = state.supervisor.detect_and_clean_residue();
        if killed > 0 {
            eprintln!("[MeshLink] 启动时已清理 {killed} 个异常退出残留进程");
        }
    }

    // 生效 Controller 地址（综合修复 P0-2：永不回退本机；未配置时默认公网 Controller）。
    let Some(controller_url) = effective_controller_url() else {
        // 理论不可达（effective_controller_url 恒有值）；保留防御。
        return Ok(IpcReply::ok(serde_json::json!({
            "state": "NOT_CONFIGURED",
            "configured": false,
            "user_facing": "等待创建连接",
            "controller_url": "",
        })));
    };

    // 仅开发模式（--local-controller）且模式为 local/lan 才拉起本机 controller。
    // 正式版本（默认）任何模式都不拉起本机 controller.exe。
    let mode = controller_mode();
    let manage_controller = local_controller_enabled() && (mode == "local" || mode == "lan");
    if manage_controller && !controller_healthy(&controller_url) {
        spawn_controller(&state, &mode)?;
    }

    // 自动拉起 mesh-agent（P0-3）：连接失败自动重试最多 3 次（P2-2 自动恢复）。
    // 每次重试先探测管道（服务可能已被上次 MeshLink 拉起），失败再 spawn。
    let pipe = std::env::var("MESHLINK_PIPE_NAME").unwrap_or_else(|_| DEFAULT_PIPE_NAME.into());
    let mut last_err: String = "未知错误".into();
    let mut client = None;
    for attempt in 1..=3u32 {
        match PipeClient::connect(&pipe, Duration::from_millis(1500)) {
            Ok(c) => {
                client = Some(c);
                break;
            }
            Err(_) => {
                // 拉起 agent（幂等：若已运行则 connect 会成功；此处管道不可达才 spawn）。
                match spawn_agent_process(&pipe, &state.supervisor.runtime, &controller_url) {
                    Ok(child) => {
                        *state.agent.lock().unwrap() = Some(child);
                        match PipeClient::connect(&pipe, Duration::from_secs(15)) {
                            Ok(c) => {
                                client = Some(c);
                                break;
                            }
                            Err(e) => {
                                // spawn 成功但管道未就绪：回收本进程拉起的 agent，下一轮重试。
                                if let Some(mut ch) = state.agent.lock().unwrap().take() {
                                    let _ = ch.kill();
                                    let _ = ch.wait();
                                }
                                last_err = format!("后台服务未就绪：{e}");
                            }
                        }
                    }
                    Err(e) => {
                        last_err = format!("后台服务启动失败：{e}");
                    }
                }
            }
        }
        if attempt < 3 {
            std::thread::sleep(Duration::from_millis(1000));
        }
    }
    let client = client.ok_or_else(|| format!("{last_err}（已重试 3 次）"))?;

    start_ipc_loop(state.inner(), app, client);
    // M1-2：仅开发模式（本机/局域网 controller）拉起本机 n2n-supernode 并注册到
    // Controller Supernode Registry（Agent 持有 credential；UI 不触碰密钥）。
    // 正式版连公网 Controller：Supernode 池由 Controller Registry 下发，不拉起本机 SN。
    if manage_controller {
        let _ = spawn_dev_supernode_and_register(state.inner());
    }
    send_status(&state)
}

/// 开发模式（--local-controller）：允许 MeshLink 拉起本机 controller.exe（127.0.0.1:18080）。
/// 判定：命令行 `--local-controller` 或环境变量 `MESHLINK_LOCAL_CONTROLLER=1`（自动化测试注入）。
fn local_controller_enabled() -> bool {
    let has_flag = std::env::args().any(|a| a == "--local-controller");
    let has_env = std::env::var("MESHLINK_LOCAL_CONTROLLER")
        .map(|v| v == "1")
        .unwrap_or(false);
    has_flag || has_env
}

/// 当前 Controller 模式：`local` | `lan` | `remote` | `""`（未配置）。
/// 环境变量 MESHLINK_CONTROLLER_URL 视为显式指定既有地址（remote 语义，不自动拉起本机）。
fn controller_mode() -> String {
    if std::env::var("MESHLINK_CONTROLLER_URL").map(|v| !v.trim().is_empty()).unwrap_or(false) {
        return "remote".into();
    }
    load_ui_config()
        .ok()
        .and_then(|v| v.get("controller_mode").and_then(|x| x.as_str()).map(String::from))
        .filter(|m| m == "local" || m == "lan" || m == "remote")
        .unwrap_or_default()
}

/// 生效 Controller 地址（综合修复 P0-2 优先级，恒有值、永不回退本机默认）：
/// 1. 环境变量 `MESHLINK_CONTROLLER_URL` 最高（测试/运维显式覆盖）；
/// 2. 用户保存配置（controller_url，无论模式——用户填的公网地址必须被尊重）；
/// 3. 开发模式（--local-controller）：本机/局域网 Controller；
/// 4. 默认公网 Controller（正式版未配置时连公网，不连 127.0.0.1）。
/// 禁止：用户设置公网地址后自动回退 127.0.0.1 / 192.168.x.x。
fn effective_controller_url() -> Option<String> {
    // 1. 环境变量最高优先。
    if let Ok(url) = std::env::var("MESHLINK_CONTROLLER_URL") {
        let url = url.trim().to_string();
        if !url.is_empty() {
            return Some(url);
        }
    }
    // 2. 用户保存配置（controller_url 为唯一权威地址来源；mode 不再覆盖它）。
    if let Ok(cfg) = load_ui_config() {
        let saved = cfg
            .get("controller_url")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if !saved.is_empty() {
            return Some(saved);
        }
    }
    // 3. 开发模式（--local-controller）：本机 / 局域网 Controller。
    if local_controller_enabled() {
        let mode = controller_mode();
        return Some(if mode == "lan" { lan_controller_url() } else { local_controller_url() });
    }
    // 4. 默认公网 Controller（正式版兜底）。
    Some(DEFAULT_PUBLIC_CONTROLLER_URL.to_string())
}

/// 本机（创建连接/发起方）Controller 地址：有 RFC1918 私网地址则自动启用局域网访问
/// （供其他设备加入），否则回退 127.0.0.1。
fn local_controller_url() -> String {
    match detect_lan_ipv4() {
        Some(ip) => format!("http://{ip}:{}", DEFAULT_CONTROLLER_PORT),
        None => DEFAULT_CONTROLLER_URL.to_string(),
    }
}

/// 局域网 Controller 地址：http://<本机 RFC1918 IPv4>:18080。
/// 若无可用私网地址（异常环境），回退到默认 127.0.0.1 并在日志中告警。
fn lan_controller_url() -> String {
    let ip = detect_lan_ipv4().unwrap_or_else(|| {
        eprintln!("[MeshLink] 未找到本机 RFC1918 IPv4，局域网 Controller 回退监听 127.0.0.1");
        "127.0.0.1".to_string()
    });
    format!("http://{ip}:{}", DEFAULT_CONTROLLER_PORT)
}

/// 自动获取本机 RFC1918 IPv4（局域网访问用）。遍历所有 up 接口，
/// 选一个非回环的私网 IPv4（10/8、172.16/12、192.168/16）；无则 None。
fn detect_lan_ipv4() -> Option<String> {
    let list = local_ip_address::list_afinet_netifas().ok()?;
    let mut candidates: Vec<String> = Vec::new();
    for (_name, ip) in list {
        let ip = ip.to_string();
        let host = ip.split('%').next().unwrap_or(&ip);
        if host
            .parse::<std::net::Ipv4Addr>()
            .map(|a| a.is_private() && !a.is_loopback())
            .unwrap_or(false)
        {
            candidates.push(host.to_string());
        }
    }
    // 优先级：取第一个私网 IPv4。多网卡时可在设置页高级选项手动指定（未来增强）。
    candidates.first().cloned()
}

/// healthz 探测（复用 controller-client 白名单与请求路径；短超时）。
fn controller_healthy(url: &str) -> bool {
    let Ok(client) = controller_client::Client::new(url) else {
        return false;
    };
    client.healthz().is_ok()
}

/// 拉起 controller.exe（按 Controller 模式选择监听方式；所有权记录到 runtime）。
/// - local：-addr 127.0.0.1:18080（仅本机访问，默认安全模式；有局域网地址则自动启用局域网监听）
/// - lan：-addr <本机RFC1918私网IP>:18080 -allow-lan-plaintext（共享给局域网其他设备）
/// remote 模式不会走到这里（不拉起本机 controller）。
/// 日志：`[Controller Start] Mode: LOCAL/LAN Listen: <addr>`（用户规格六）。
fn spawn_controller(state: &IpcState, mode: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("exe 路径失败：{e}"))?;
    let dir = exe.parent().ok_or("exe 目录解析失败")?;
    let controller = dir.join("controller.exe");
    if !controller.exists() {
        // 未随包携带时（如纯 dev 环境）不阻断：Agent 会以 CONTROLLER_UNREACHABLE 呈现。
        eprintln!("[MeshLink] 未找到 controller.exe（{}），跳过自动拉起", controller.display());
        return Ok(());
    }

    // 监听地址与参数：local = 本机（有局域网地址自动启用局域网监听）；lan = 显式局域网。
    let (listen_addr, allow_lan, mode_label) = controller_listen_spec(mode);

    // 日志落 logs/controller.log（综合修复 P2-1：分类日志目录）。
    let stderr = append_log_stderr("controller.log");
    let mut cmd = StdCommand::new(&controller);
    cmd.arg("-addr").arg(&listen_addr);
    if allow_lan {
        cmd.arg("-allow-lan-plaintext");
    }
    cmd.stdout(Stdio::null()).stderr(stderr);

    // 用户规格六：[Controller Start] 日志（含模式与监听地址；同时写 app.log 供诊断中心）。
    eprintln!("[Controller Start] Mode: {mode_label} Listen: {listen_addr}");
    append_log("app.log", &format!("[Controller Start] Mode: {mode_label} Listen: {listen_addr}"));

    let child = state
        .supervisor
        .spawn_managed("controller", "controller.exe", &mut cmd)
        .map_err(|e| format!("controller 启动失败：{e}"))?;
    *state.controller.lock().unwrap() = Some(child);

    // 等待 healthz 就绪（最多 ~10s；controller 无参启动很快）。
    let health_url = format!("http://{listen_addr}");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if controller_healthy(&health_url) {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("controller 启动超时（healthz 未就绪）：{health_url}"));
        }
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// 根据 Controller 模式计算监听规格（listen_addr, allow_lan_plaintext, mode_label）。
/// - `lan`：必须监听局域网（有 RFC1918 地址则用之，否则回退 127.0.0.1）；
/// - `local`：有局域网地址则自动启用局域网监听（供其他设备加入），否则 127.0.0.1。
/// 纯函数（不触碰 I/O），供单测锁定启动参数策略。
fn controller_listen_spec(mode: &str) -> (String, bool, &'static str) {
    let lan_ip = detect_lan_ipv4();
    match mode {
        "lan" => {
            let ip = lan_ip.unwrap_or_else(|| "127.0.0.1".to_string());
            (format!("{ip}:{DEFAULT_CONTROLLER_PORT}"), true, "LAN")
        }
        _ => match lan_ip {
            Some(ip) => (format!("{ip}:{DEFAULT_CONTROLLER_PORT}"), true, "LOCAL"),
            None => (format!("127.0.0.1:{DEFAULT_CONTROLLER_PORT}"), false, "LOCAL"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controller_listen_spec_lan_requires_lan_plaintext() {
        // lan 模式：必然带 -allow-lan-plaintext；无私网地址时回退 127.0.0.1。
        let (addr, allow_lan, label) = controller_listen_spec("lan");
        assert!(allow_lan, "lan 模式必须启用局域网明文");
        assert_eq!(label, "LAN");
        assert!(!addr.starts_with("http"), "addr 应是不带 scheme 的 host:port: {addr}");
        assert!(addr.ends_with(":18080"), "端口固定 18080: {addr}");
    }

    #[test]
    fn controller_listen_spec_local_auto_lan() {
        // local 模式：监听地址要么是私网 IPv4（自动启用局域网），要么是 127.0.0.1（仅本机）。
        let (addr, _allow_lan, label) = controller_listen_spec("local");
        assert_eq!(label, "LOCAL");
        let host = addr.split(':').next().unwrap();
        if host != "127.0.0.1" {
            assert!(
                host.parse::<std::net::Ipv4Addr>().map(|a| a.is_private()).unwrap_or(false),
                "local 有局域网地址时应为私网 IPv4: {addr}"
            );
        }
    }

    #[test]
    fn controller_listen_spec_port_is_canonical() {
        assert_eq!(DEFAULT_CONTROLLER_PORT, "18080");
    }
}

/// M1-2：DEV 模式拉起本机 n2n-supernode.exe（无参 → 默认 0.0.0.0:7654）并注册到
/// Controller Supernode Registry（经 Agent IPC，credential 由 Agent 持有）。
/// - n2n-supernode.exe 未随包 → 跳过（N2N 路径仍可由 Controller Registry 下发远程 SN）。
/// - 已拉起（重连场景）→ 幂等复用，仅重新注册刷新健康时间。
fn spawn_dev_supernode_and_register(state: &IpcState) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("exe 路径失败：{e}"))?;
    let dir = exe.parent().ok_or("exe 目录解析失败")?;
    let sn = dir.join("n2n-supernode.exe");
    if !sn.exists() {
        eprintln!("[MeshLink] 未找到 n2n-supernode.exe（{}），跳过自动拉起", sn.display());
        return Ok(());
    }

    // 仅当本进程尚未拉起 supernode 时 spawn（重连幂等）。
    if state.supernode.lock().unwrap().is_none() {
        let stderr = append_log_stderr("supernode.log");
        let mut cmd = StdCommand::new(&sn);
        cmd.stdout(Stdio::null()).stderr(stderr);
        let child = state
            .supervisor
            .spawn_managed("supernode", "n2n-supernode.exe", &mut cmd)
            .map_err(|e| format!("n2n-supernode 启动失败：{e}"))?;
        *state.supernode.lock().unwrap() = Some(child);
    }

    // 注册到 Controller Registry（host 用回环地址；优先绑定可被对端访问的地址由
    // 用户后续配置远程 SN 覆盖）。注册失败不阻断（Agent 仍可连远程 SN 池）。
    if let Some(tx) = state.job_tx.lock().unwrap().clone() {
        let req = Request {
            id: state.next_id.fetch_add(1, Ordering::Relaxed),
            command: Command::RegisterLocalSupernode {
                sn_id: "sn-local".into(),
                host: "127.0.0.1".into(),
                port: 7654,
                priority: 100,
            },
        };
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx.send(IpcJob::Request { req, reply: reply_tx }).is_ok() {
            match reply_rx.recv_timeout(Duration::from_secs(10)) {
                Ok(Ok(_)) => eprintln!("[MeshLink] 本机 Supernode sn-local 已注册到 Controller"),
                Ok(Err(e)) => eprintln!("[MeshLink] Supernode 注册失败: {e}"),
                Err(_) => eprintln!("[MeshLink] Supernode 注册超时"),
            }
        }
    }
    Ok(())
}

/// 转发一条 IPC 命令（统一入口；未知命令 serde 直接拒绝）。
/// wire 构造复用 `mesh_ipc::build_request`——与 GUI Bridge 集成测试同一路径。
#[tauri::command]
pub fn ipc_request(
    state: State<'_, IpcState>,
    cmd: String,
    payload: Option<serde_json::Value>,
) -> Result<IpcReply, String> {
    let tx = state.job_tx.lock().unwrap().clone();
    let Some(tx) = tx else {
        return Ok(IpcReply::err("AGENT_STOPPED", "后台服务未连接"));
    };

    let req = build_request(&state.next_id, &cmd, payload.as_ref())?;

    let (reply_tx, reply_rx) = mpsc::channel();
    tx.send(IpcJob::Request { req, reply: reply_tx })
        .map_err(|_| "IPC 线程已退出".to_string())?;

    match reply_rx.recv_timeout(Duration::from_secs(20)) {
        Ok(Ok(resp)) => Ok(IpcReply::from_response(&resp)),
        Ok(Err(e)) => Ok(IpcReply::err("AGENT_STOPPED", format!("后台服务断开：{e}"))),
        Err(_) => Ok(IpcReply::err("AGENT_TIMEOUT", "后台服务响应超时")),
    }
}

/// 返回默认 Controller 地址（综合修复 P0-2：正式版默认公网 Controller；
/// 本地开发默认 127.0.0.1:18080 由 mesh-ipc `DEFAULT_CONTROLLER_URL` 保留为 DEV 锚点）。
/// 设置页无已保存配置时用它回填输入框——JS 不再各自硬编码。
#[tauri::command]
pub fn get_controller_default() -> Result<String, String> {
    Ok(DEFAULT_PUBLIC_CONTROLLER_URL.to_string())
}

/// 读取 UI 侧普通配置（M1-1：Controller 地址。credential/private key 仍只归 Agent）。
#[tauri::command]
pub fn load_ui_config() -> Result<serde_json::Value, String> {
    let path = ui_config_path();
    if !path.exists() {
        // 双机架构调整：首次启动无配置 → 未配置 Controller（不再默认 127.0.0.1）。
        return Ok(serde_json::json!({ "controller_url": "", "controller_mode": "" }));
    }
    let text = std::fs::read_to_string(&path).map_err(|e| format!("读取配置失败：{e}"))?;
    let mut v: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("配置解析失败：{e}"))?;
    // 兼容旧配置：无 controller_mode 字段时补齐（不覆盖用户已保存地址）。
    if v.get("controller_mode").is_none() {
        let mode = if v.get("controller_url").and_then(|x| x.as_str()).map(|s| !s.is_empty()).unwrap_or(false) {
            "remote"
        } else {
            ""
        };
        v["controller_mode"] = serde_json::json!(mode);
    }
    Ok(v)
}

/// 保存 Controller 配置到普通配置（设置页；下次启动 spawn 时作为默认值）。
/// 综合修复 P0-2：`controller_url` 是唯一权威地址来源——用户填写的地址（含公网
/// https://…）必须原样保存并被 `effective_controller_url` 采纳，**不得**因模式
/// local/lan 而覆盖成本机/局域网地址（旧 bug：用户设公网地址后回退 127.0.0.1）。
/// - 用户填地址（任意模式）：校验后保存；
/// - 用户留空 + 开发模式（--local-controller）local/lan：保存推导的本机/局域网地址；
/// - 用户留空 + 其他：报错（提示填地址）。
/// 仅允许合法地址（生产 HTTPS / DEV localhost / RFC1918 私网）；公网明文 HTTP 拒绝。
#[tauri::command]
pub fn save_controller_config(mode: String, url: String) -> Result<serde_json::Value, String> {
    let mode = mode.trim().to_string();
    if mode != "local" && mode != "lan" && mode != "remote" {
        return Err("Controller 模式必须是 local（本机）、lan（局域网）或 remote（已有地址）。".into());
    }
    let url = url.trim().trim_end_matches('/').to_string();
    let effective = if url.is_empty() {
        // 留空：创建连接（local/lan）允许空——正式版回退默认公网、dev 模式回退本机；
        // 加入连接（remote）必须显式填地址。
        if mode == "local" || mode == "lan" {
            String::new()
        } else {
            return Err("请输入服务器地址（可展开「高级设置」填写 https://…）。".into());
        }
    } else {
        validate_controller_url(&url)?;
        url
    };
    let cfg = serde_json::json!({
        "controller_mode": mode,
        "controller_url": effective,
    });
    let path = ui_config_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    std::fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap())
        .map_err(|e| format!("保存配置失败：{e}"))?;
    Ok(cfg)
}

/// 兼容保留：仅保存地址（旧调用方/测试用）。地址归属按 remote 语义（不自动拉起本机）。
#[tauri::command]
pub fn save_controller_url(url: String) -> Result<serde_json::Value, String> {
    save_controller_config("remote".into(), url)
}

/// 读取当前 Controller 配置（模式 + 地址 + 生效地址 + 是否已配置 + 本机局域网地址）。
#[tauri::command]
pub fn get_controller_config() -> Result<serde_json::Value, String> {
    let cfg = load_ui_config().ok().unwrap_or_else(|| serde_json::json!({}));
    let mode = cfg.get("controller_mode").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let url = cfg.get("controller_url").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let effective = effective_controller_url().unwrap_or_default();
    let lan_ip = detect_lan_ipv4().unwrap_or_default();
    Ok(serde_json::json!({
        // configured = 用户是否显式保存了地址（区别于「默认公网回退」）。
        "configured": !url.is_empty(),
        "mode": mode,
        "controller_url": url,
        "effective_url": effective,
        "lan_ip": lan_ip,
    }))
}

/// Controller URL 白名单（与 controller-client parse_base_url 对齐）：
/// DEV 仅 http://localhost/ http://127.0.0.1/；生产必须 https://。无降级。
/// 局域网双机联机：http:// 私网地址（RFC1918）显式放行（仅可信局域网）。
fn validate_controller_url(url: &str) -> Result<(), String> {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => return Err("地址格式无效，请确认包含协议（如 https://）。".into()),
    };
    if scheme == "https" {
        return Ok(());
    }
    if scheme == "http" {
        let host = rest.split(['/', ':', '?']).next().unwrap_or("").to_ascii_lowercase();
        if host == "localhost" || host == "127.0.0.1" {
            return Ok(());
        }
        // 局域网（RFC1918）明文：仅可信局域网联机用；公网明文始终拒绝。
        if is_private_host(&host) {
            return Ok(());
        }
        return Err("生产 Controller 必须使用 HTTPS（开发机可用 http://localhost/ 或 http://127.0.0.1/，局域网联机可用私网地址）。".into());
    }
    Err("Controller 地址仅支持 https://（开发机可用 http://localhost/ 或 http://127.0.0.1/）。".into())
}

/// 判定主机名是否 RFC1918 私网（10/8、172.16/12、192.168/16）。
fn is_private_host(host: &str) -> bool {
    use std::net::IpAddr;
    match host.parse::<IpAddr>() {
        // Ipv4Addr::is_private() 稳定（RFC1918）；IPv6 局域网联机请走 https。
        Ok(IpAddr::V4(v4)) => v4.is_private(),
        Ok(IpAddr::V6(_)) => false,
        Err(_) => false,
    }
}

fn ui_config_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&base).join("MeshLink").join("ui").join("config.json")
}

// ---------------------------------------------------------------------------
// 诊断中心日志（综合修复 P2-1）
//
// 分类日志目录：`%LOCALAPPDATA%\MeshLink\logs\`（与 data_dir/runtime 同根）：
//   app.log          MeshLink 应用生命周期日志（本进程关键动作）
//   agent.log        mesh-agent 输出（含连接/网络/错误事件行）
//   controller.log   本机 controller（仅 --local-controller 开发模式）
//   supernode.log    本机 n2n-supernode（仅 --local-controller 开发模式）
// connection/network/error 为 agent.log 的分类过滤视图（诊断中心按关键词读取）。
// ---------------------------------------------------------------------------

fn logs_dir() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
    std::path::Path::new(&base).join("MeshLink").join("logs")
}

/// 打开日志文件追加句柄（创建父目录；失败回退 Stdio::null）。
fn append_log_stderr(name: &str) -> Stdio {
    let dir = logs_dir();
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join(name);
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        Ok(f) => Stdio::from(f),
        Err(_) => Stdio::null(),
    }
}

/// 向分类日志追加一行（MeshLink 自身关键生命周期事件，诊断中心可见）。
fn append_log(name: &str, line: &str) {
    let dir = logs_dir();
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    use std::io::Write;
    let mut f = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(name))
    {
        Ok(f) => f,
        Err(_) => return,
    };
    let _ = writeln!(f, "{line}");
}

/// 读取分类日志（诊断中心「日志查看」）。返回每个分类最近 `limit` 行。
/// - `all`：合并 app + agent + controller + supernode（逐文件合并）。
/// - `agent` / `controller` / `supernode`：对应原始日志。
/// - `connection` / `network` / `error`：agent.log 按关键词过滤视图。
#[tauri::command]
pub fn read_log_files(
    category: Option<String>,
    limit: Option<usize>,
) -> Result<serde_json::Value, String> {
    let limit = limit.unwrap_or(200).min(2000);
    let cat = category.unwrap_or_else(|| "all".into());
    let dir = logs_dir();
    let _ = std::fs::create_dir_all(&dir);

    let read_last = |name: &str, filter: Option<&[&str]>| -> Vec<String> {
        let path = dir.join(name);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Vec::new();
        };
        let mut lines: Vec<String> = text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter(|l| match filter {
                Some(kws) => kws.iter().any(|k| l.to_ascii_lowercase().contains(k)),
                None => true,
            })
            .map(|l| l.to_string())
            .collect();
        let skip = lines.len().saturating_sub(limit);
        lines.drain(..skip);
        lines
    };

    let files = [
        ("app", dir.join("app.log")),
        ("agent", dir.join("agent.log")),
        ("controller", dir.join("controller.log")),
        ("supernode", dir.join("supernode.log")),
    ];

    let result = match cat.as_str() {
        "app" => serde_json::json!({ "category": "app", "lines": read_last("app.log", None) }),
        "agent" => serde_json::json!({ "category": "agent", "lines": read_last("agent.log", None) }),
        "controller" => serde_json::json!({ "category": "controller", "lines": read_last("controller.log", None) }),
        "supernode" => serde_json::json!({ "category": "supernode", "lines": read_last("supernode.log", None) }),
        "connection" => serde_json::json!({
            "category": "connection",
            "source": "agent.log",
            "lines": read_last("agent.log", Some(&["peer", "candidate", "directlink", "n2n", "session", "connected", "disconnect", "punch"])),
        }),
        "network" => serde_json::json!({
            "category": "network",
            "source": "agent.log",
            "lines": read_last("agent.log", Some(&["stun", "nat", "udp", "socket", "port", "icmp"])),
        }),
        "error" => serde_json::json!({
            "category": "error",
            "lines": read_last("agent.log", Some(&["error", "failed", "失败", "timeout", "超时", "unreachable"]))
                .into_iter()
                .chain(read_last("app.log", Some(&["error", "失败"])))
                .collect::<Vec<_>>(),
        }),
        "files" => serde_json::json!({
            "category": "files",
            "dir": dir.to_string_lossy(),
            "files": files.iter().filter(|(_, p)| p.exists()).map(|(n, p)| json!({
                "name": n,
                "size": std::fs::metadata(p).map(|m| m.len()).unwrap_or(0),
            })).collect::<Vec<_>>(),
        }),
        _ => {
            // all：合并四个原始日志（文件存在才合并）。
            let mut lines: Vec<String> = Vec::new();
            for (tag, path) in &files {
                if path.exists() {
                    if let Ok(text) = std::fs::read_to_string(path) {
                        for l in text.lines().filter(|l| !l.trim().is_empty()) {
                            lines.push(format!("[{tag}] {l}"));
                        }
                    }
                }
            }
            let skip = lines.len().saturating_sub(limit);
            lines.drain(..skip);
            serde_json::json!({ "category": "all", "lines": lines })
        }
    };

    Ok(result)
}

/// UI 退出时有序回收（M1-1.5 规格二）：
/// 1. 停止新的 UI 请求（job_tx 置 None）
/// 2. 通知 mesh-agent 优雅 shutdown（关闭当前会话 → 清理 runtime 临时文件 → 进程自退）
/// 3. 删除临时运行配置（runtime 目录整体清空）
/// 4. 关闭 mesh-agent（兜底 kill，进程通常已在 2 自退）
/// 5. 关闭 DEV controller（仅当本进程拉起，ownership 判断）
pub fn shutdown(state: &IpcState) {
    // 1. 停止新的 UI 请求，同时取出 tx 用于发送 Shutdown。
    let tx = state.job_tx.lock().unwrap().take();
    if let Some(tx) = tx {
        let req = Request {
            id: state.next_id.fetch_add(1, Ordering::Relaxed),
            command: Command::Shutdown,
        };
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx.send(IpcJob::Request { req, reply: reply_tx }).is_ok() {
            let _ = reply_rx.recv_timeout(Duration::from_secs(3));
        }
    }

    // 3. 删除临时运行配置（agent 已在 Shutdown 中清自己的临时文件，这里删整个目录）。
    state.supervisor.runtime.clear_all();

    // 4. 关闭 mesh-agent（兜底：graceful 后进程通常已自退，kill 保证无残留）。
    if let Some(mut child) = state.agent.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    // 5. 关闭 DEV controller（仅关本进程拉起的）。
    if let Some(mut child) = state.controller.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }

    // M1-2：关闭本机 n2n-supernode（仅关本进程拉起的）。
    if let Some(mut child) = state.supernode.lock().unwrap().take() {
        let _ = child.kill();
        let _ = child.wait();
    }
}

// ---------------------------------------------------------------------------
// 内部
// ---------------------------------------------------------------------------

fn send_status(state: &State<'_, IpcState>) -> Result<IpcReply, String> {
    let tx = state.job_tx.lock().unwrap().clone();
    let Some(tx) = tx else {
        return Ok(IpcReply::err("AGENT_STOPPED", "后台服务未连接"));
    };
    let req = Request {
        id: state.next_id.fetch_add(1, Ordering::Relaxed),
        command: Command::GetStatus,
    };
    let (reply_tx, reply_rx) = mpsc::channel();
    tx.send(IpcJob::Request { req, reply: reply_tx })
        .map_err(|_| "IPC 线程已退出".to_string())?;
    match reply_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(resp)) => Ok(IpcReply::from_response(&resp)),
        Ok(Err(e)) => Ok(IpcReply::err("AGENT_STOPPED", format!("后台服务断开：{e}"))),
        Err(_) => Ok(IpcReply::err("AGENT_TIMEOUT", "后台服务响应超时")),
    }
}

fn spawn_agent_process(pipe: &str, runtime: &RuntimeDir, controller_url: &str) -> Result<Child, String> {
    let exe = std::env::current_exe().map_err(|e| format!("exe 路径失败：{e}"))?;
    let dir = exe.parent().ok_or("exe 目录解析失败")?;
    let agent = dir.join("mesh-agent.exe");
    if !agent.exists() {
        return Err(format!("未找到后台服务 {}", agent.display()));
    }

    // Controller 地址由调用方（agent_connect）解析传入：未配置时不会走到本函数。
    let controller = controller_url.to_string();
    let overlay = std::env::var("MESHLINK_OVERLAY").unwrap_or_else(|_| "wintun".into());
    let data_dir = std::env::var("MESHLINK_DATA_DIR").unwrap_or_else(|_| {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
        format!("{local}\\MeshLink\\agent")
    });
    // M1-1.5：runtime 目录（supervisor 与 agent 共用；agent 写临时文件，supervisor 删整个目录）。
    let runtime_dir = runtime.dir.to_string_lossy().into_owned();

    // Agent 日志落 logs/agent.log（综合修复 P2-1：分类日志目录；无控制台窗口时的诊断来源）。
    let stderr = append_log_stderr("agent.log");
    append_log("app.log", &format!("[MeshLink] 启动 mesh-agent：controller={controller_url} pipe={pipe}"));

    let mut cmd = StdCommand::new(&agent);
    cmd.env("MESHLINK_CONTROLLER_URL", controller)
        .env("MESHLINK_OVERLAY", overlay)
        .env("MESHLINK_DATA_DIR", data_dir)
        .env("MESHLINK_RUNTIME_DIR", runtime_dir)
        .env("MESHLINK_PIPE_NAME", pipe)
        .stdout(Stdio::null())
        .stderr(stderr);
    for key in ["MESHLINK_DEVICE_NAME", "MESHLINK_STUN"] {
        if let Ok(val) = std::env::var(key) {
            cmd.env(key, val);
        }
    }
    // 所有权记录到 runtime/managed_process.json（异常退出后可据此清理）。
    let supervisor = ProcessSupervisor::with_runtime(runtime.clone());
    supervisor.spawn_managed("agent", "mesh-agent.exe", &mut cmd)
}

/// PipeClient 含裸管道句柄（非 Send）；IPC 线程独占所有权后传递是健全的。
struct SendPipeClient(PipeClient);
unsafe impl Send for SendPipeClient {}

/// IPC 线程：独占 PipeClient。命令（job 通道）与事件（管道读）交替处理：
/// 事件必须持续流动（Agent 推送进度事件时 UI 并不发出命令）。
fn start_ipc_loop(state: &IpcState, app: AppHandle, client: PipeClient) {
    let (job_tx, job_rx) = mpsc::channel::<IpcJob>();
    *state.job_tx.lock().unwrap() = Some(job_tx);
    state.connected.store(true, Ordering::Release);

    let conn = state.connected.clone();
    let client = SendPipeClient(client);
    std::thread::Builder::new()
        .name("ui-ipc-loop".into())
        .spawn(move || {
            let app = app;
            let mut client = client;
            ipc_loop(&app, &mut client.0, &job_rx);
            if client.0.is_closed() {
                let _ = app.emit(
                    "agent-event",
                    &Event::Error {
                        code: "AGENT_STOPPED".into(),
                        message: "后台服务已断开".into(),
                    },
                );
            }
            conn.store(false, Ordering::Release);
        })
        .expect("IPC 线程创建失败");
}

fn ipc_loop(app: &AppHandle, client: &mut PipeClient, job_rx: &Receiver<IpcJob>) {
    loop {
        // 1. 非阻塞清空积压命令。
        loop {
            match job_rx.try_recv() {
                Ok(IpcJob::Request { req, reply }) => {
                    let resp = client.request_timeout(&req, Duration::from_secs(15));
                    let _ = reply.send(resp.map_err(|e| e.to_string()));
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return,
            }
        }
        // 2. 冲刷请求期间排队的 pending 事件。
        for ev in client.take_pending_events() {
            let _ = app.emit("agent-event", &ev);
        }
        if client.is_closed() {
            return;
        }
        // 3. 等待下一条事件（200ms 窗口兼作命令等待）。
        match client.wait_message(Duration::from_millis(200)) {
            Some(ServerMessage::Event(ev)) => {
                let _ = app.emit("agent-event", &ev);
            }
            Some(ServerMessage::Response(_)) => {}
            None => {
                if client.is_closed() {
                    return;
                }
            }
        }
    }
}
