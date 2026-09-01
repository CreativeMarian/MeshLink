//! UI ↔ MeshAgentService IPC 桥（规格三/四）。
//!
//! - UI 进程**不持有**密钥/credential/UDP socket/Wintun（结构性保证：
//!   `ui_process_does_not_receive_private_key`）；一切经 mesh-ipc Named Pipe；
//! - 单独 IPC 线程独占 `PipeClient`（非线程安全）：命令经 job 通道串行转发，
//!   事件经 Tauri event `agent-event` 推给 webview；
//! - 后台服务进程（mesh-agent.exe）由 UI 拉起（MVP 生命周期；后续里程碑
//!   换 Windows Service 时退化为纯 connect）。

use mesh_ipc::{build_request, Command, Event, PipeClient, Request, Response, ServerMessage, DEFAULT_CONTROLLER_URL, DEFAULT_PIPE_NAME};
use std::process::{Child, Command as StdCommand, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter, State};

use crate::supervisor::{ProcessSupervisor, RuntimeDir};

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
/// 双机架构调整（ADR-004 延续）：
/// - 无 Controller 配置 → 不拉起 controller / agent，返回 NOT_CONFIGURED（UI 显示「未配置 Controller」）；
/// - 仅当用户显式选择「本机 Controller」模式且地址为 dev loopback 时，才允许本进程拉起本地 controller.exe；
/// - 「已有 Controller 地址」模式（含远程/局域网共享 Controller）绝不自动拉起本机 controller。
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

    // 生效 Controller 地址：None = 未配置。未配置时不默认连 127.0.0.1、不拉起任何子进程。
    let Some(controller_url) = effective_controller_url() else {
        return Ok(IpcReply::ok(serde_json::json!({
            "state": "NOT_CONFIGURED",
            "configured": false,
            "user_facing": "未配置 Controller",
            "controller_url": "",
        })));
    };

    // 是否本机 Controller 模式（显式选择后，MeshLink 才负责拉起 controller.exe）。
    let local_mode = controller_mode() == "local";
    let dev_mode = local_mode && is_dev_controller(&controller_url);    if dev_mode && !controller_healthy(&controller_url) {
        spawn_dev_controller(&state)?;
    }

    let pipe =
        std::env::var("MESHLINK_PIPE_NAME").unwrap_or_else(|_| DEFAULT_PIPE_NAME.into());

    let client = match PipeClient::connect(&pipe, Duration::from_millis(1500)) {
        Ok(c) => c,
        Err(_) => {
            let child = spawn_agent_process(&pipe, &state.supervisor.runtime, &controller_url)
                .map_err(|e| format!("后台服务启动失败：{e}"))?;
            *state.agent.lock().unwrap() = Some(child);
            PipeClient::connect(&pipe, Duration::from_secs(15))
                .map_err(|e| format!("连接后台服务失败：{e}"))?
        }
    };

    start_ipc_loop(state.inner(), app, client);
    // M1-2：DEV 模式拉起本机 n2n-supernode 并注册到 Controller Supernode Registry
    // （Agent 持有 credential；UI 不触碰密钥。注册失败不阻断首页 READY）。
    if dev_mode {
        let _ = spawn_dev_supernode_and_register(state.inner());
    }
    send_status(&state)
}

/// 当前 Controller 模式：`local` | `remote` | `""`（未配置）。
/// 环境变量 MESHLINK_CONTROLLER_URL 视为显式指定既有地址（remote 语义，不自动拉起本机）。
fn controller_mode() -> String {
    if std::env::var("MESHLINK_CONTROLLER_URL").map(|v| !v.trim().is_empty()).unwrap_or(false) {
        return "remote".into();
    }
    load_ui_config()
        .ok()
        .and_then(|v| v.get("controller_mode").and_then(|x| x.as_str()).map(String::from))
        .filter(|m| m == "local" || m == "remote")
        .unwrap_or_default()
}

/// 生效 Controller 地址：
/// - 环境变量 `MESHLINK_CONTROLLER_URL` 最高优先级（测试/运维显式覆盖）；
/// - 否则读 UI 配置：`local` 模式 → 单一默认；`remote` 模式 → 已保存地址；
/// - 无配置（含旧配置仅 controller_url 无 mode）→ 按已有地址处理；完全无地址 → None（未配置）。
fn effective_controller_url() -> Option<String> {
    if let Ok(url) = std::env::var("MESHLINK_CONTROLLER_URL") {
        let url = url.trim().to_string();
        if !url.is_empty() {
            return Some(url);
        }
    }
    let cfg = load_ui_config().ok()?;
    let mode = cfg.get("controller_mode").and_then(|x| x.as_str()).unwrap_or("");
    let saved = cfg.get("controller_url").and_then(|x| x.as_str()).unwrap_or("").trim().to_string();
    match mode {
        "local" => Some(DEFAULT_CONTROLLER_URL.to_string()),
        "remote" if !saved.is_empty() => Some(saved),
        // 旧配置：只有 controller_url、无 controller_mode → 按 remote 处理（不自动拉起本机）。
        "" if !saved.is_empty() => Some(saved),
        _ => None, // 未配置 Controller
    }
}

/// 是否 DEV Controller（http + localhost/127.0.0.1）——此类才允许本进程拉起。
fn is_dev_controller(url: &str) -> bool {
    let Some(rest) = url.trim_end_matches('/').split_once("://") else {
        return false;
    };
    let (scheme, rest) = rest;
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    let host = rest.split(['/', ':']).next().unwrap_or("").to_ascii_lowercase();
    host == "localhost" || host == "127.0.0.1"
}

/// healthz 探测（复用 controller-client 白名单与请求路径；短超时）。
fn controller_healthy(url: &str) -> bool {
    let Ok(client) = controller_client::Client::new(url) else {
        return false;
    };
    client.healthz().is_ok()
}

/// 拉起 DEV controller.exe（无参 → 默认监听 127.0.0.1:18080；所有权记录到 runtime）。
fn spawn_dev_controller(state: &IpcState) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("exe 路径失败：{e}"))?;
    let dir = exe.parent().ok_or("exe 目录解析失败")?;
    let controller = dir.join("controller.exe");
    if !controller.exists() {
        // 未随包携带时（如纯 dev 环境）不阻断：Agent 会以 CONTROLLER_UNREACHABLE 呈现。
        eprintln!("[MeshLink] 未找到 DEV controller.exe（{}），跳过自动拉起", controller.display());
        return Ok(());
    }
    let log_path = state
        .supervisor
        .runtime
        .dir
        .join("controller.log");
    let _ = state.supervisor.runtime.ensure();
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map(Stdio::from)
        .unwrap_or(Stdio::null());
    let mut cmd = StdCommand::new(&controller);
    cmd.stdout(Stdio::null()).stderr(stderr);
    let child = state
        .supervisor
        .spawn_managed("controller", "controller.exe", &mut cmd)
        .map_err(|e| format!("DEV controller 启动失败：{e}"))?;
    *state.controller.lock().unwrap() = Some(child);

    // 等待 healthz 就绪（最多 ~10s；controller 无参启动很快）。
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        // 本机 Controller 模式：地址固定为单一默认（DEFAULT_CONTROLLER_URL）。
        if controller_healthy(DEFAULT_CONTROLLER_URL) {
            return Ok(());
        }
        if std::time::Instant::now() > deadline {
            return Err("DEV controller 启动超时（healthz 未就绪）".into());
        }
        std::thread::sleep(Duration::from_millis(300));
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
        let log_path = state.supervisor.runtime.dir.join("supernode.log");
        let _ = state.supervisor.runtime.ensure();
        let stderr = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .map(Stdio::from)
            .unwrap_or(Stdio::null());
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

/// 返回全局唯一默认 Controller 地址（单一 Default，源自 mesh-ipc）。
/// 设置页无已保存配置时用它回填输入框——JS 不再各自硬编码。
#[tauri::command]
pub fn get_controller_default() -> Result<String, String> {
    Ok(DEFAULT_CONTROLLER_URL.to_string())
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
/// 双机架构调整：显式记录模式 `local`（本机 Controller，MeshLink 负责拉起）或
/// `remote`（已有 Controller 地址，绝不自动拉起本机）。仅允许合法地址
/// （生产 HTTPS / DEV localhost / RFC1918 私网）；公网明文 HTTP 拒绝。
#[tauri::command]
pub fn save_controller_config(mode: String, url: String) -> Result<serde_json::Value, String> {
    let mode = mode.trim().to_string();
    if mode != "local" && mode != "remote" {
        return Err("Controller 模式必须是 local（本机）或 remote（已有地址）。".into());
    }
    let mut cfg = serde_json::json!({ "controller_mode": mode });
    if mode == "remote" {
        let url = url.trim().trim_end_matches('/').to_string();
        if url.is_empty() {
            return Err("请输入已有 Controller 地址。".into());
        }
        validate_controller_url(&url).map_err(|e| e)?;
        cfg["controller_url"] = serde_json::json!(url);
    } else {
        // local 模式：地址固定为单一默认，不落盘用户地址（避免与远程地址混淆）。
        cfg["controller_url"] = serde_json::json!(DEFAULT_CONTROLLER_URL);
    }
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

/// 读取当前 Controller 配置（模式 + 地址 + 生效地址 + 是否已配置）。
#[tauri::command]
pub fn get_controller_config() -> Result<serde_json::Value, String> {
    let cfg = load_ui_config().ok().unwrap_or_else(|| serde_json::json!({}));
    let mode = cfg.get("controller_mode").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let url = cfg.get("controller_url").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let effective = effective_controller_url().unwrap_or_default();
    Ok(serde_json::json!({
        "configured": !effective.is_empty(),
        "mode": mode,
        "controller_url": url,
        "effective_url": effective,
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

    // Agent 日志落 data_dir（无控制台窗口时的唯一诊断来源）。
    let log_path = std::path::Path::new(&data_dir).join("agent.log");
    let _ = std::fs::create_dir_all(&data_dir);
    let stderr = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map(Stdio::from)
        .unwrap_or(Stdio::null());

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
