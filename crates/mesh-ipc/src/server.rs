//! Named Pipe 服务端（UI ↔ MeshAgentService 本地 IPC）。
//!
//! Windows FFI（raw 声明，与 secure-store/acl.rs 同风格）：
//! - `CreateNamedPipeW` 携带**显式 SECURITY_ATTRIBUTES**（DACL = 当前用户 +
//!   SYSTEM，GENERIC_READ|GENERIC_WRITE）——不依赖默认管道 DACL（默认会给
//!   Everyone 读权限，用户规格四明确禁止低权限进程读取事件/下发命令）；
//! - BYTE 模式 + 每实例线程：ConnectNamedPipe 阻塞等连接，断开后
//!   DisconnectNamedPipe 复用实例；
//! - 读侧用 PeekNamedPipe 轮询（5ms）：stop 时线程可退出，无悬挂阻塞 IO；
//! - 事件广播：共享 `Vec<Sender<Vec<u8>>>` 注册表，死端自动清理。
//!
//! 帧格式：JSON Lines（见 `proto` 模块）。

#![allow(non_snake_case, non_camel_case_types)]

use crate::proto::{decode_line, encode_line, Event, Request, Response};
use mesh_common::{ErrorCode, MeshError};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::raw::{c_int, c_void};
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

// ---- Win32 常量 ----
type HANDLE = *mut c_void;
type BOOL = c_int;
type PCWSTR = *const u16;
type PSID = *const c_void;

const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const PIPE_TYPE_BYTE: u32 = 0;
const PIPE_READMODE_BYTE: u32 = 0;
const PIPE_WAIT: u32 = 0;
const PIPE_UNLIMITED_INSTANCES: u32 = 0xFF;
const ERROR_PIPE_CONNECTED: u32 = 536;
const INVALID_HANDLE_VALUE: isize = -1;

// 显式 DACL（安全描述符）常量
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const ACL_REVISION: u32 = 2;
const ACL_BUFFER_LEN: usize = 512;
const TOKEN_QUERY: u32 = 0x8;
const TOKEN_USER: u32 = 1;
const SECURITY_DESCRIPTOR_MIN_LEN: usize = 64;
/// 管道对象访问位（FILE_GENERIC 读写的具体位——CreateNamedPipeW 的 SD 校验
/// 拒绝纯 GENERIC 位掩码，ERROR_INVALID_ACL(1336)；展开成 specific 位通过）。
const PIPE_ACCESS_ALL: u32 = 0x001F_01FF;

#[repr(C)]
struct SecurityAttributes {
    nLength: u32,
    lpSecurityDescriptor: *mut c_void,
    bInheritHandle: BOOL,
}

extern "system" {
    // kernel32
    fn CreateNamedPipeW(
        lpName: PCWSTR,
        dwOpenMode: u32,
        dwPipeMode: u32,
        nMaxInstances: u32,
        nOutBufferSize: u32,
        nInBufferSize: u32,
        nDefaultTimeOut: u32,
        lpSecurityAttributes: *const SecurityAttributes,
    ) -> HANDLE;
    fn ConnectNamedPipe(hNamedPipe: HANDLE, lpOverlapped: *mut c_void) -> BOOL;
    fn DisconnectNamedPipe(hNamedPipe: HANDLE) -> BOOL;
    fn ReadFile(hFile: HANDLE, lpBuffer: *mut u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: *mut u32, lpOverlapped: *mut c_void) -> BOOL;
    fn WriteFile(hFile: HANDLE, lpBuffer: *const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: *mut u32, lpOverlapped: *mut c_void) -> BOOL;
    fn PeekNamedPipe(hNamedPipe: HANDLE, lpBuffer: *mut u8, nBufferSize: u32, lpBytesRead: *mut u32, lpTotalBytesAvail: *mut u32, lpBytesLeftThisMessage: *mut u32) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetCurrentProcess() -> HANDLE;
    fn LocalFree(hMem: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn OpenProcessToken(ProcessHandle: HANDLE, DesiredAccess: u32, TokenHandle: *mut HANDLE) -> c_int;
    fn GetTokenInformation(TokenHandle: HANDLE, TokenInformationClass: u32, TokenInformation: *mut c_void, TokenInformationLength: u32, ReturnLength: *mut u32) -> c_int;
    fn InitializeAcl(pAcl: *mut u8, nAclLength: u32, dwAclRevision: u32) -> c_int;
    fn AddAccessAllowedAce(pAcl: *mut u8, dwAceRevision: u32, AccessMask: u32, pSid: PSID) -> c_int;
    fn InitializeSecurityDescriptor(pSecurityDescriptor: *mut c_void, dwRevision: u32) -> c_int;
    fn SetSecurityDescriptorDacl(pSecurityDescriptor: *mut c_void, bDaclPresent: BOOL, pDacl: *const c_void, bDaclDefaulted: BOOL) -> c_int;
    fn ConvertStringSidToSidW(StringSid: PCWSTR, pSid: *mut PSID) -> c_int;
}

fn to_wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

extern "system" {
    fn GetLastError() -> u32;
}

// ---- ACL（复用 secure-store 的成熟模式；管道对象用 GENERIC 读写映射） ----

fn current_user_sid() -> Result<Vec<u8>, MeshError> {
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(MeshError::new(ErrorCode::Internal, "OpenProcessToken 失败"));
        }
        let mut needed: u32 = 0;
        GetTokenInformation(token, TOKEN_USER, std::ptr::null_mut(), 0, &mut needed);
        let mut buf = vec![0u8; needed as usize];
        if GetTokenInformation(token, TOKEN_USER, buf.as_mut_ptr() as *mut c_void, needed, &mut needed) == 0 {
            return Err(MeshError::new(ErrorCode::Internal, "GetTokenInformation 失败"));
        }
        let sid_ptr = *(buf.as_ptr() as *const *const u8);
        let sub_count = *sid_ptr.add(1) as usize;
        let sid_len = 8 + sub_count * 4;
        Ok(std::slice::from_raw_parts(sid_ptr, sid_len).to_vec())
    }
}

fn system_sid() -> Result<Vec<u8>, MeshError> {
    unsafe {
        let mut sid: PSID = std::ptr::null();
        let wide = to_wide("S-1-5-18");
        if ConvertStringSidToSidW(wide.as_ptr(), &mut sid) == 0 {
            return Err(MeshError::new(ErrorCode::Internal, "ConvertStringSidToSidW 失败"));
        }
        let sub_count = *(sid as *const u8).add(1) as usize;
        let sid_len = 8 + sub_count * 4;
        let owned = std::slice::from_raw_parts(sid as *const u8, sid_len).to_vec();
        LocalFree(sid as *mut c_void);
        Ok(owned)
    }
}

/// 构建管道显式 SD：DACL = 当前用户 + SYSTEM，无 Everyone（默认 SD 会给
/// Everyone 读——用户规格四禁止）。
///
/// 自引用陷阱：`sd` 内保存 `acl` 的裸指针——**必须在结构体到达最终地址后**
/// 调用 `bind()`；`build()` 只做 ACL/SID（返回值 move 进线程闭包后地址改变，
/// 先绑定的指针悬空 → CreateNamedPipeW ERROR_INVALID_ACL(1336)）。
struct PipeSecurity {
    sd: [u8; SECURITY_DESCRIPTOR_MIN_LEN],
    acl: [u8; ACL_BUFFER_LEN],
    _user_sid: Vec<u8>,
    _sys_sid: Vec<u8>,
}

impl PipeSecurity {
    fn build() -> Result<Self, MeshError> {
        let user_sid = current_user_sid()?;
        let sys_sid = system_sid()?;
        let mut sec = Self { sd: [0u8; SECURITY_DESCRIPTOR_MIN_LEN], acl: [0u8; ACL_BUFFER_LEN], _user_sid: user_sid.clone(), _sys_sid: sys_sid.clone() };
        unsafe {
            if InitializeAcl(sec.acl.as_mut_ptr(), ACL_BUFFER_LEN as u32, ACL_REVISION) == 0 {
                return Err(MeshError::new(ErrorCode::Internal, "InitializeAcl 失败"));
            }
            for sid in [&user_sid, &sys_sid] {
                if AddAccessAllowedAce(sec.acl.as_mut_ptr(), ACL_REVISION, PIPE_ACCESS_ALL, sid.as_ptr() as PSID) == 0 {
                    return Err(MeshError::new(ErrorCode::Internal, "AddAccessAllowedAce 失败"));
                }
            }
        }
        Ok(sec)
    }

    /// 在最终地址上把 DACL 指针写入 SD（此后不得再 move 本结构体）。
    fn bind(&mut self) -> Result<(), MeshError> {
        unsafe {
            if InitializeSecurityDescriptor(self.sd.as_mut_ptr() as *mut c_void, SECURITY_DESCRIPTOR_REVISION) == 0 {
                return Err(MeshError::new(ErrorCode::Internal, "InitializeSecurityDescriptor 失败"));
            }
            if SetSecurityDescriptorDacl(self.sd.as_mut_ptr() as *mut c_void, 1, self.acl.as_ptr() as *const c_void, 0) == 0 {
                return Err(MeshError::new(ErrorCode::Internal, "SetSecurityDescriptorDacl 失败"));
            }
        }
        Ok(())
    }

    fn attributes(&mut self) -> SecurityAttributes {
        SecurityAttributes {
            nLength: std::mem::size_of::<SecurityAttributes>() as u32,
            lpSecurityDescriptor: self.sd.as_mut_ptr() as *mut c_void,
            bInheritHandle: 0,
        }
    }
}

/// 请求处理函数（同步——Agent 侧自行 block_on 其 runtime）。
pub type RequestHandler = Arc<dyn Fn(Request) -> Response + Send + Sync>;

/// 服务端句柄：stop 信号 + 线程汇聚。
pub struct PipeServerHandle {
    stopped: Arc<AtomicBool>,
    threads: Mutex<Vec<JoinHandle<()>>>,
    pipe_name: String,
}

impl PipeServerHandle {
    /// 停止服务。
    ///
    /// accept 线程阻塞在 `ConnectNamedPipe`（无超时），直接 join 会永久死锁——
    /// 先连入哑客户端唤醒全部实例（连接完成 → 线程检查 stopped → 退出并
    /// 关闭实例），再汇聚线程。哑客户端随后丢弃（实例已关，管道随之消失）。
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for _ in 0..INSTANCE_COUNT {
            match crate::client::PipeClient::connect(&self.pipe_name, Duration::from_millis(300)) {
                Ok(c) => drop(c),
                Err(_) => break, // 管道已不存在（全部实例已退出）
            }
        }
        let threads: Vec<_> = self.threads.lock().unwrap().drain(..).collect();
        for t in threads {
            let _ = t.join();
        }
    }

    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }
}

/// 连接注册表：conn_id → 该连接的写端（事件广播目标）。
type ClientRegistry = Arc<Mutex<HashMap<u64, std::sync::mpsc::Sender<Vec<u8>>>>>;

const POLL_INTERVAL: Duration = Duration::from_millis(5);
const INSTANCE_COUNT: usize = 4;

/// 启动管道服务端。
/// - `pipe_name`：如 `\\.\pipe\MeshLink-Agent`（测试可用随机名）；
/// - `handler`：命令处理；
/// - `events_rx`：Agent → UI 事件源（广播到所有连接）。
pub fn spawn_server(
    pipe_name: &str,
    handler: RequestHandler,
    events_rx: Receiver<Event>,
) -> Result<Arc<PipeServerHandle>, MeshError> {
    if !pipe_name.starts_with(r"\\.\pipe\") {
        return Err(MeshError::new(ErrorCode::Internal, format!("管道名非法: {pipe_name}")));
    }
    let handle = Arc::new(PipeServerHandle {
        stopped: Arc::new(AtomicBool::new(false)),
        threads: Mutex::new(Vec::new()),
        pipe_name: pipe_name.to_string(),
    });
    let registry: ClientRegistry = Arc::new(Mutex::new(HashMap::new()));
    let next_conn_id = Arc::new(AtomicU64::new(1));

    // 事件广播线程
    {
        let registry = registry.clone();
        let stopped = Arc::clone(&handle.stopped);
        let t = std::thread::Builder::new()
            .name("mesh-ipc-broadcast".into())
            .spawn(move || loop {
                if stopped.load(Ordering::Acquire) {
                    return;
                }
                match events_rx.recv_timeout(Duration::from_millis(200)) {
                    Ok(ev) => {
                        let line = encode_line(&ev).expect("事件序列化");
                        let mut dead = Vec::new();
                        {
                            let reg = registry.lock().unwrap();
                            for (id, tx) in reg.iter() {
                                if tx.send(line.clone()).is_err() {
                                    dead.push(*id);
                                }
                            }
                            tracing::info!(target: "gatedbg", event = ?ev, conns = reg.len(), dead = dead.len(), "IPC 广播投递");
                        }
                        if !dead.is_empty() {
                            registry.lock().unwrap().retain(|id, _| !dead.contains(id));
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        tracing::info!(target: "gatedbg", "IPC 广播线程退出：事件源通道关闭");
                        return;
                    }
                }
            })
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("广播线程启动失败: {e}")))?;
        handle.threads.lock().unwrap().push(t);
    }

    // 每实例线程：等连接 → 服务该客户端 → 断开后关闭实例重建
    for i in 0..INSTANCE_COUNT {
        let name = pipe_name.to_string();
        let handler = handler.clone();
        let registry = registry.clone();
        let stopped = Arc::clone(&handle.stopped);
        let next_id = next_conn_id.clone();
        let t = std::thread::Builder::new()
            .name(format!("mesh-ipc-accept-{i}"))
            .spawn(move || {
                let mut sec = match PipeSecurity::build() {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!(error = ?e, "管道安全描述符构建失败");
                        return;
                    }
                };
                // 结构体已在闭包内定居，现在绑定 DACL 指针才有效（见类型注释）。
                if let Err(e) = sec.bind() {
                    tracing::warn!(error = ?e, "管道安全描述符绑定失败");
                    return;
                }
                loop {
                    if stopped.load(Ordering::Acquire) {
                        return;
                    }
                    let wide = to_wide(&name);
                    let attrs = sec.attributes();
                    let pipe = unsafe {
                        CreateNamedPipeW(
                            wide.as_ptr(),
                            PIPE_ACCESS_DUPLEX,
                            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                            PIPE_UNLIMITED_INSTANCES,
                            64 * 1024,
                            64 * 1024,
                            0,
                            &attrs,
                        )
                    };
                    if pipe as isize == INVALID_HANDLE_VALUE {
                        let err = unsafe { GetLastError() };
                        tracing::warn!(pipe = %name, winerror = err, "CreateNamedPipeW 失败");
                        return;
                    }
                    let connected = unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) };
                    if connected == 0 {
                        // 同步管道连接已被预先完成（哑客户端唤醒/竞态）视为成功。
                        let err = unsafe { GetLastError() };
                        if err != ERROR_PIPE_CONNECTED {
                            unsafe { CloseHandle(pipe) };
                            if stopped.load(Ordering::Acquire) {
                                return;
                            }
                            continue;
                        }
                    }
                    if stopped.load(Ordering::Acquire) {
                        unsafe {
                            DisconnectNamedPipe(pipe);
                            CloseHandle(pipe);
                        }
                        return;
                    }
                    serve_connection(pipe, &handler, &registry, &stopped, &next_id);
                    unsafe {
                        // 不 FlushFileBuffers：服务端 flush 会阻塞到客户端读完全部
                        // 缓冲数据（MSDN 语义）——客户端停止读取（如 UI 关闭/测试
                        // 收尾）时永久死锁；DisconnectNamedPipe 本就丢弃未读数据。
                        DisconnectNamedPipe(pipe);
                        CloseHandle(pipe);
                    }
                }
            })
            .expect("spawn accept thread");
        handle.threads.lock().unwrap().push(t);
    }
    Ok(handle)
}

/// 单连接服务：读轮询（本线程）+ 写线程（响应与事件共用写出通道，串行化
/// WriteFile 避免交错）。
fn serve_connection(
    pipe: HANDLE,
    handler: &RequestHandler,
    registry: &ClientRegistry,
    stopped: &Arc<AtomicBool>,
    next_id: &AtomicU64,
) {
    let conn_id = next_id.fetch_add(1, Ordering::Relaxed);
    let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
    registry.lock().unwrap().insert(conn_id, tx_out.clone());

    // 写线程：recv 超时轮询 + stopped 检查（读循环结束后通道 Disconnected
    // 也会退出——两个出口都必需，否则 stop() 永久卡在 join）。
    let writer = {
        let pipe = pipe as usize; // 跨线程裸指针转 usize（JoinHandle 内还原）
        let stopped = Arc::clone(stopped);
        std::thread::Builder::new()
            .name("mesh-ipc-writer".into())
            .spawn(move || {
                let pipe = pipe as HANDLE;
                loop {
                    match rx_out.recv_timeout(Duration::from_millis(200)) {
                        Ok(line) => {
                            if let Err(e) = write_all(pipe, &line) {
                                tracing::info!(target: "gatedbg", error = %e, "IPC writer 写入失败退出");
                                break;
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if stopped.load(Ordering::Acquire) {
                                break;
                            }
                        }
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                            tracing::info!(target: "gatedbg", "IPC writer 退出：输出通道关闭");
                            break;
                        }
                    }
                }
                // 退出路径不 flush：服务端 FlushFileBuffers 阻塞至客户端读完全部
                // 数据——客户端已停止读取时死锁（write_all 后数据已在内核管道
                // 缓冲，对端随时可读，无需 flush）。
            })
            .expect("spawn writer thread")
    };

    // 读循环（本线程）：PeekNamedPipe 轮询
    let mut line_buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if stopped.load(Ordering::Acquire) {
            tracing::info!(target: "gatedbg", conn = conn_id, "IPC 读循环退出：stopped");
            break;
        }
        let mut avail: u32 = 0;
        let ok = unsafe {
            PeekNamedPipe(pipe, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut())
        };
        if ok == 0 {
            let err = unsafe { GetLastError() };
            tracing::info!(target: "gatedbg", conn = conn_id, winerror = err, "IPC 读循环退出：PeekNamedPipe 失败");
            break; // 客户端断开（BROKEN_PIPE/NO_DATA）
        }
        if avail == 0 {
            std::thread::sleep(POLL_INTERVAL);
            continue;
        }
        let want = avail.min(chunk.len() as u32);
        let mut got: u32 = 0;
        let ok = unsafe { ReadFile(pipe, chunk.as_mut_ptr(), want, &mut got, std::ptr::null_mut()) };
        if ok == 0 || got == 0 {
            let err = unsafe { GetLastError() };
            tracing::info!(target: "gatedbg", conn = conn_id, winerror = err, got, "IPC 读循环退出：ReadFile 失败");
            break;
        }
        line_buf.extend_from_slice(&chunk[..got as usize]);
        // 逐行处理
        loop {
            match decode_line(&line_buf) {
                Err(_) => {
                    let resp = Response {
                        id: 0,
                        ok: false,
                        data: None,
                        error: Some(crate::proto::IpcError::new("IPC_PROTOCOL", "行超长")),
                    };
                    let _ = encode_line(&resp).map(|l| tx_out.send(l));
                    line_buf.clear();
                    break;
                }
                Ok(None) => break,
                Ok(Some((line, used))) => {
                    let line = line.to_vec();
                    line_buf.drain(..used);
                    match serde_json::from_slice::<Request>(&line) {
                        Ok(req) => {
                            // Request id=0 为 RESERVED/INVALID（用户规格协议硬化）：
                            // 合法请求必须经 mesh_ipc::build_request 生成非零递增 id。
                            // 外部构造 id=0 直接拒绝，**不进入** handler / 正常
                            // response correlation。
                            if req.id == 0 {
                                let resp = Response {
                                    id: 0,
                                    ok: false,
                                    data: None,
                                    error: Some(crate::proto::IpcError::new(
                                        "IPC_INVALID_REQUEST_ID",
                                        "Request id 必须为非零（id=0 保留）",
                                    )),
                                };
                                if let Ok(l) = encode_line(&resp) {
                                    if tx_out.send(l).is_err() {
                                        break;
                                    }
                                }
                                continue;
                            }
                            let resp = handler(req);
                            if let Ok(l) = encode_line(&resp) {
                                if tx_out.send(l).is_err() {
                                    break;
                                }
                            }
                        }
                        Err(_) => {
                            let resp = Response {
                                id: 0,
                                ok: false,
                                data: None,
                                error: Some(crate::proto::IpcError::new(
                                    "IPC_PROTOCOL",
                                    "请求解析失败（非 JSON 或未知命令）",
                                )),
                            };
                            if let Ok(l) = encode_line(&resp) {
                                let _ = tx_out.send(l);
                            }
                        }
                    }
                }
            }
        }
    }
    registry.lock().unwrap().remove(&conn_id);
    drop(tx_out);
    let _ = writer.join();
}

fn write_all(pipe: HANDLE, data: &[u8]) -> Result<(), MeshError> {
    let mut off = 0usize;
    while off < data.len() {
        let mut written: u32 = 0;
        let ok = unsafe {
            WriteFile(pipe, data[off..].as_ptr(), (data.len() - off).min(u32::MAX as usize) as u32, &mut written, std::ptr::null_mut())
        };
        if ok == 0 {
            return Err(MeshError::new(ErrorCode::Internal, "管道写入失败"));
        }
        off += written as usize;
    }
    Ok(())
}

// ---- 测试 ----
#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::PipeClient;
    use crate::proto::Command;
    use std::sync::mpsc;

    fn init_test_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();
    }

    fn unique_pipe(tag: &str) -> String {
        format!(
            r"\\.\pipe\meshlink-ipc-test-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u32
        )
    }

    fn echo_handler() -> RequestHandler {
        Arc::new(|req: Request| {
            let data = match &req.command {
                Command::GetStatus => serde_json::json!({"state":"READY"}),
                Command::JoinQuickSession { code } => serde_json::json!({"joined": code}),
                _ => serde_json::Value::Null,
            };
            Response { id: req.id, ok: true, data: Some(data), error: None }
        })
    }

    #[test]
    fn server_client_roundtrip_and_event_broadcast() {
        init_test_tracing();
        let name = unique_pipe("roundtrip");
        let (tx_ev, rx_ev) = mpsc::channel::<Event>();
        let server = spawn_server(&name, echo_handler(), rx_ev).expect("spawn server");

        // 等待实例就绪（CreateNamedPipeW 在线程内完成）
        let mut client = None;
        for _ in 0..100 {
            match PipeClient::connect(&name, Duration::from_secs(2)) {
                Ok(c) => {
                    client = Some(c);
                    break;
                }
                Err(_) => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        let mut client = client.expect("连接超时");

        // 命令往返
        let resp = client.request(&Request { id: 1, command: Command::GetStatus }).expect("req");
        assert!(resp.ok);
        assert_eq!(resp.data.unwrap()["state"], "READY");

        let resp = client
            .request(&Request { id: 2, command: Command::JoinQuickSession { code: "482731".into() } })
            .expect("req2");
        assert_eq!(resp.id, 2);
        assert_eq!(resp.data.unwrap()["joined"], "482731");

        // 事件广播：第二个客户端也要收到（先请求-响应一轮，确保其
        // serve_connection 已把写端注册进广播表——否则存在注册竞态）。
        let mut client2 = PipeClient::connect(&name, Duration::from_secs(2)).expect("client2");
        let resp = client2.request(&Request { id: 3, command: Command::GetStatus }).expect("client2 req");
        assert!(resp.ok);
        tx_ev.send(Event::Punching { track: "B".into() }).expect("send event");
        let got = client.wait_message(Duration::from_secs(3)).expect("事件超时");
        match got {
            crate::proto::ServerMessage::Event(crate::proto::Event::Punching { track }) => assert_eq!(track, "B"),
            other => panic!("应为 Punching 事件: {other:?}"),
        }
        let got2 = client2.wait_message(Duration::from_secs(3)).expect("client2 事件");
        assert!(matches!(got2, crate::proto::ServerMessage::Event(_)));

        server.stop();
    }

    /// 回归：事件先于响应写入管道（服务端事件与响应共用写通道的固有竞态——
    /// Agent 在返回 CancelSession 响应前先发 Disconnected）时，request 不得
    /// 丢弃事件。旧实现 pending 扫描会弹出事件并静默丢弃。
    #[test]
    fn event_written_before_response_is_not_dropped() {
        init_test_tracing();
        let name = unique_pipe("event-race");
        let (tx_ev, rx_ev) = mpsc::channel::<Event>();
        let tx = tx_ev.clone();
        let handler: RequestHandler = Arc::new(move |req: Request| {
            // 先投递事件并延迟响应 → 事件行先于响应行写入管道。
            tx.send(Event::Punching { track: "race".into() }).expect("send");
            std::thread::sleep(Duration::from_millis(100));
            Response { id: req.id, ok: true, data: None, error: None }
        });
        let server = spawn_server(&name, handler, rx_ev).expect("spawn server");
        let mut client = wait_connect(&name);

        let resp = client.request(&Request { id: 9, command: Command::GetStatus }).expect("req");
        assert!(resp.ok);

        // 事件必须在 request 返回后仍可取回（旧实现在此超时丢失）。
        let got = client
            .wait_message(Duration::from_secs(3))
            .expect("事件在等待响应期间被丢弃（pending 扫描回归）");
        match got {
            crate::proto::ServerMessage::Event(crate::proto::Event::Punching { track }) => {
                assert_eq!(track, "race");
            }
            other => panic!("应为 Punching 事件: {other:?}"),
        }
        drop(tx_ev);
        server.stop();
    }

    #[test]
    fn malformed_request_gets_protocol_error() {
        let name = unique_pipe("malformed");
        let (_tx_ev, rx_ev) = mpsc::channel::<Event>();
        let server = spawn_server(&name, echo_handler(), rx_ev).expect("spawn server");
        // 打开原始客户端手写坏行
        let mut client = wait_connect(&name);
        client.write_message(b"not json\n").expect("write");
        // 超时放宽：workspace 并行测试下进程/管道竞争可能使响应稍慢（3s 偶发饿死）。
        let resp = client.wait_message(Duration::from_secs(10)).expect("resp");
        match resp {
            crate::proto::ServerMessage::Response(r) => {
                assert!(!r.ok);
                assert_eq!(r.error.unwrap().code, "IPC_PROTOCOL");
            }
            other => panic!("应为响应: {other:?}"),
        }
        server.stop();
    }

    fn wait_connect(name: &str) -> PipeClient {
        for _ in 0..100 {
            if let Ok(c) = PipeClient::connect(name, Duration::from_secs(2)) {
                return c;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("连接超时");
    }

    /// 对 Windows 命名管道的 accept/write 竞态（偶发 ERROR_BROKEN_PIPE=109）做重连重试。
    fn request_robust(name: &str, client: &mut PipeClient, req: &Request) -> Result<Response, MeshError> {
        for _ in 0..3 {
            match client.request(req) {
                Ok(r) => return Ok(r),
                Err(_) => *client = wait_connect(name),
            }
        }
        client.request(req)
    }

    /// 管道 DACL 收敛验证：恰好 2 个 ACE（当前用户 + SYSTEM）。
    /// （Everyone 读权限被显式排除——默认管道 SD 不满足用户规格四。）
    ///
    /// 按名称查询管道 SD 会返回 ERROR_INVALID_PARAMETER(87)——管道对象只能
    /// 经打开的句柄查询（GetSecurityInfo）。
    #[test]
    fn pipe_dacl_has_exactly_two_aces() {
        init_test_tracing();
        let name = unique_pipe("acl");
        let (_tx_ev, rx_ev) = mpsc::channel::<Event>();
        let server = spawn_server(&name, echo_handler(), rx_ev).expect("spawn server");
        let c = wait_connect(&name);

        extern "system" {
            fn GetSecurityInfo(
                handle: HANDLE,
                ObjectType: u32,
                SecurityInfo: u32,
                ppsidOwner: *mut PSID,
                ppsidGroup: *mut PSID,
                ppDacl: *mut *const c_void,
                ppSacl: *mut *const c_void,
                ppSecurityDescriptor: *mut *mut c_void,
            ) -> u32;
        }
        const SE_KERNEL_OBJECT: u32 = 6; // SE_OBJECT_TYPE：0=UNKNOWN；管道端点句柄按内核对象查询（SE_FILE_OBJECT 返回 87）
        const DACL_SECURITY_INFORMATION: u32 = 0x4;
        unsafe {
            let mut owner: PSID = std::ptr::null();
            let mut group: PSID = std::ptr::null();
            let mut dacl: *const c_void = std::ptr::null();
            let mut sacl: *const c_void = std::ptr::null();
            let mut sd: *mut c_void = std::ptr::null_mut();
            let rc = GetSecurityInfo(
                c.raw_handle() as HANDLE,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                &mut owner,
                &mut group,
                &mut dacl,
                &mut sacl,
                &mut sd,
            );
            assert_eq!(rc, 0, "GetSecurityInfo 失败 (WinError {rc})");
            assert!(!dacl.is_null(), "应存在 DACL");
            let acl = dacl as *const u8;
            let ace_count = u16::from_le_bytes([*acl.add(4), *acl.add(5)]);
            assert_eq!(ace_count, 2, "管道 DACL 应恰好 2 个 ACE（当前用户 + SYSTEM），got {ace_count}");
            if !sd.is_null() {
                LocalFree(sd);
            }
        }
        server.stop();
    }

    /// 停止后新请求返回断开（服务优雅退出）。
    #[test]
    fn stop_terminates_serving() {
        let name = unique_pipe("stop");
        let (tx_ev, rx_ev) = mpsc::channel::<Event>();
        let server = spawn_server(&name, echo_handler(), rx_ev).expect("spawn server");
        let mut client = wait_connect(&name);
        let resp = client.request(&Request { id: 5, command: Command::GetStatus }).expect("req");
        assert!(resp.ok);
        server.stop();
        // 停止后：读侧退出 → 连接关闭
        assert!(client.request(&Request { id: 6, command: Command::GetStatus }).is_err());
        drop(tx_ev);
    }

    /// Request id=0 为 RESERVED/INVALID：Agent 直接回 IPC_INVALID_REQUEST_ID，
    /// **不进入** handler（不进入正常 response correlation）。
    #[test]
    fn request_id_zero_rejected_before_handler() {
        init_test_tracing();
        let name = unique_pipe("idzero");
        let (tx_ev, rx_ev) = mpsc::channel::<Event>();
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls2 = calls.clone();
        let handler: RequestHandler = Arc::new(move |req: Request| {
            calls2.fetch_add(1, Ordering::Relaxed);
            Response { id: req.id, ok: true, data: None, error: None }
        });
        let server = spawn_server(&name, handler, rx_ev).expect("spawn server");
        let mut client = wait_connect(&name);

        // 合法 id=1 正常通过（Windows 管道在并行测试下有 accept/write 竞态，
        // 偶发 ERROR_BROKEN_PIPE=109 → 重连后重发；写失败时 handler 未执行，幂等）。
        let before = calls.load(Ordering::Relaxed);
        let ok = request_robust(&name, &mut client, &Request { id: 1, command: Command::GetStatus })
            .expect("req");
        assert!(ok.ok, "id=1 应正常处理");
        assert!(calls.load(Ordering::Relaxed) > before, "合法请求应进 handler");

        // id=0 被拒绝且不进 handler。
        let c1 = calls.load(Ordering::Relaxed);
        let resp = request_robust(&name, &mut client, &Request { id: 0, command: Command::GetStatus })
            .expect("req");
        assert!(!resp.ok, "id=0 必须失败");
        let err = resp.error.expect("错误对象");
        assert_eq!(err.code, "IPC_INVALID_REQUEST_ID", "错误码");
        assert!(!err.message.trim().is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), c1, "id=0 不得进入 handler");

        server.stop();
        drop(tx_ev);
    }
}
