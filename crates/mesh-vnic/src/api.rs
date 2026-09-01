//! Wintun DLL 动态加载与符号解析（M0-3 要求三/五/十二）。
//!
//! 安全加载策略（DLL Hijacking 防护）：
//! - `LoadLibraryExW("wintun.dll", NULL, SEARCH_APPLICATION_DIR | SEARCH_SYSTEM32)`
//! - 搜索范围仅限：应用程序目录（exe 所在目录）与 System32
//! - 禁止：当前工作目录 / PATH / 用户目录 —— 放在 CWD 的伪造 wintun.dll 永远不会被加载
//!
//! Logger 桥接（要求十二）：WINTUN 日志回调经进程级静态桥接转发到 `tracing`，
//! 回调不持有任何 Rust 对象指针，DLL 释放顺序与 logger 无耦合。
//! 官方允许回调从任意线程并发调用 —— 本回调只使用 `tracing`（线程安全）与原子量。

use crate::error::{OsError, VnicError};
use std::ffi::c_void;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::Level;

// ---------------------------------------------------------------------------
// Windows 基础 FFI（仅本 crate 需要的最小集合，全部系统导出、ABI 稳定）
// ---------------------------------------------------------------------------

pub(crate) type Handle = *mut c_void;
pub(crate) const INVALID_HANDLE_VALUE: Handle = -1isize as Handle;
pub(crate) const INFINITE: u32 = u32::MAX;
pub(crate) const WAIT_OBJECT_0: u32 = 0;
pub(crate) const WAIT_TIMEOUT: u32 = 258;
pub(crate) const WAIT_FAILED: u32 = u32::MAX - 1;

pub(crate) const ERROR_SUCCESS: OsError = 0;
pub(crate) const ERROR_ALREADY_EXISTS: OsError = 183;
pub(crate) const ERROR_BUFFER_OVERFLOW: OsError = 34;
pub(crate) const ERROR_NO_MORE_ITEMS: OsError = 259;
pub(crate) const ERROR_ACCESS_DENIED: OsError = 5;
pub(crate) const ERROR_INVALID_PARAMETER: OsError = 87;
pub(crate) const ERROR_NOT_FOUND: OsError = 1168;
/// ERROR_BAD_EXE_FORMAT：DLL 架构与进程不符
pub(crate) const ERROR_BAD_EXE_FORMAT: OsError = 193;
/// WAIT_ABANDONED：持有 Mutex 的进程未 Release 即退出（Windows 自动释放 Mutex，
/// 等待方得到该值 → 我们判定"前 Owner 崩溃，本 Owner 成功接管，但 Adapter 可能需重建"）。
pub(crate) const WAIT_ABANDONED: u32 = 0x0000_0080;
/// Mutex 立即尝试获取（0 ms 超时），避免 B 进程长时间等待 A 正常持锁。
pub(crate) const WAIT_MUTEX_IMMEDIATE: u32 = 0;

pub(crate) mod win {
    use super::*;

    pub(crate) const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
    pub(crate) const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

    #[link(name = "kernel32")]
    extern "system" {
        pub(crate) fn LoadLibraryExW(lp_lib_file_name: *const u16, h_file: Handle, dw_flags: u32) -> Handle;
        pub(crate) fn FreeLibrary(h_lib_module: Handle) -> i32;
        pub(crate) fn GetProcAddress(h_module: Handle, lp_proc_name: *const u8) -> *mut c_void;
        pub(crate) fn GetModuleFileNameW(h_module: Handle, lp_filename: *mut u16, n_size: u32) -> u32;
        pub(crate) fn GetLastError() -> OsError;
        pub(crate) fn CreateEventW(lp_event_attributes: *const c_void, b_manual_reset: i32, b_initial_state: i32, lp_name: *const u16) -> Handle;
        pub(crate) fn SetEvent(h_event: Handle) -> i32;
        pub(crate) fn WaitForMultipleObjects(n_count: u32, lp_handles: *const Handle, b_wait_all: i32, dw_milliseconds: u32) -> u32;
        pub(crate) fn WaitForSingleObject(h_handle: Handle, dw_milliseconds: u32) -> u32;
        pub(crate) fn CloseHandle(h_object: Handle) -> i32;
        pub(crate) fn GetCurrentProcess() -> Handle;
        pub(crate) fn GetProcessHandleCount(h_process: Handle, pdw_handle_count: *mut u32) -> i32;
        pub(crate) fn K32GetProcessMemoryInfo(
            h_process: Handle,
            ppsmem_counters: *mut ProcessMemoryCounters,
            cb: u32,
        ) -> i32;
        pub(crate) fn CreateMutexW(lp_mutex_attributes: *const c_void, b_initial_owner: i32, lp_name: *const u16) -> Handle;
        pub(crate) fn OpenMutexW(dw_desired_access: u32, b_inherit_handle: i32, lp_name: *const u16) -> Handle;
        pub(crate) fn ReleaseMutex(h_mutex: Handle) -> i32;
        pub(crate) fn LocalFree(h_mem: Handle) -> Handle;
    }

    // advapi32：SDDL 字符串 → SECURITY_DESCRIPTOR（M0-3.1-1 显式 DACL）
    #[link(name = "advapi32")]
    extern "system" {
        pub(crate) fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            string_sd: *const u16,
            sddl_revision: u32,
            security_descriptor: *mut *mut c_void,
            security_descriptor_size: *mut u32,
        ) -> i32;
    }

    // -----------------------------------------------------------------------
    // Named Mutex 安全属性（M0-3.1-1a 强制系统级单 Owner + 防普通用户占锁）
    // -----------------------------------------------------------------------

    /// MUTEX_ALL_ACCESS 我们不使用，按最小权限原则只申请需要的位。
    pub(crate) const MUTEX_MODIFY_STATE: u32 = 0x0001;
    pub(crate) const SYNCHRONIZE: u32 = 0x0010_0000;
    pub(crate) const READ_CONTROL: u32 = 0x0002_0000;
    /// 打开 Mutex 最小权限：SYNCHRONIZE（WaitForSingleObject 需要）+ READ_CONTROL。
    /// ReleaseMutex 只需 MUTEX_MODIFY_STATE；合并一起申请。
    pub(crate) const MUTEX_OPEN_DESIRED: u32 = MUTEX_MODIFY_STATE | SYNCHRONIZE | READ_CONTROL;

    /// SDDL_REVISION_1（sddl.h）。
    pub(crate) const SDDL_REVISION_1: u32 = 1;
    /// MeshLink VNIC 互斥体的**显式** Protected DACL（M0-3.1-1a，不依赖默认 Token DACL）：
    ///
    /// - `D:` DACL；`P` Protected（不继承父对象 ACE）
    /// - `(A;;GA;;;SY)`  LocalSystem        = Generic All（完全控制 + 获取）
    /// - `(A;;GA;;;BA)`  BUILTIN\Administrators = Generic All
    ///
    /// 除此以外**任何**账户（包括同用户的非提权进程、Authenticated Users、
    /// CREATOR OWNER 之外的普通管理员组之外账户）均无任何访问位：
    /// Create/Open/Wait 全部 ERROR_ACCESS_DENIED。
    ///
    /// 注：Global\ 命名空间对 Mutex 的创建**不需要** SeCreateGlobalPrivilege
    /// （该 privilege 只约束 file-mapping/section、symbolic-link 等特定对象类型），
    /// 因此普通用户理论上可以"创建"同名对象，但拿不到任何访问权 → 无法抢占、
    /// 无法打开获取、无法长期占有 —— 也不能通过默认 DACL 授权（本 SD 为显式
    /// Protected DACL，与创建者 Token 的默认 DACL 无关）。
    pub(crate) const MUTEX_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";

    /// SECURITY_ATTRIBUTES（winbase.h，ABI 稳定）：nLength = sizeof(SECURITY_ATTRIBUTES)。
    /// 本 crate 总是携带显式 SecurityDescriptor（MUTEX_SDDL 转换产物），禁止 NULL SD。
    #[repr(C)]
    pub(crate) struct SecurityAttributes {
        pub n_length: u32,
        pub lp_security_descriptor: *mut c_void,
        pub b_inherit_handle: i32,
    }

    /// 创建命名互斥体（Global\\ 前缀 = 跨所有终端服务会话系统范围），
    /// 携带 [`MUTEX_SDDL`] 显式 Security Descriptor。
    /// 返回 (mutex_handle, created_new: bool)；created_new=false 表示同名互斥体已存在
    /// （本次只是打开——注意 CreateMutexW 即使存在也返回 handle，LastError=183；
    /// 注意：对象存在 ≠ 对象被持有，ownership 由后续 WaitForSingleObject 判定）。
    /// 失败返回 NULL，调用方必须 GetLastError（普通用户场景 = ERROR_ACCESS_DENIED）。
    pub(crate) unsafe fn create_named_mutex_global(name_wide: &[u16]) -> (Handle, bool) {
        let sddl_w = str_to_wide(MUTEX_SDDL);
        let mut sd: *mut c_void = std::ptr::null_mut();
        let ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        );
        if ok == 0 || sd.is_null() {
            // SDDL 转换失败（不可能发生：常量串由编译期校验）——按创建失败处理
            return (std::ptr::null_mut(), false);
        }
        let sa = SecurityAttributes {
            n_length: std::mem::size_of::<SecurityAttributes>() as u32,
            lp_security_descriptor: sd,
            b_inherit_handle: 0,
        };
        let h = CreateMutexW(
            &sa as *const SecurityAttributes as *const c_void,
            0, // 不立即占有：创建成功后用 WaitForSingleObject 显式请求
            name_wide.as_ptr(),
        );
        // SD 仅在 Create 调用期间被引用；返回后立即释放本地分配。
        LocalFree(sd);
        let created = if h.is_null() || h == INVALID_HANDLE_VALUE {
            false
        } else {
            GetLastError() != ERROR_ALREADY_EXISTS
        };
        (h, created)
    }

    /// PROCESS_MEMORY_COUNTERS（psapi.h，ABI 稳定）。
    #[repr(C)]
    pub(crate) struct ProcessMemoryCounters {
        pub cb: u32,
        pub page_fault_count: u32,
        pub peak_working_set_size: usize,
        pub working_set_size: usize,
        pub quota_peak_paged_pool_usage: usize,
        pub quota_paged_pool_usage: usize,
        pub quota_peak_non_paged_pool_usage: usize,
        pub quota_non_paged_pool_usage: usize,
        pub pagefile_usage: usize,
        pub peak_pagefile_usage: usize,
    }

    impl ProcessMemoryCounters {
        pub(crate) fn zeroed() -> Self {
            // SAFETY：全零 POD 输入结构，字段随后显式赋值
            unsafe { std::mem::zeroed() }
        }
    }

    /// 进程当前打开的 HANDLE 数（泄漏检查用，M0-3 要求二十三）。
    pub(crate) fn process_handle_count() -> u32 {
        unsafe {
            let mut n: u32 = 0;
            if GetProcessHandleCount(GetCurrentProcess(), &mut n) != 0 { n } else { 0 }
        }
    }

    /// 进程内存占用（Working Set / Private Bytes≈PagefileUsage，要求二十三）。
    pub(crate) fn process_memory_usage() -> (u64, u64) {
        unsafe {
            let mut mc = ProcessMemoryCounters::zeroed();
            mc.cb = std::mem::size_of::<ProcessMemoryCounters>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut mc, mc.cb) != 0 {
                (mc.working_set_size as u64, mc.pagefile_usage as u64)
            } else {
                (0, 0)
            }
        }
    }

    /// 宽字符串 -> Rust String（Wintun logger 消息用）。
    /// 防御：宽字符最多 4096 个（单条日志绝不会更长），避免非 NUL 结尾越界扫描触发 AV。
    pub(crate) unsafe fn wide_to_string(p: *const u16) -> String {
        const MAX: usize = 4096;
        let mut len = 0usize;
        while len < MAX && *p.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(p, len);
        String::from_utf16_lossy(slice)
    }

    /// Rust 字符串 -> NUL 结尾 UTF-16。
    pub(crate) fn str_to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

// ---------------------------------------------------------------------------
// Wintun 常量与类型（对照 third_party/wintun/include/wintun.h 0.14.1）
// ---------------------------------------------------------------------------

/// Wintun Session Ring 容量下限：0x20000（128 KiB）
pub const WINTUN_MIN_RING_CAPACITY: u32 = 0x2_0000;
/// Wintun Session Ring 容量上限：0x4000000（64 MiB）
pub const WINTUN_MAX_RING_CAPACITY: u32 = 0x400_0000;

pub(crate) type WintunAdapterHandle = Handle;
pub(crate) type WintunSessionHandle = Handle;

/// WINTUN_LOG_INFO = 0 / WINTUN_LOG_WARN = 1 / WINTUN_LOG_ERR = 2
const WINTUN_LOG_INFO: i32 = 0;
const WINTUN_LOG_WARN: i32 = 1;
const WINTUN_LOG_ERR: i32 = 2;

/// GUID（对照 winnt.h，ABI 稳定）。M0 默认传 NULL（模式 A）；
/// 模式 B（持久化 GUID）由配置生成，见 ADR/WINTUN_ADAPTER_IDENTITY.md。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// 解析 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" 形式（模式 B 配置来源）。
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('-').collect();
        if parts.len() != 5 {
            return None;
        }
        let h = |t: &str, n: usize| u64::from_str_radix(t, 16).ok().filter(|_| t.len() == n);
        let d1 = u32::try_from(h(parts[0], 8)?).ok()?;
        let d2 = u16::try_from(h(parts[1], 4)?).ok()?;
        let d3 = u16::try_from(h(parts[2], 4)?).ok()?;
        let b = |i: usize| u8::from_str_radix(&parts[3][i..i + 2], 16).ok();
        let b2 = |i: usize| u8::from_str_radix(&parts[4][i..i + 2], 16).ok();
        Some(Self {
            data1: d1,
            data2: d2,
            data3: d3,
            // 标准 UUID 8-4-4-4-12：data4 前 2 字节来自第 4 组(4 hex)，
            // 后 6 字节来自第 5 组(12 hex)
            data4: [
                b(0)?, b(2)?,
                b2(0)?, b2(2)?, b2(4)?, b2(6)?, b2(8)?, b2(10)?,
            ],
        })
    }
}

/// NET_LUID（64 位接口标识，ABI 稳定）。
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetLuid(pub u64);

type LoggerCallback = extern "system" fn(level: i32, timestamp: u64, message: *const u16);

// ---------------------------------------------------------------------------
// 函数表（要求五：13 个 API 全部解析；WintunDeleteDriver 仅留 uninstall 工具，不在正常流程调用）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub(crate) struct WintunFunctions {
    pub create_adapter: unsafe extern "system" fn(*const u16, *const u16, *const Guid, *mut i32) -> WintunAdapterHandle,
    pub open_adapter: unsafe extern "system" fn(*const u16) -> WintunAdapterHandle,
    pub close_adapter: unsafe extern "system" fn(WintunAdapterHandle),
    pub delete_driver: unsafe extern "system" fn(*mut i32) -> i32,
    pub get_adapter_luid: unsafe extern "system" fn(WintunAdapterHandle, *mut NetLuid) -> i32,
    pub get_running_driver_version: unsafe extern "system" fn() -> u32,
    pub set_logger: unsafe extern "system" fn(Option<LoggerCallback>),
    pub start_session: unsafe extern "system" fn(WintunAdapterHandle, u32) -> WintunSessionHandle,
    pub end_session: unsafe extern "system" fn(WintunSessionHandle),
    pub get_read_wait_event: unsafe extern "system" fn(WintunSessionHandle) -> Handle,
    pub receive_packet: unsafe extern "system" fn(WintunSessionHandle, *mut u32) -> *mut u8,
    pub release_receive_packet: unsafe extern "system" fn(WintunSessionHandle, *mut u8),
    pub allocate_send_packet: unsafe extern "system" fn(WintunSessionHandle, u32) -> *mut u8,
    pub send_packet: unsafe extern "system" fn(WintunSessionHandle, *const u8),
}

/// 必需符号在 [`WintunLibrary::resolve`] 中逐个按名解析（见该函数字面量列表）；
/// `WintunDeleteDriver` 属 uninstall/cleanup 工具能力，解析但不在正常运行路径调用。

// ---------------------------------------------------------------------------
// 进程级 logger 静态桥接（要求十二：不持有任何可能被释放的对象）
// ---------------------------------------------------------------------------

static LOGGER_BRIDGED: AtomicBool = AtomicBool::new(false);

extern "system" fn wintun_logger_bridge(level: i32, _timestamp: u64, message: *const u16) {
    // 仅当桥接开启且消息指针非空时转发；不触碰任何 Rust 对象生命周期。
    if !LOGGER_BRIDGED.load(Ordering::Relaxed) || message.is_null() {
        return;
    }
    let msg = unsafe { win::wide_to_string(message) };
    match level {
        WINTUN_LOG_ERR => tracing::error!(target: "wintun", "{msg}"),
        WINTUN_LOG_WARN => tracing::warn!(target: "wintun", "{msg}"),
        // Wintun INFO 较冗长，映射到 DEBUG（要求十二允许 INFO/DEBUG 映射）
        WINTUN_LOG_INFO => tracing::debug!(target: "wintun", "{msg}"),
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// WintunLibrary
// ---------------------------------------------------------------------------

/// 已加载的 wintun.dll 及其函数表。
///
/// 生命周期（要求六）：持有 HMODULE；Drop 时先确保 logger 桥接关闭再 FreeLibrary。
/// 调用方通过 `Arc<WintunLibrary>` 共享 —— Adapter/Session 持有 Arc 引用，
/// 结构上保证"Adapter/Session 存活期间 DLL 绝不释放"。
#[derive(Debug)]
pub struct WintunLibrary {
    module: Handle,
    pub(crate) f: WintunFunctions,
}

// SAFETY：HMODULE 只是 DLL 映射基址；Wintun 全部导出函数线程安全（官方 0.14.1
// 头文件注明各 API 可多线程调用），函数表为不可变 Copy。跨线程共享安全。
unsafe impl Send for WintunLibrary {}
unsafe impl Sync for WintunLibrary {}

impl WintunLibrary {
    /// 从可执行文件所在目录加载（生产路径）。
    pub fn load_default() -> Result<Self, VnicError> {
        let dir = Self::executable_dir();
        Self::load(&dir.join("wintun.dll"))
    }

    /// 按显式路径加载（测试/开发用）。搜索标志固定，拒绝 cwd/PATH 注入。
    pub fn load(path: &Path) -> Result<Self, VnicError> {
        let wide = win::str_to_wide(&path.to_string_lossy());
        let module = unsafe {
            win::LoadLibraryExW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                win::LOAD_LIBRARY_SEARCH_APPLICATION_DIR | win::LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            let os = unsafe { win::GetLastError() };
            let path_s = path.to_string_lossy().into_owned();
            return Err(if os == ERROR_BAD_EXE_FORMAT {
                VnicError::DllArchitectureMismatch { path: path_s, os }
            } else {
                VnicError::DllNotFound { path: path_s, os }
            });
        }

        match Self::resolve(module) {
            Ok(f) => {
                unsafe { (f.set_logger)(Some(wintun_logger_bridge)) };
                LOGGER_BRIDGED.store(true, Ordering::Release);
                tracing::info!(
                    target: "wintun",
                    "wintun.dll 加载成功: {} (驱动版本 0x{:X})",
                    path.display(),
                    unsafe { (f.get_running_driver_version)() }
                );
                Ok(Self { module, f })
            }
            Err(e) => {
                unsafe { win::FreeLibrary(module) };
                Err(e)
            }
        }
    }

    /// 解析全部必需符号；缺失 -> ApiSymbolMissing（验收 17）。
    fn resolve(module: Handle) -> Result<WintunFunctions, VnicError> {
        unsafe fn sym(module: Handle, name: &'static str) -> Result<*mut c_void, VnicError> {
            let c = std::ffi::CString::new(name).unwrap();
            let p = win::GetProcAddress(module, c.as_ptr() as *const u8);
            if p.is_null() {
                Err(VnicError::ApiSymbolMissing { symbol: name, os: win::GetLastError() })
            } else {
                Ok(p)
            }
        }
        // SAFETY：符号经 GetProcAddress 按名解析，签名对照 wintun.h 0.14.1；
        // 架构匹配由 LoadLibraryExW 保证（架构不符根本加载不进来）。
        unsafe {
            let create = sym(module, "WintunCreateAdapter")?;
            let open = sym(module, "WintunOpenAdapter")?;
            let close = sym(module, "WintunCloseAdapter")?;
            let delete = sym(module, "WintunDeleteDriver")?;
            let luid = sym(module, "WintunGetAdapterLUID")?;
            let ver = sym(module, "WintunGetRunningDriverVersion")?;
            let log = sym(module, "WintunSetLogger")?;
            let start = sym(module, "WintunStartSession")?;
            let end = sym(module, "WintunEndSession")?;
            let ev = sym(module, "WintunGetReadWaitEvent")?;
            let rx = sym(module, "WintunReceivePacket")?;
            let rxrel = sym(module, "WintunReleaseReceivePacket")?;
            let alloc = sym(module, "WintunAllocateSendPacket")?;
            let send = sym(module, "WintunSendPacket")?;
            Ok(WintunFunctions {
                create_adapter: std::mem::transmute(create),
                open_adapter: std::mem::transmute(open),
                close_adapter: std::mem::transmute(close),
                delete_driver: std::mem::transmute(delete),
                get_adapter_luid: std::mem::transmute(luid),
                get_running_driver_version: std::mem::transmute(ver),
                set_logger: std::mem::transmute::<*mut c_void, unsafe extern "system" fn(Option<LoggerCallback>)>(log),
                start_session: std::mem::transmute(start),
                end_session: std::mem::transmute(end),
                get_read_wait_event: std::mem::transmute(ev),
                receive_packet: std::mem::transmute(rx),
                release_receive_packet: std::mem::transmute(rxrel),
                allocate_send_packet: std::mem::transmute(alloc),
                send_packet: std::mem::transmute(send),
            })
        }
    }

    /// 可执行文件所在目录（安装器应将 wintun.dll 放在此处）。
    pub fn executable_dir() -> std::path::PathBuf {
        let mut buf = [0u16; 32768];
        let n = unsafe { win::GetModuleFileNameW(std::ptr::null_mut(), buf.as_mut_ptr(), buf.len() as u32) };
        if n == 0 {
            return std::env::current_exe().map(|p| p.parent().map(|d| d.to_path_buf()).unwrap_or_default()).unwrap_or_default();
        }
        let s = String::from_utf16_lossy(&buf[..n as usize]);
        std::path::PathBuf::from(s).parent().map(|d| d.to_path_buf()).unwrap_or_default()
    }

    /// Wintun 驱动版本（0xMMMMmmBB；加载后即可查询，验证是"真 DLL"）。
    pub fn running_driver_version(&self) -> u32 {
        unsafe { (self.f.get_running_driver_version)() }
    }

    /// Ring capacity 启动前校验（要求七：非法直接拒绝，不静默修正）。
    pub fn validate_ring_capacity(capacity: u32) -> Result<(), VnicError> {
        if !capacity.is_power_of_two() || capacity == 0 {
            return Err(VnicError::RingCapacityInvalid { value: capacity, reason: "必须是 2 的幂" });
        }
        if capacity < WINTUN_MIN_RING_CAPACITY {
            return Err(VnicError::RingCapacityInvalid { value: capacity, reason: "低于 WINTUN_MIN_RING_CAPACITY (0x20000)" });
        }
        if capacity > WINTUN_MAX_RING_CAPACITY {
            return Err(VnicError::RingCapacityInvalid { value: capacity, reason: "超过 WINTUN_MAX_RING_CAPACITY (0x4000000)" });
        }
        Ok(())
    }
}

impl Drop for WintunLibrary {
    fn drop(&mut self) {
        // 先关桥接再卸载：FreeLibrary 之后不可能再有回调进入。
        LOGGER_BRIDGED.store(false, Ordering::Release);
        unsafe { win::FreeLibrary(self.module) };
        tracing::debug!(target: "wintun", "wintun.dll 已释放");
    }
}

/// tracing Level 常量引用（避免 unused import 警告；保留说明映射来源）。
const _: Level = Level::DEBUG;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_capacity_validation_rejects_illegal_values() {
        assert!(WintunLibrary::validate_ring_capacity(0x400000).is_ok(), "4 MiB 官方示例值必须合法");
        assert!(WintunLibrary::validate_ring_capacity(WINTUN_MIN_RING_CAPACITY).is_ok());
        assert!(WintunLibrary::validate_ring_capacity(WINTUN_MAX_RING_CAPACITY).is_ok());
        // 非 2 的幂
        let e = WintunLibrary::validate_ring_capacity(0x300000).unwrap_err();
        assert!(matches!(e, VnicError::RingCapacityInvalid { .. }));
        // 0 与过小 / 过大
        assert!(WintunLibrary::validate_ring_capacity(0).is_err());
        assert!(WintunLibrary::validate_ring_capacity(0x10000).is_err(), "低于 MIN 必须拒绝");
        assert!(WintunLibrary::validate_ring_capacity(0x8000000).is_err(), "超过 MAX 必须拒绝");
    }

    #[test]
    fn missing_dll_reports_dll_not_found() {
        // 不存在的绝对路径 -> DllNotFound（绝不从 cwd/PATH 兜底加载）
        let e = WintunLibrary::load(Path::new("Z:\\no_such_dir\\wintun.dll")).unwrap_err();
        assert!(matches!(e, VnicError::DllNotFound { .. }), "实际: {e}");
    }

    #[test]
    fn non_wintun_dll_reports_symbol_missing() {
        // kernel32.dll 有导出但没有 WintunCreateAdapter -> ApiSymbolMissing
        let sys32 = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let path = std::path::PathBuf::from(sys32).join("System32\\kernel32.dll");
        let e = WintunLibrary::load(&path).unwrap_err();
        assert!(matches!(e, VnicError::ApiSymbolMissing { .. }), "实际: {e}");
        if let VnicError::ApiSymbolMissing { symbol, .. } = e {
            assert_eq!(symbol, "WintunCreateAdapter");
        }
    }

    #[test]
    fn guid_parse_roundtrip() {
        let g = Guid::parse("deadbabe-cafe-beef-0123-456789abcdef").expect("GUID 解析应成功");
        assert_eq!(g.data1, 0xdeadbabe);
        assert_eq!(g.data2, 0xcafe);
        assert_eq!(g.data3, 0xbeef);
        assert_eq!(&g.data4[..4], &[0x01, 0x23, 0x45, 0x67]);
        assert_eq!(&g.data4[4..], &[0x89, 0xab, 0xcd, 0xef]);
        assert!(Guid::parse("nope").is_none());
        assert!(Guid::parse("deadbabe-cafe-beef-0123-456789abcdeZ").is_none());
    }

    /// 要求三安全测试：CWD 里的伪造 wintun.dll 绝不能被加载。
    ///
    /// 原理：`LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`
    /// 搜索范围仅限应用目录与 System32，明确排除 CWD/PATH/用户目录。
    /// 测试在 CWD 放一个垃圾 "wintun.dll"：
    /// - 若搜索顺序错误（搜到 CWD）→ 解析失败得到 BAD_EXE_FORMAT(193)
    /// - 正确行为 → CWD 不参与搜索：得到 DllNotFound(126)，
    ///   或 System32 恰好有真 DLL 时加载成功
    #[test]
    fn fake_dll_in_cwd_is_never_loaded() {
        let fake = std::env::current_dir().unwrap().join("wintun.dll");
        std::fs::write(&fake, b"this is not a real dll - fake payload").expect("写入伪 DLL");
        // 裸名加载：走 Windows DLL 搜索顺序（受 LOAD_LIBRARY_SEARCH_* 标志约束）
        let result = WintunLibrary::load(Path::new("wintun.dll"));
        let _ = std::fs::remove_file(&fake);
        match result {
            Err(VnicError::DllNotFound { .. }) => {} // 正确：CWD 未被搜索
            Ok(_) => {} // System32 有真 DLL（实机装过 Wintun），加载的不是 CWD 伪 DLL
            Err(VnicError::DllArchitectureMismatch { .. }) => {
                panic!("CWD 伪 DLL 被搜索并加载——DLL Hijacking 防护失效！")
            }
            Err(e) => panic!("意外错误（不应发生）: {e}"),
        }
        // load_default（生产路径）同样不得碰 CWD：应用目录无 DLL 时必须 DllNotFound
        let result = WintunLibrary::load_default();
        match result {
            Err(VnicError::DllNotFound { .. }) => {}
            Ok(_) => panic!("测试环境应用目录不应有 wintun.dll（实机集成测试请跳过本单测）"),
            Err(e) => panic!("意外错误: {e}"),
        }
    }
}
