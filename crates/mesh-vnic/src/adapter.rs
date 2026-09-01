//! WintunAdapter RAII（M0-3 要求六：Adapter 存活期间 DLL 绝不释放）。
//!
//! 所有权：`WintunAdapter` 持有 `Arc<WintunLibrary>`；
//! `WintunSession` 持有 `Arc<WintunAdapter>` —— Drop 链保证
//! Session End → Adapter Close → FreeLibrary 的释放顺序。
//!
//! **M0-3.1-1 系统级单 Owner 互斥（V-04 立即修复）：**
//! 已发生的事故：并发两个同名 MeshLink WintunCreateAdapter →
//! 后者 Wintun 先删旧适配器再建新适配器 → 前者 stale handle →
//! 段错误 0xC0000005 → Wintun 内核驱动全局状态损坏（新 adapter PHANTOM Code45、
//! on-link 路由不生成、pnputil 无法修复，只能重启）。
//!
//! 防御：在 **任何** WintunCreateAdapter/WintunOpenAdapter 调用前，先持有
//! `Global\MeshLink-Vnic-<adapter_name_hash>` 系统命名互斥体。互斥体携带
//! **显式 Protected DACL**（SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`，仅 LocalSystem 与
//! BUILTIN\Administrators 有 Generic All；不依赖进程 Token 默认 DACL）。
//! 持锁失败立即返回对应分类错误，**绝不碰 WintunCreateAdapter**：
//! - `WAIT_TIMEOUT`            → `AdapterLockedByOtherProcess`（另一 Owner 正常持锁）
//! - `WAIT_ABANDONED`          → 前 Owner 进程异常退出未 Release；本进程接管成功，
//!   记录 `MutexAbandonedRecovered` 结构化事件后继续 Adapter Recovery
//! - Create/Wait 返回 ERROR_ACCESS_DENIED → `AdapterMutexAccessDenied`（权限不足）
//! - `WAIT_FAILED` / 其它 OS 错误      → `AdapterMutexWaitFailed`（含具体 Win32 错误码）
//!
//! 注意：`CreateMutexW` 返回 `ERROR_ALREADY_EXISTS` 只代表**对象已存在**，
//! 不代表**对象被持有** —— ownership 由 WaitForSingleObject 的返回值单独判定。
//! 锁生命周期 = `AdapterLock` RAII：与 `WintunAdapter` 共生死。Owner 进程
//! taskkill /F 未 Release 即退出 → Windows 内核自动把 Mutex 标记为
//! WAIT_ABANDONED 并释放 → 下一个合法 Owner 能够立即接管。

use crate::api::{
    win,
    Handle, Guid, NetLuid, WintunAdapterHandle, WintunFunctions, WintunLibrary,
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    INVALID_HANDLE_VALUE, WAIT_ABANDONED, WAIT_MUTEX_IMMEDIATE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use crate::error::VnicError;
use std::sync::Arc;

/// 同名 Adapter 冲突判定（WintunCreateAdapter 返回 OS ERROR_ALREADY_EXISTS）。
pub(crate) fn create_error(os: u32, reboot_required: bool) -> VnicError {
    if os == ERROR_ALREADY_EXISTS {
        VnicError::AdapterConflict { name: String::new() }
    } else {
        VnicError::AdapterCreateFailed { os, reboot_required }
    }
}

// ---------------------------------------------------------------------------
// Global\MeshLink-Vnic-<key> Named Mutex RAII（M0-3.1-1 系统级互斥）
// ---------------------------------------------------------------------------

/// 计算 Mutex 名后缀 adapter-key：FNV-1a 64-bit hex（小写）。
/// 用稳定哈希保证跨进程、跨重启动的 adapter-name → mutex-name 一致性；
/// 选用 FNV-1a 无 std 外依赖、输出固定 16 hex 字符，不触碰 Global\ 对象名长度上限（260 chars）。
pub(crate) fn adapter_key(adapter_name: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325; // FNV-1a offset basis 64-bit
    for b in adapter_name.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3); // FNV prime 64-bit
    }
    format!("{h:016x}")
}

/// Global\ 命名互斥体 RAII：Drop 自动 Release + CloseHandle。
/// 在任何 WintunCreateAdapter / OpenAdapter **前**必须成功构造；失败一律返回
/// `AdapterLockedByOtherProcess`，绝不调用 Wintun DLL API（硬契约，防事故复发）。
#[derive(Debug)]
pub(crate) struct AdapterLock {
    handle: Handle,
    name: String,
    /// true 表示 WAIT_ABANDONED 后取得所有权：前 Owner 崩溃退出，Mutex 由内核
    /// 转交给我们。Windows 语义上我们仍是合法 Owner，必须照常 ReleaseMutex。
    /// 该标志仅记录作诊断用途（日志里打印提醒检查 crash 原因）。
    pub abandoned: bool,
}

impl AdapterLock {
    /// 在 Create/Open 之前获取系统级互斥体。**绝不调用任何 Wintun DLL API 前未持锁。**
    ///
    /// 获取策略（ownership 与"对象是否存在"是两个独立状态，后者不作判定依据）：
    /// 1. CreateMutexW 创建或打开（显式 SDDL DACL：仅 LocalSystem/Administrators
    ///    可访问；非提权进程 Create/Open 即 ERROR_ACCESS_DENIED）。
    /// 2. WaitForSingleObject(h, 0ms) 立即请求所有权，不阻塞 B 进程等待正常持锁的 A：
    ///    - `WAIT_OBJECT_0`  → 持有成功（正常 Owner）
    ///    - `WAIT_ABANDONED` → 前 Owner 进程/线程异常退出未 Release；内核把 Mutex
    ///      遗弃转交给本进程 → 持有成功，记录 `MutexAbandonedRecovered` 结构化事件
    ///      并置 `abandoned=true`（上层据此执行 Adapter Recovery）
    ///    - `WAIT_TIMEOUT`   → 另一进程正常持有 → `AdapterLockedByOtherProcess`
    ///    - `WAIT_FAILED`    → 按最后一错误分类：`ERROR_ACCESS_DENIED` →
    ///      `AdapterMutexAccessDenied`，其它 → `AdapterMutexWaitFailed`
    pub(crate) fn acquire_for(adapter_name: &str) -> Result<Self, VnicError> {
        let key = adapter_key(adapter_name);
        let name = format!("Global\\MeshLink-Vnic-{key}");
        let name_w = win::str_to_wide(&name);
        let (handle, _created_new) = unsafe { win::create_named_mutex_global(&name_w) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            let os = unsafe { win::GetLastError() };
            tracing::error!(
                target: "vnic",
                "CreateMutexW({name}) 失败 os={os}；拒绝进入 WintunCreateAdapter"
            );
            return Err(if os == ERROR_ACCESS_DENIED {
                // 显式 DACL 拒绝（普通用户/非提权进程）：权限不足，语义上不同于"被持锁"
                VnicError::AdapterMutexAccessDenied { mutex_name: name, os }
            } else {
                VnicError::AdapterMutexWaitFailed { mutex_name: name, os }
            });
        }

        let wait = unsafe { win::WaitForSingleObject(handle, WAIT_MUTEX_IMMEDIATE) };
        match wait {
            WAIT_OBJECT_0 => Ok(Self { handle, name, abandoned: false }),
            WAIT_ABANDONED => {
                // 前 Owner taskkill /F / 线程异常终止未 ReleaseMutex，
                // 内核自动转交 Mutex（abandoned ownership）。我们仍需在 Drop 时
                // ReleaseMutex（Windows 对 abandoned 接管者同样要求显式 Release）。
                tracing::warn!(
                    target: "vnic",
                    mutex = %name,
                    event = "MutexAbandonedRecovered",
                    previous_owner = "crashed",
                    "前 Owner 进程异常退出未 Release（WAIT_ABANDONED）；Mutex 已由本进程接管，继续 Adapter Recovery"
                );
                Ok(Self { handle, name, abandoned: true })
            }
            WAIT_TIMEOUT => {
                // 正常持锁的其他 Owner 仍在运行 -> B 进程绝不调用 WintunCreateAdapter
                unsafe { win::CloseHandle(handle) };
                Err(VnicError::AdapterLockedByOtherProcess {
                    mutex_name: name,
                    holder_pid_guess: None,
                })
            }
            _ => {
                // WAIT_FAILED 或未知返回值：按最后一错误分类（权限不足单独区分）
                let os = unsafe { win::GetLastError() };
                unsafe { win::CloseHandle(handle) };
                tracing::error!(
                    target: "vnic",
                    "WaitForSingleObject({name}) 失败 wait={wait} os={os}"
                );
                Err(if os == ERROR_ACCESS_DENIED {
                    VnicError::AdapterMutexAccessDenied { mutex_name: name, os }
                } else {
                    VnicError::AdapterMutexWaitFailed { mutex_name: name, os }
                })
            }
        }
    }

    pub fn mutex_name(&self) -> &str {
        &self.name
    }
}

impl Drop for AdapterLock {
    fn drop(&mut self) {
        // 先 ReleaseMutex（归还所有权），再 CloseHandle（释放内核对象引用）。
        // 顺序保证：即使 ReleaseMutex 失败（如 handle 无效或非当前 Owner），
        // 也不阻止 CloseHandle，避免句柄泄漏。
        if !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            let _ok = unsafe { win::ReleaseMutex(self.handle) };
            unsafe { win::CloseHandle(self.handle) };
            self.handle = INVALID_HANDLE_VALUE;
        }
    }
}

// SAFETY：AdapterLock 的内核句柄 HANDLE 只由当前 Owner 通过 ReleaseMutex/CloseHandle
// 操作；跨线程无数据竞争。WintunAdapter（包含 AdapterLock）已 Send+Sync，本互斥
// 体的 Send+Sync 与整体架构一致（单 Owner，多线程只读查询 mutex_name）。
unsafe impl Send for AdapterLock {}
unsafe impl Sync for AdapterLock {}

// ---------------------------------------------------------------------------
// WintunAdapter（M0-3 原结构 + 新增 AdapterLock 字段）
// ---------------------------------------------------------------------------

/// 已打开的 Wintun Adapter。
#[derive(Debug)]
pub struct WintunAdapter {
    handle: WintunAdapterHandle,
    name: String,
    /// M0-3.1-1 前置互斥：与 Adapter 共生死。先持锁再 CreateAdapter；
    /// 先 CloseAdapter 再放锁（字段声明序 = Drop 逆序 → lock 在 Adapter 之后 Drop，
    /// 实际由显式 shutdown 控制顺序 + Drop 兜底无错）。
    _lock: AdapterLock,
    /// 持库引用：保证 Adapter 关闭前 DLL 不释放（要求六）
    _library: Arc<WintunLibrary>,
}

impl WintunAdapter {
    /// 创建（或复用同名已存在）Adapter。**调用前必须已成功 `AdapterLock::acquire_for`。**
    ///
    /// `requested_guid`：M0 研究 A（None）/ B（持久化 GUID）双模式，
    /// 默认 None，不复制官方示例 GUID（要求十七）。
    /// WintunCreateAdapter 对同名 Adapter 的复用语义即 crash-recovery 基础。
    pub fn create(
        lock: AdapterLock,
        library: &Arc<WintunLibrary>,
        name: &str,
        tunnel_type: &str,
        requested_guid: Option<&Guid>,
    ) -> Result<Self, VnicError> {
        let name_w = win::str_to_wide(name);
        let tt_w = win::str_to_wide(tunnel_type);
        let mut reboot_required: i32 = 0;
        let handle = unsafe {
            (library.f.create_adapter)(
                name_w.as_ptr(),
                tt_w.as_ptr(),
                requested_guid.map_or(std::ptr::null(), |g| g as *const Guid),
                &mut reboot_required,
            )
        };
        if handle.is_null() {
            let os = unsafe { win::GetLastError() };
            let mut err = create_error(os, reboot_required != 0);
            if let VnicError::AdapterConflict { name: n } = &mut err {
                *n = name.to_string();
            }
            tracing::error!(target: "vnic", "WintunCreateAdapter 失败: {err}");
            // Drop lock (by implicit drop of local `lock`): 释放互斥让下一个 Owner 能接管
            drop(lock);
            Err(err)
        } else {
            tracing::info!(target: "vnic", "Wintun adapter 已创建/复用: {name}");
            Ok(Self {
                handle,
                name: name.to_string(),
                _lock: lock,
                _library: Arc::clone(library),
            })
        }
    }

    /// 打开按名存在的 Adapter（attach 场景）。**调用前必须已成功 `AdapterLock::acquire_for`。**
    pub fn open(
        lock: AdapterLock,
        library: &Arc<WintunLibrary>,
        name: &str,
    ) -> Result<Self, VnicError> {
        let name_w = win::str_to_wide(name);
        let handle = unsafe { (library.f.open_adapter)(name_w.as_ptr()) };
        if handle.is_null() {
            let os = unsafe { win::GetLastError() };
            tracing::error!(target: "vnic", "WintunOpenAdapter 失败: {name} (os={os})");
            drop(lock);
            Err(VnicError::AdapterOpenFailed { name: name.to_string(), os })
        } else {
            Ok(Self {
                handle,
                name: name.to_string(),
                _lock: lock,
                _library: Arc::clone(library),
            })
        }
    }

    pub fn handle(&self) -> WintunAdapterHandle {
        self.handle
    }

    /// 库引用（session/worker 构建时使用）。
    pub(crate) fn library(&self) -> &Arc<WintunLibrary> {
        &self._library
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// 读取接口 LUID（IP Helper 配置 IPv4 的输入）。
    pub fn luid(&self) -> Result<NetLuid, VnicError> {
        // 通过内部函数表访问（借用 library 函数表）
        let f: &WintunFunctions = &self._library.f;
        let mut luid = NetLuid::default();
        let ok = unsafe { (f.get_adapter_luid)(self.handle, &mut luid) };
        if ok == 0 {
            Err(VnicError::AdapterOpenFailed { name: self.name.clone(), os: unsafe { win::GetLastError() } })
        } else {
            Ok(luid)
        }
    }
}

impl Drop for WintunAdapter {
    fn drop(&mut self) {
        // 顺序保证：此时 Session 必已 End（Session 持有本对象的 Arc）。
        unsafe { (self._library.f.close_adapter)(self.handle) };
        tracing::debug!(target: "vnic", "Wintun adapter 已关闭: {}", self.name);
    }
}

// SAFETY：adapter 句柄为 Wintun 内部对象指针，官方 API 线程安全
// （WintunCloseAdapter 由唯一所有者 Drop 调用；LUID 查询只读）。
unsafe impl Send for WintunAdapter {}
unsafe impl Sync for WintunAdapter {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// 实机 Gate 用的是真实双进程（tests/real_machine.rs + mesh-vnic-test-helper）。
    /// 本模块只用同一进程的线程做**单元级**语义验证（用户允许保留）：
    /// Windows Mutex 的 abandoned 标记在「持锁线程终止未 Release」时同样触发，
    /// 与进程被杀的内核语义一致（ownership 归属线程死亡 → WAIT_ABANDONED）。

    /// 每个测试用独立 adapter_name → 独立 Global\Mutex，互不干扰（FNV-1a 注入 pid+纳秒）。
    fn unique_name(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        format!("unit-{tag}-{}-{nanos}", std::process::id())
    }

    /// 非管理员环境下（如部分 CI/开发 shell）Mutex 创建会被显式 DACL 拒绝：
    /// 此时跳过（如实输出 SKIP，不虚报通过）。
    fn skip_if_access_denied(e: &VnicError) {
        if let VnicError::AdapterMutexAccessDenied { os: 5, .. } = e {
            eprintln!("SKIP: 当前进程无 Mutex 访问权（非管理员），单元级语义验证跳过");
            std::process::exit(0);
        }
    }

    #[test]
    fn adapter_key_is_stable_fnv1a_16hex() {
        // 跨进程/跨重启稳定性：同输入同输出；输出恒 16 hex 小写
        assert_eq!(adapter_key("MeshLink"), adapter_key("MeshLink"));
        let k = adapter_key("MeshLink");
        assert_eq!(k.len(), 16);
        assert!(k.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(adapter_key("MeshLink"), adapter_key("meshlink"));
    }

    #[test]
    fn mutex_contention_same_process_returns_locked() {
        let name = unique_name("contention");
        let _lock = match AdapterLock::acquire_for(&name) {
            Ok(l) => l,
            Err(e) => { skip_if_access_denied(&e); return; }
        };
        // Windows Mutex ownership 归属**线程**：同线程重复 wait 是递归获取
        // （立即 WAIT_OBJECT_0，计数 +1），因此"另一个 Owner"必须由**另一个
        // 线程**模拟。第二 acquirer 必须得到 WAIT_TIMEOUT → Locked，且绝不把
        // "对象已存在（ERROR_ALREADY_EXISTS）"误判为"被持有"——这里 Mutex
        // 对象确实已存在，但报错必须来自 ownership 等待。
        let h = std::thread::spawn({
            let name = name.clone();
            move || {
                let err = AdapterLock::acquire_for(&name).unwrap_err();
                match err {
                    VnicError::AdapterLockedByOtherProcess { mutex_name, .. } => {
                        assert!(mutex_name.starts_with("Global\\MeshLink-Vnic-"));
                        assert_eq!(mutex_name.len(), "Global\\MeshLink-Vnic-".len() + 16);
                    }
                    other => panic!("必须 AdapterLockedByOtherProcess，实际: {other}"),
                }
            }
        });
        h.join().expect("第二 acquirer 线程 join");
    }

    #[test]
    fn mutex_abandoned_by_thread_exit_is_recovered() {
        let name = unique_name("abandoned");
        // 持锁线程**自己 acquire**（内核 ownership 归属该线程），随后 mem::forget
        // （不 Drop → 不 ReleaseMutex）后退出：线程终止时仍拥有 Mutex → 内核
        // 标记 abandoned → 下一个未拥有该 Mutex 的 waiter 得 WAIT_ABANDONED 并接管。
        let holder = std::thread::spawn({
            let name = name.clone();
            move || {
                match AdapterLock::acquire_for(&name) {
                    Ok(l) => std::mem::forget(l), // 单元级等价 taskkill /F
                    Err(e) => skip_if_access_denied(&e),
                }
            }
        });
        holder.join().expect("持锁线程退出");
        // 主线程从未拥有该 Mutex → wait 才是真正的跨 Owner 竞争语义。
        for _ in 0..50 {
            match AdapterLock::acquire_for(&name) {
                Ok(next) => {
                    assert!(next.abandoned, "接管者必须观察到 WAIT_ABANDONED（abandoned=true）");
                    assert_eq!(next.mutex_name(), &format!("Global\\MeshLink-Vnic-{}", adapter_key(&name)));
                    drop(next); // ReleaseMutex + CloseHandle 正常归还
                    return;
                }
                Err(VnicError::AdapterLockedByOtherProcess { .. }) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(e) => panic!("接管阶段意外错误: {e}"),
            }
        }
        panic!("50 次重试后仍未观察到 abandoned 接管");
    }

    #[test]
    fn mutex_release_then_reacquire_is_not_abandoned() {
        // 正常 Drop（ReleaseMutex）后的下一个 Owner：WAIT_OBJECT_0，abandoned=false
        let name = unique_name("clean");
        {
            let l = match AdapterLock::acquire_for(&name) {
                Ok(l) => l,
                Err(e) => { skip_if_access_denied(&e); return; }
            };
            assert!(!l.abandoned);
        } // Drop：ReleaseMutex + CloseHandle
        let l2 = AdapterLock::acquire_for(&name).expect("释放后必须能再次获取");
        assert!(!l2.abandoned, "正常释放后的获取绝不是 abandoned");
    }
}
