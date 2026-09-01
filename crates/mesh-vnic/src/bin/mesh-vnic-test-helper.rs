//! M0-3.1 跨进程互斥验收 helper（真实 Process A / Process B 测试专用）。
//!
//! 背景：同一进程内的线程模拟不能证明跨进程 Mutex 语义（ownership 线程
//! 归属、abandoned 标记、DACL 跨进程评估都发生在真实多进程场景）。
//! 本 helper 与 `tests/real_machine.rs` 配合，构成真正的双 Windows 进程验收。
//!
//! 子命令：
//! ```text
//! hold <adapter_name>           创建 VNIC → READY → 驻留（供父测试 taskkill /F）
//! try-acquire <adapter_name>    尝试创建同名 VNIC，按结果输出并语义化退出
//! recover <adapter_name>        预打开 Mutex → [父测试杀 A] → 接管 abandoned
//!                               Mutex → 恢复 Adapter → RX/TX smoke
//! try-mutex <adapter_name>      仅探测命名 Mutex 可获取性（FFI 直连，不碰 Wintun）
//! ```
//!
//! recover 的预打开（PREOPEN）：Windows 内核对象在最后一个句柄关闭后销毁；
//! Owner 进程被 taskkill 后若无他人持有句柄，下一次 CreateMutexW 得到全新
//! 对象（WAIT_OBJECT_0），永远观察不到 WAIT_ABANDONED。recover 先用
//! OpenMutexW 持有一个保活句柄（真实部署中"后继者已在等待"的经典模式），
//! 再走生产路径 MeshVnic::create —— 此时的 WaitForSingleObject 才能在
//! Owner 死亡时确定性返回 WAIT_ABANDONED。
//!
//! 公共选项：`--out <file>` 把协议行追加写入文件（CreateProcessAsUserW 启动的
//! 非提权子进程没有继承的 stdio 管道时，父进程经文件读取结果）。
//!
//! 退出码（父测试按此断言）：
//! ```text
//! 0 = 成功（acquired / created / recovered）
//! 2 = AdapterLockedByOtherProcess
//! 3 = AdapterMutexAccessDenied
//! 4 = AdapterMutexWaitFailed
//! 5 = 其它错误（stderr 打印细节）
//! 6 = recover 的 RX/TX smoke 失败
//! ```
//!
//! 网段约定（与 tests/real_machine.rs 一致）：
//! - A（hold）用 10.219.177.0/24；
//! - B（try-acquire / recover）用 10.219.178.0/24 —— **同名 adapter**（同一把
//!   Global\Mutex，key 只取决于 adapter_name），但**不同网段**，避免 A 被
//!   taskkill 后遗留 on-link 路由触发 B 的 OverlaySubnetConflict 误报。

use mesh_vnic::{MeshVnic, VnicConfig, VnicError};
use std::io::{BufRead, Write};
use std::net::Ipv4Addr;
use std::process::exit;

const DLL_REL: &str = r"..\..\third_party\wintun\bin\amd64\wintun.dll";

// ---- 退出码（与模块文档一致） ----
const EXIT_OK: i32 = 0;
const EXIT_LOCKED: i32 = 2;
const EXIT_ACCESS_DENIED: i32 = 3;
const EXIT_WAIT_FAILED: i32 = 4;
const EXIT_OTHER: i32 = 5;
const EXIT_SMOKE_FAIL: i32 = 6;

fn dll_path() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("MESH_VNIC_DLL") {
        return std::path::PathBuf::from(p);
    }
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DLL_REL)
}

/// FNV-1a 64-bit —— 与 mesh_vnic::adapter::adapter_key 完全一致（helper 是
/// 独立 bin，无法访问 pub(crate) 项；改动 key 算法时必须同步这里）。
fn fnv1a64(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

fn mutex_name(adapter: &str) -> String {
    format!("Global\\MeshLink-Vnic-{:016x}", fnv1a64(adapter))
}

/// A 用 .177 网段（tests/real_machine.rs 的 TEST_* 常量同款）。
fn config_a(adapter: &str) -> VnicConfig {
    let p = config_manager::VnicParams {
        adapter_name: adapter.to_string(),
        virtual_ip: "10.219.177.1".into(),
        overlay_cidr: "10.219.177.0/24".into(),
        ..Default::default()
    };
    VnicConfig::from_params(&p).expect("A 配置必须合法")
}

/// B 用 .178 网段 + **同名** adapter（同一把 Mutex；避开 A 遗留 on-link 网段）。
fn config_b(adapter: &str) -> VnicConfig {
    let p = config_manager::VnicParams {
        adapter_name: adapter.to_string(),
        virtual_ip: "10.219.178.1".into(),
        overlay_cidr: "10.219.178.0/24".into(),
        ..Default::default()
    };
    VnicConfig::from_params(&p).expect("B 配置必须合法")
}

/// 协议输出：stdout +（可选）--out 文件。
struct Out {
    file: Option<std::fs::File>,
}
impl Out {
    fn new() -> Self {
        let file = std::env::args()
            .position(|a| a == "--out")
            .and_then(|i| std::env::args().nth(i + 1))
            .map(|p| std::fs::OpenOptions::new().create(true).append(true).open(p).ok())
            .flatten();
        Out { file }
    }
    fn line(&mut self, s: &str) {
        println!("{s}");
        let _ = std::io::stdout().flush();
        if let Some(f) = &mut self.file {
            let _ = writeln!(f, "{s}");
            let _ = f.flush();
        }
    }
}

fn map_exit(e: &VnicError) -> i32 {
    match e {
        VnicError::AdapterLockedByOtherProcess { .. } => EXIT_LOCKED,
        VnicError::AdapterMutexAccessDenied { .. } => EXIT_ACCESS_DENIED,
        VnicError::AdapterMutexWaitFailed { .. } => EXIT_WAIT_FAILED,
        _ => EXIT_OTHER,
    }
}

// ---------------------------------------------------------------------------
// 独立 FFI（kernel32 最小集）：预打开 / 探测命名 Mutex 用。
// 与 mesh-vnic 内部实现零耦合（helper 是独立 bin，只依赖公开 lib API + 自带 FFI）。
// ---------------------------------------------------------------------------
mod raw_mutex {
    use std::ffi::c_void;
    pub type Handle = *mut c_void;

    pub const WAIT_OBJECT_0: u32 = 0;
    pub const WAIT_ABANDONED: u32 = 0x0000_0080;
    pub const WAIT_TIMEOUT: u32 = 258;
    pub const WAIT_FAILED: u32 = u32::MAX - 1;
    pub const ERROR_ACCESS_DENIED: u32 = 5;
    /// SYNCHRONIZE | READ_CONTROL | MUTEX_MODIFY_STATE（最小权限打开）
    pub const MUTEX_OPEN_DESIRED: u32 = 0x0001 | 0x0010_0000 | 0x0002_0000;

    #[link(name = "kernel32")]
    extern "system" {
        pub fn CreateMutexW(attrs: *const c_void, initial_owner: i32, name: *const u16) -> Handle;
        pub fn OpenMutexW(desired: u32, inherit: i32, name: *const u16) -> Handle;
        pub fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
        pub fn ReleaseMutex(h: Handle) -> i32;
        pub fn CloseHandle(h: Handle) -> i32;
        pub fn GetLastError() -> u32;
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "usage: {} <hold|try-acquire|recover|try-mutex> <adapter_name> [--out <file>]",
            args.first().map(String::as_str).unwrap_or("mesh-vnic-test-helper")
        );
        exit(EXIT_OTHER);
    }
    let cmd = args[1].as_str();
    let adapter = args[2].clone();
    let mut out = Out::new();

    match cmd {
        // -------------------------------------------------------------
        // hold：创建 VNIC（= 持 Mutex + Adapter + Session）后驻留
        // -------------------------------------------------------------
        "hold" => {
            let mut vnic = match MeshVnic::create_with_dll(&dll_path(), config_a(&adapter)) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("HOLD_CREATE_FAILED: {e}");
                    exit(map_exit(&e));
                }
            };
            out.line(&format!(
                "READY pid={} adapter={adapter} mutex={} luid=0x{:X}",
                std::process::id(),
                mutex_name(&adapter),
                vnic.luid().unwrap_or(0),
            ));
            // 驻留直到父进程 taskkill /F（无清理路径，制造 abandoned ownership）；
            // stdin EOF（父进程关闭管道/手动 Ctrl+Z 回车）则优雅退出。
            let stdin = std::io::stdin();
            let mut line = String::new();
            loop {
                match stdin.lock().read_line(&mut line) {
                    Ok(0) => break, // EOF
                    Ok(_) => { line.clear(); continue; }
                    Err(_) => break,
                }
            }
            out.line("HOLD_EOF_STOP");
            vnic.stop().ok();
            exit(EXIT_OK);
        }

        // -------------------------------------------------------------
        // try-acquire：完整走 MeshVnic::create 生产路径
        // （Mutex 在 WintunCreateAdapter 之前；错误类型即结构化证据：
        //   若 B 报 AdapterConflict/AdapterCreateFailed 说明已越过 Mutex —— 失败）
        // -------------------------------------------------------------
        "try-acquire" => {
            match MeshVnic::create_with_dll(&dll_path(), config_b(&adapter)) {
                Ok(mut vnic) => {
                    out.line(&format!(
                        "CREATED adapter={adapter} abandoned={} luid=0x{:X}",
                        vnic.lock_recovered_from_abandoned(),
                        vnic.luid().unwrap_or(0),
                    ));
                    vnic.stop().ok();
                    exit(EXIT_OK);
                }
                Err(e) => {
                    let variant = match &e {
                        VnicError::AdapterLockedByOtherProcess { .. } => "AdapterLockedByOtherProcess",
                        VnicError::AdapterMutexAccessDenied { .. } => "AdapterMutexAccessDenied",
                        VnicError::AdapterMutexWaitFailed { .. } => "AdapterMutexWaitFailed",
                        _ => "Other",
                    };
                    out.line(&format!("RESULT={variant}"));
                    eprintln!("try-acquire 失败: {e}");
                    exit(map_exit(&e));
                }
            }
        }

        // -------------------------------------------------------------
        // recover：预打开保活 → [父测试 taskkill A] → 生产路径接管 abandoned
        // → 恢复 Adapter → RX/TX smoke
        // -------------------------------------------------------------
        "recover" => {
            // 1. 预打开（严格 OpenMutexW，不创建）：保活句柄保证 A 死后
            //    Mutex 对象不销毁 → 生产路径才能观察到 WAIT_ABANDONED。
            let name_w: Vec<u16> = mutex_name(&adapter).encode_utf16().chain(std::iter::once(0)).collect();
            let keep = unsafe {
                raw_mutex::OpenMutexW(raw_mutex::MUTEX_OPEN_DESIRED, 0, name_w.as_ptr())
            };
            if keep.is_null() {
                let os = unsafe { raw_mutex::GetLastError() };
                out.line(&format!("PREOPEN_FAIL os={os} mutex={}", mutex_name(&adapter)));
                eprintln!("recover 预打开失败 os={os}（A 未先启动？）");
                exit(if os == raw_mutex::ERROR_ACCESS_DENIED { EXIT_ACCESS_DENIED } else { EXIT_OTHER });
            }
            out.line(&format!(
                "PREOPEN pid={} mutex={} keep_alive=1",
                std::process::id(),
                mutex_name(&adapter),
            ));

            // 2. 生产路径重试（A 死亡后下一次 create 必须 WAIT_ABANDONED 接管）。
            let mut acquired: Option<MeshVnic> = None;
            let mut last_err = String::from("unreached");
            for _ in 0..150 {
                // 150 × 200ms = 30s 窗口
                match MeshVnic::create_with_dll(&dll_path(), config_b(&adapter)) {
                    Ok(v) => { acquired = Some(v); break; }
                    Err(VnicError::AdapterLockedByOtherProcess { .. }) => {
                        // A 仍活着（父测试还没来得及杀）—— 继续等
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                    Err(e) => {
                        last_err = format!("{e}");
                        out.line(&format!("RESULT={}", map_exit(&e)));
                        eprintln!("recover 生产路径失败: {e}");
                        unsafe { raw_mutex::CloseHandle(keep); }
                        exit(map_exit(&e));
                    }
                }
            }
            let mut vnic = match acquired {
                Some(v) => v,
                None => {
                    out.line("RECOVER_FAIL=5");
                    eprintln!("recover 30s 窗口内未接管成功: {last_err}");
                    unsafe { raw_mutex::CloseHandle(keep); }
                    exit(EXIT_OTHER);
                }
            };
            let abandoned = vnic.lock_recovered_from_abandoned();
            if abandoned {
                out.line(&format!(
                    "EVENT=MutexAbandonedRecovered mutex={}",
                    mutex_name(&adapter),
                ));
            }
            out.line(&format!(
                "RECOVERED abandoned={abandoned} pid={} adapter={adapter} luid=0x{:X}",
                std::process::id(),
                vnic.luid().unwrap_or(0),
            ));

            // 3. RX/TX smoke：内嵌 ICMP responder + Windows 栈 ping（真实双向）
            //    ping 10.219.178.2 → on-link → VNIC RX → responder → TX → 栈回包
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stop2 = stop.clone();
            let peer: Ipv4Addr = "10.219.178.2".parse().unwrap();
            let mut ok = false;
            std::thread::scope(|s| {
                let responder = s.spawn(|| {
                    while !stop2.load(std::sync::atomic::Ordering::Acquire) {
                        match vnic.recv_timeout(std::time::Duration::from_millis(100)) {
                            Ok(Some(pkt)) => { let _ = vnic.send_icmp_echo_reply_for(&pkt); }
                            Ok(None) => continue,
                            Err(_) => break,
                        }
                    }
                });
                for _ in 0..5 {
                    // on-link 路由由栈在接口 up 后生成（NLA 延迟），最多重试 5 次
                    let p = std::process::Command::new("ping")
                        .args(["-n", "1", "-w", "2000", &peer.to_string()])
                        .output();
                    if p.map(|o| o.status.code() == Some(0)).unwrap_or(false) {
                        ok = true;
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                }
                stop.store(true, std::sync::atomic::Ordering::Release);
                let _ = responder.join();
            });
            let st = vnic.stats();
            out.line(&format!(
                "SMOKE={} rx={} tx={}",
                if ok { "PASS" } else { "FAIL" },
                st.rx_packets, st.tx_packets,
            ));
            vnic.stop().ok();
            unsafe { raw_mutex::CloseHandle(keep); }
            exit(if ok { EXIT_OK } else { EXIT_SMOKE_FAIL });
        }

        // -------------------------------------------------------------
        // try-mutex：独立 FFI 探测命名 Mutex（不触碰 Wintun / 不依赖本 crate 内部）
        // non-admin ACL 测试用：期望 CreateMutexW → ACCESS_DENIED (os=5) → exit 3
        // -------------------------------------------------------------
        "try-mutex" => {
            exit(try_mutex(&adapter, &mut out));
        }

        _ => {
            eprintln!("unknown command: {cmd}");
            exit(EXIT_OTHER);
        }
    }
}

/// 独立 FFI 探测：CreateMutexW(NULL attrs) + WaitForSingleObject(0ms)。
/// （对象存在 ≠ 对象被持有：结果由 wait 返回值单独判定。）
fn try_mutex(adapter: &str, out: &mut Out) -> i32 {
    use raw_mutex::*;
    let name_w: Vec<u16> = mutex_name(adapter).encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY：name_w 是 NUL 结尾 UTF-16 缓冲，生命周期覆盖调用。
    let h = unsafe { CreateMutexW(std::ptr::null(), 0, name_w.as_ptr()) };
    if h.is_null() {
        let os = unsafe { GetLastError() };
        out.line(&format!("MUTEX_RESULT=OPEN_FAILED os={os} mutex={}", mutex_name(adapter)));
        return if os == ERROR_ACCESS_DENIED { EXIT_ACCESS_DENIED } else { EXIT_WAIT_FAILED };
    }
    let wait = unsafe { WaitForSingleObject(h, 0) };
    let code = match wait {
        WAIT_OBJECT_0 => {
            out.line(&format!("MUTEX_RESULT=ACQUIRED mutex={}", mutex_name(adapter)));
            EXIT_OK
        }
        WAIT_ABANDONED => {
            out.line(&format!("MUTEX_RESULT=ABANDONED mutex={}", mutex_name(adapter)));
            EXIT_OK
        }
        WAIT_TIMEOUT => {
            out.line(&format!("MUTEX_RESULT=LOCKED mutex={}", mutex_name(adapter)));
            EXIT_LOCKED
        }
        WAIT_FAILED | _ => {
            let os = unsafe { GetLastError() };
            out.line(&format!("MUTEX_RESULT=WAIT_FAILED os={os} mutex={}", mutex_name(adapter)));
            if os == ERROR_ACCESS_DENIED { EXIT_ACCESS_DENIED } else { EXIT_WAIT_FAILED }
        }
    };
    // SAFETY：h 有效且本函数独占使用。
    unsafe {
        if wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED {
            ReleaseMutex(h);
        }
        CloseHandle(h);
    }
    code
}
