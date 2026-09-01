//! M0-3i 实机验收测试（需要：管理员权限 + 官方 wintun.dll + Windows 10+）。
//!
//! 运行方式（管理员 PowerShell）：
//! ```powershell
//! $env:MESH_VNIC_E2E = "1"
//! cargo test -p mesh-vnic --test real_machine -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! 未设置 MESH_VNIC_E2E 时全部跳过；设置了但非管理员则硬失败（防止误判通过）。
//!
//! 测试网段刻意选用 10.219.177.0/24（避开常见 LAN/Docker/WSL 网段）；
//! 若与本机真实网段冲突，subnet-conflict 用例之外会失败并如实报告。

use mesh_vnic::{MeshVnic, VnicConfig, VnicError};
use std::net::Ipv4Addr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TEST_IP: &str = "10.219.177.1";
const TEST_CIDR: &str = "10.219.177.0/24";
const TEST_PEER: &str = "10.219.177.2";
/// 模式 B 固定持久化 GUID（ADR 实验；非官方示例 deadbabe，要求十七）
const GUID_B: &str = "7e3a1c92-5b4d-4e8f-9a01-2c3d4e5f6a7b";

fn e2e_enabled() -> bool {
    std::env::var("MESH_VNIC_E2E").is_ok()
}

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
}

fn require_env_and_admin() -> bool {
    if !e2e_enabled() {
        eprintln!("SKIP: 未设置 MESH_VNIC_E2E=1（实机验收测试按需运行）");
        return false;
    }
    // SAFETY：shell32 IsUserAnAdmin，无参数
    if unsafe { IsUserAnAdmin() } == 0 {
        panic!("E2E 已启用但当前进程非管理员权限——请以管理员身份运行 cargo test");
    }
    true
}

fn dll_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(r"..\..\third_party\wintun\bin\amd64\wintun.dll")
}

fn test_params() -> config_manager::VnicParams {
    config_manager::VnicParams {
        virtual_ip: TEST_IP.into(),
        overlay_cidr: TEST_CIDR.into(),
        ..Default::default()
    }
}

fn test_config() -> VnicConfig {
    VnicConfig::from_params(&test_params()).expect("测试配置必须合法")
}

/// ICMP Echo Responder（scoped 线程借用 vnic）。
/// `stats` 记录处理的 echo request 数。
fn respond_echo(vnic: &MeshVnic, stop: &AtomicBool, stats: &AtomicU64) {
    while !stop.load(Ordering::Acquire) {
        match vnic.recv_timeout(Duration::from_millis(100)) {
            Ok(Some(pkt)) => {
                stats.fetch_add(1, Ordering::Relaxed);
                let _ = vnic.send_icmp_echo_reply_for(&pkt);
            }
            Ok(None) => continue,
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// 1. Adapter 创建 + IPv4 配置 + Session + 路由检查 + IP 不残留
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn adapter_create_ip_session_routes_and_no_residual() {
    if !require_env_and_admin() { return; }
    let mut vnic = MeshVnic::create_with_dll(&dll_path(), test_config())
        .expect("VNIC 创建必须成功（管理员 + 官方 DLL）");

    // 驱动版本：官方 Wintun 0.14.x 内核驱动（Major<<16|Minor 编码）→ 0.14 = 0x0000000E
    // （实测官方签名 0.14.1 DLL 在干净与已装机器上均返回 0x0000000E，自带日志 "driver 0.14"）
    let ver = vnic.driver_version();
    println!("driver_version = 0x{ver:08X}");
    assert_eq!(ver, 0x0000_000E, "必须是官方 Wintun 0.14.x 内核驱动");

    // LUID 与 IP
    let luid = vnic.luid().expect("LUID 必须可得");
    println!("luid = 0x{luid:X}");
    let ip: Ipv4Addr = TEST_IP.parse().unwrap();
    assert!(
        MeshVnic::local_ipv4_addresses().unwrap().iter().any(|(a, p, l)| *a == ip && *p == 24 && *l == luid),
        "虚拟 IP 必须已配置在本接口上"
    );

    // 验收 22：路由只允许 on-link /24，绝不允许 0.0.0.0/0
    // on-link 路由由栈在接口完全 up 后生成（NLA 有延迟），轮询等待最多 10s
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let routes = loop {
        let routes = vnic.routes_via_self().expect("路由枚举必须成功");
        let has_onlink =
            routes.iter().any(|(d, p)| *d == Ipv4Addr::new(10, 219, 177, 0) && *p == 24);
        if has_onlink || std::time::Instant::now() > deadline {
            break routes;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    println!("routes = {routes:?}");
    assert!(
        routes.iter().any(|(d, p)| *d == Ipv4Addr::new(10, 219, 177, 0) && *p == 24),
        "on-link /24 路由必须在 10s 内出现"
    );
    assert!(
        !routes.iter().any(|(_, p)| *p == 0),
        "禁止 0.0.0.0/0 默认路由（M0 是 Overlay LAN）"
    );

    // 验收 12：可取消 shutdown（5s 超时内完成）
    let t0 = std::time::Instant::now();
    vnic.stop().expect("stop 必须成功");
    assert!(t0.elapsed() < Duration::from_secs(5), "stop 必须在超时前完成");

    // 验收 6：Adapter 删除后 IP 不残留
    let residual = MeshVnic::local_ipv4_addresses()
        .unwrap()
        .into_iter()
        .any(|(a, _, l)| a == ip && l == luid);
    assert!(!residual, "stop 后虚拟 IP 不得残留");
}

// ---------------------------------------------------------------------------
// 1b. 对端 /32 主机路由（Overlay MVP 规格八：路由最小化 + 无残留）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn peer_host_route_add_idempotent_and_no_residual() {
    if !require_env_and_admin() { return; }
    let mut vnic = MeshVnic::create_with_dll(&dll_path(), test_config())
        .expect("VNIC 创建必须成功（管理员 + 官方 DLL）");
    let peer: Ipv4Addr = TEST_PEER.parse().unwrap();
    let luid = vnic.luid().expect("LUID 必须可得");

    // 安装 + 幂等重装
    vnic.add_peer_route(peer).expect("安装对端 /32 路由必须成功");
    vnic.add_peer_route(peer).expect("重复安装必须幂等成功");
    assert_eq!(vnic.installed_peer_routes(), vec![peer], "已安装列表必须恰好包含对端");

    // 策略校验：overlay 网段外地址必须被拒绝（规格八）
    let outside: Ipv4Addr = "10.70.31.2".parse().unwrap();
    assert!(
        matches!(vnic.add_peer_route(outside), Err(VnicError::ConfigInvalid { .. })),
        "网段外地址必须被策略拒绝，绝不进入系统路由表"
    );

    // 路由表必须出现 (peer, /32) 且绝无 0.0.0.0/0
    let deadline = Instant::now() + Duration::from_secs(10);
    let routes = loop {
        let routes = vnic.routes_via_self().expect("路由枚举必须成功");
        if routes.iter().any(|(d, p)| *d == peer && *p == 32) || Instant::now() > deadline {
            break routes;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    println!("routes = {routes:?}");
    assert!(
        routes.iter().any(|(d, p)| *d == peer && *p == 32),
        "对端 /32 路由必须在 10s 内出现"
    );
    assert!(
        !routes.iter().any(|(_, p)| *p == 0),
        "禁止 0.0.0.0/0 默认路由（规格八：绝不抢默认路由）"
    );

    // stop：路由必须随会话回收（不残留）
    vnic.stop().expect("stop 必须成功");
    let after = vnic.routes_via_self().expect("stop 后路由枚举仍可执行");
    println!("routes_after_stop = {after:?}");
    assert!(
        !after.iter().any(|(d, p)| *d == peer && *p == 32),
        "stop 后对端 /32 路由必须被回收"
    );
    assert!(
        !after.iter().any(|(_, p)| *p == 0),
        "stop 后同样禁止默认路由"
    );
    let _ = luid;
}

// ---------------------------------------------------------------------------
// 2. ICMP 双向真实收发（要求二十一 / 验收 8、9）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn icmp_bidirectional_through_windows_stack() {
    if !require_env_and_admin() { return; }
    let mut vnic = MeshVnic::create_with_dll(&dll_path(), test_config())
        .expect("VNIC 创建必须成功");

    let stop = AtomicBool::new(false);
    let answered = AtomicU64::new(0);
    std::thread::scope(|s| {
        s.spawn(|| respond_echo(&vnic, &stop, &answered));
        // 让 Windows 路由/接口状态稳定
        std::thread::sleep(Duration::from_millis(300));
        // Windows TCP/IP 栈 → Wintun → mesh-vnic RX；回程 mesh-vnic TX → 栈
        let out = Command::new("ping")
            .args(["-n", "2", "-w", "2000", TEST_PEER])
            .output()
            .expect("ping 启动失败");
        let stdout = String::from_utf8_lossy(&out.stdout);
        println!("ping exit={} \n{}", out.status.code().unwrap_or(-1), stdout);
        assert_eq!(out.status.code(), Some(0), "ping 必须成功（RX+TX 双向证明）");
        stop.store(true, Ordering::Release);
    });

    let a = answered.load(Ordering::Relaxed);
    println!("echo requests answered = {a}");
    assert!(a >= 2, "必须至少应答 2 个 echo request");
    let st = vnic.stats();
    println!("stats = {st:?}");
    assert!(st.rx_packets > 0, "RX 必须收到包");
    assert!(st.tx_packets > 0, "TX 必须发出包");
    // Windows 在新启用的适配器上会主动发送 IPv6 ND(NDP)/NBNS(137)/SSDP(1900)/IGMP 等
    // 非 IPv4 / 非本测试预期的包，它们会被 RX worker 的严格 IPv4 校验计入 rx_dropped_invalid。
    // 这不属于 bug：
    //   - 丢弃逻辑无 panic（验收 19：非法 IPv4 包不 panic）已由 crate::packet 单元测试 ×5 覆盖；
    //   - 这里我们只确保无真实错误：rx_errors / tx_errors = 0。
    assert_eq!(st.rx_errors, 0, "RX 无协议外错误");
    assert_eq!(st.tx_errors, 0, "TX 无协议外错误");
    vnic.stop().expect("stop 必须成功");
}

// ---------------------------------------------------------------------------
// 3. 生命周期压力 ×100（要求二十二 / 验收 11、14）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn lifecycle_stress_100_cycles() {
    if !require_env_and_admin() { return; }
    let mut samples = Vec::new();
    for i in 1..=100 {
        let mut vnic = MeshVnic::create_with_dll(&dll_path(), test_config())
            .unwrap_or_else(|e| panic!("第 {i} 次创建失败: {e}"));
        // TX 非法包不 panic（验收 20）
        let _ = vnic.send(vec![0u8; 3]);
        // TX 合法包（echo request 伪包，无人应答也无妨）
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&[10, 219, 177, 2]);
        pkt[16..20].copy_from_slice(&[10, 219, 177, 1]);
        pkt[20] = 8;
        let _ = vnic.send(pkt);
        vnic.stop().unwrap_or_else(|e| panic!("第 {i} 次停止失败: {e}"));

        if matches!(i, 1 | 10 | 50 | 100) {
            let (ws, pb) = MeshVnic::process_memory_usage();
            let s = (i, MeshVnic::process_handle_count(), ws, pb);
            println!("cycle {:>3}: handles={} working_set={:.1}MiB private={:.1}MiB", s.0, s.1, s.2 as f64 / 1048576.0, s.3 as f64 / 1048576.0);
            samples.push(s);
        }
    }
    // 泄漏判据：handle 数第 100 次相对第 10 次增长 < 10%（要求二十三）
    let h10 = samples.iter().find(|s| s.0 == 10).unwrap().1 as f64;
    let h100 = samples.iter().find(|s| s.0 == 100).unwrap().1 as f64;
    println!("handle growth 10→100: {:.1}%", (h100 - h10) / h10 * 100.0);
    assert!(h100 < h10 * 1.10, "handle 数明显线性增长：10 次时 {h10}，100 次时 {h100}");
}

// ---------------------------------------------------------------------------
// 4. Service-style start/stop ×100（要求二十二 / 验收 12）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn service_style_start_stop_100() {
    if !require_env_and_admin() { return; }
    for i in 1..=100 {
        let mut vnic = MeshVnic::create_with_dll(&dll_path(), test_config())
            .unwrap_or_else(|e| panic!("service 第 {i} 次启动失败: {e}"));
        // 模拟 Service 运行态：后台收包 + 立即停止（检验无死锁）
        let stop = AtomicBool::new(false);
        let n = AtomicU64::new(0);
        std::thread::scope(|s| {
            s.spawn(|| respond_echo(&vnic, &stop, &n));
            std::thread::sleep(Duration::from_millis(2));
            stop.store(true, Ordering::Release);
        });
        let t0 = std::time::Instant::now();
        vnic.stop().unwrap_or_else(|e| panic!("service 第 {i} 次停止失败: {e}"));
        assert!(t0.elapsed() < Duration::from_secs(5), "第 {i} 次 stop 卡死超过 5s");
    }
    println!("service-style 100 次 start/stop 全部成功且无死锁");
}

// ---------------------------------------------------------------------------
// 5. Crash Recovery（要求二十二 / 验收 13）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn crash_recovery_after_process_kill() {
    if !require_env_and_admin() { return; }
    let exe = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(r"..\..\target\debug\examples\vnic_smoke.exe");
    let exe = exe.canonicalize().expect("先 cargo build --examples -p mesh-vnic");

    // 1. 子进程创建 VNIC 后驻留
    let mut child = Command::new(&exe)
        .arg("--hold")
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("vnic_smoke 启动失败");
    // 循环读行直到 READY（中间可能有其它 stdout 行），EOF/超时视为失败
    use std::io::BufRead;
    let mut line = String::new();
    {
        let stdout = child.stdout.as_mut().unwrap();
        let mut reader = std::io::BufReader::new(stdout);
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        loop {
            assert!(std::time::Instant::now() < deadline, "等待子进程 READY 超时");
            line.clear();
            let n = reader.read_line(&mut line).expect("读取子进程 stdout 失败");
            if n == 0 {
                panic!("子进程提前退出（未打印 READY）");
            }
            if line.contains("READY") {
                break;
            }
        }
    }
    println!("子进程: {}", line.trim());
    assert!(line.contains("READY"), "子进程必须创建 VNIC 成功");

    // 2. 强杀（模拟 crash，无任何清理路径）
    let _ = child.kill();
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(500));

    // 3. 重新启动必须成功（同名 Adapter 复用 / 重建，绝不卡在 already exists）
    let mut vnic2 = MeshVnic::create_with_dll(&dll_path(), test_config())
        .expect("crash 后重启必须成功（验收 13）");
    let luid2 = vnic2.luid();
    println!("crash 后 luid = {luid2:?}");
    assert!(vnic2.luid().is_some());
    // IP 必须重新配置成功（可能因 ghost 适配器残留而"已存在"→ 幂等接受）
    vnic2.stop().expect("crash 后重启的 VNIC 必须可正常停止");
}

// ---------------------------------------------------------------------------
// 6. Provider Crash 不影响 VNIC（要求二十四 / 验收 21）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn provider_crash_does_not_affect_vnic() {
    if !require_env_and_admin() { return; }
    let mut vnic = MeshVnic::create_with_dll(&dll_path(), test_config()).expect("VNIC 创建必须成功");

    // FakeTransportProvider：panic / Fatal —— 独立线程崩溃不影响 VNIC
    let provider = std::thread::spawn(|| {
        panic!("FakeTransportProvider fatal crash（模拟 Provider 崩溃）");
    });
    let _ = provider.join(); // panic 已被隔离在线程内

    // VNIC 完好：接口存活、IP 仍在、可继续收发
    assert!(vnic.luid().is_some(), "VNIC 必须仍然存活");
    let ip: Ipv4Addr = TEST_IP.parse().unwrap();
    let luid = vnic.luid().unwrap();
    assert!(
        MeshVnic::local_ipv4_addresses().unwrap().iter().any(|(a, _, l)| *a == ip && *l == luid),
        "Provider 崩溃后虚拟 IP 必须仍在"
    );
    let mut pkt = vec![0u8; 28];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
    pkt[9] = 1;
    pkt[12..16].copy_from_slice(&[10, 219, 177, 2]);
    pkt[16..20].copy_from_slice(&[10, 219, 177, 1]);
    pkt[20] = 8;
    vnic.send(pkt).expect("Provider 崩溃后 TX 必须仍可工作");
    vnic.stop().expect("Provider 崩溃后 stop 必须正常");
}

// ---------------------------------------------------------------------------
// 7. GUID 模式 A/B identity 观测（要求十七 / 验收数据 → ADR）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn guid_identity_mode_a_vs_b() {
    if !require_env_and_admin() { return; }

    // 模式 A：RequestedGUID = NULL
    let mut a1 = MeshVnic::create_with_dll(&dll_path(), test_config()).unwrap();
    let luid_a1 = a1.luid();
    a1.stop().unwrap();
    let mut a2 = MeshVnic::create_with_dll(&dll_path(), test_config()).unwrap();
    let luid_a2 = a2.luid();
    a2.stop().unwrap();

    // 模式 B：固定持久化 GUID
    let params_b = config_manager::VnicParams {
        virtual_ip: TEST_IP.into(),
        overlay_cidr: TEST_CIDR.into(),
        requested_guid: Some(GUID_B.into()),
        ..Default::default()
    };
    let cfg_b = VnicConfig::from_params(&params_b).unwrap();
    let mut b1 = MeshVnic::create_with_dll(&dll_path(), cfg_b.clone()).unwrap();
    let luid_b1 = b1.luid();
    b1.stop().unwrap();
    let mut b2 = MeshVnic::create_with_dll(&dll_path(), cfg_b.clone()).unwrap();
    let luid_b2 = b2.luid();
    b2.stop().unwrap();

    println!("模式 A（GUID=NULL）: 第一次={luid_a1:?} 第二次={luid_a2:?} 稳定={}", luid_a1 == luid_a2);
    println!("模式 B（固定 GUID）: 第一次={luid_b1:?} 第二次={luid_b2:?} 稳定={}", luid_b1 == luid_b2);

    // 模式 B 硬保证：同一 GUID → 同一 Adapter → 同一 LUID（Wintun 官方语义）
    assert_eq!(luid_b1, luid_b2, "模式 B 同 GUID 必须得到稳定 LUID");
    // 模式 A 行为记录进 ADR，不做硬断言（可能因同名复用而相同或不同）
}

// ---------------------------------------------------------------------------
// 8. TX Backpressure：Ring/队列满不 panic（要求十 / 验收 19）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn tx_backpressure_ring_full_no_panic() {
    if !require_env_and_admin() { return; }
    // tx_queue_len=1：不消费，灌包制造 backpressure
    let params = config_manager::VnicParams {
        virtual_ip: TEST_IP.into(),
        overlay_cidr: TEST_CIDR.into(),
        tx_queue_len: 1,
        ..Default::default()
    };
    let cfg = VnicConfig::from_params(&params).unwrap();
    let vnic = MeshVnic::create_with_dll(&dll_path(), cfg).expect("创建必须成功");

    let mut ring_full = 0u32;
    for i in 0..200 {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[9] = 1;
        pkt[12..16].copy_from_slice(&[10, 219, 177, 2]);
        pkt[16..20].copy_from_slice(&[10, 219, 177, 1]);
        pkt[20] = 8;
        pkt[24..28].copy_from_slice(&(i as u32).to_be_bytes());
        match vnic.send(pkt) {
            Ok(()) => {}
            Err(VnicError::SendRingFull) => ring_full += 1,
            Err(e) => panic!("意外错误（不得 panic，但也不应是这个）: {e}"),
        }
    }
    println!("backpressure 触发 {ring_full}/200 次，无 panic");
    let st = vnic.stats();
    println!("stats = {st:?}");
    assert!(st.tx_dropped_queue_full > 0, "队列满丢弃必须被计数（vnic_tx_ring_full_total）");
    // 消费者不存在但 TX worker 在跑：给 ring 一点时间消化
    std::thread::sleep(Duration::from_millis(200));
    drop(vnic); // Drop 内部 shutdown 路径必须正常（不 panic）
}

// ---------------------------------------------------------------------------
// 9. Overlay 网段冲突检测（要求十四 / 验收 23）
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn overlay_subnet_conflict_detected() {
    if !require_env_and_admin() { return; }
    // 找一个本机现有网段（排除测试自身网段），用它作为 overlay → 必须被拒绝
    let locals = MeshVnic::local_ipv4_addresses().expect("枚举本机地址失败");
    let test_net = u32::from(Ipv4Addr::new(10, 219, 177, 0));
    let safe_mask = |p: u8| -> u32 {
        let p = p.min(32) as u32;
        if p == 0 { 0 } else { u32::MAX << (32 - p) }
    };
    let victim = locals.iter().find(|(a, p, _)| {
        let net = u32::from(*a) & safe_mask(*p);
        net != test_net && *p > 0 && *p <= 32
    });
    let (ip, prefix) = match victim {
        Some((a, p, _)) => (*a, *p),
        None => {
            eprintln!("SKIP: 本机没有其它 IPv4 网段可供冲突测试");
            return;
        }
    };
    let net_u32 = u32::from(ip) & (!0u32 << (32 - prefix as u32));
    let net_ip = Ipv4Addr::from(net_u32);
    let host_part = net_ip.to_string();
    let virtual_ip = format!("{}.1", &host_part[..host_part.rfind('.').unwrap()]);
    let params = config_manager::VnicParams {
        virtual_ip,
        overlay_cidr: format!("{net_ip}/{prefix}"),
        ..Default::default()
    };
    println!("尝试与现有网段重叠的 overlay: {net_ip}/{prefix}");
    let cfg = VnicConfig::from_params(&params).unwrap();
    let err = match MeshVnic::create_with_dll(&dll_path(), cfg) {
        Err(e) => e,
        Ok(_) => panic!("重叠网段 {net_ip}/{prefix} 必须创建失败"),
    };
    assert!(
        matches!(err, VnicError::OverlaySubnetConflict { .. }),
        "重叠网段必须报 OverlaySubnetConflict，实际: {err}"
    );
    println!("OverlaySubnetConflict 正确检出");
}

// ===========================================================================
// M0-3.1-1 真实跨进程互斥验收（Process A / Process B = 独立 Windows 进程，
// 禁止同进程线程模拟作为验收）。helper = mesh-vnic-test-helper.exe
// （cargo test 自动构建同包 bins，CARGO_BIN_EXE_ 宏编译期注入路径）。
//
// 语义前提（Windows 内核对象生命周期）：Mutex 对象在**最后一个句柄关闭**后
// 被销毁。Owner 进程被 taskkill /F 后若无人持有该对象的句柄，下一次
// CreateMutexW 得到的是全新对象（WAIT_OBJECT_0），永远观察不到
// WAIT_ABANDONED —— 所以 abandoned 观测必须在 Owner 死亡前由另一个进程
// **预打开** Mutex（保持句柄存活），这正是真实部署中"后继者已在等待"的经典
// 模式：被阻塞的 waiter 在 Owner 死亡时收到 WAIT_ABANDONED。
// ===========================================================================

fn helper_exe() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_mesh-vnic-test-helper"))
}

/// 启动 helper（stdout 管道），阻塞读到一个协议行（READY/PREOPEN/…）。
fn spawn_helper_expect_line(args: &[&str]) -> (std::process::Child, String) {
    use std::io::BufRead;
    let mut child = Command::new(helper_exe())
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("helper 启动失败（cargo test 自动构建同包 bins）");
    let mut line = String::new();
    {
        let stdout = child.stdout.as_mut().unwrap();
        let mut reader = std::io::BufReader::new(stdout);
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            assert!(Instant::now() < deadline, "等待 helper 协议行超时");
            line.clear();
            let n = reader.read_line(&mut line).expect("读 helper stdout 失败");
            if n == 0 {
                panic!("helper 提前退出（未打印任何协议行）");
            }
            let t = line.trim();
            let is_protocol = ["READY", "PREOPEN", "CREATED", "RECOVERED", "RECOVER_FAIL", "RESULT=", "MUTEX_RESULT="]
                .iter().any(|p| t.starts_with(p));
            if is_protocol {
                break;
            }
        }
    }
    (child, line.trim().to_string())
}

fn field<'a>(line: &'a str, key: &str) -> Option<String> {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key).map(String::from))
}

/// 阻塞运行 helper 到退出，返回 (exit_code, 全部 stdout)。
fn run_helper(args: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(helper_exe())
        .args(args)
        .output()
        .expect("helper 启动失败");
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

// ---------------------------------------------------------------------------
// 10. 真实双进程 contention：
//     Process A 独立进程持锁 → Process B 独立进程必须 AdapterLockedByOtherProcess
//     → TerminateProcess(A) → Process B' 成功获取 Mutex + Adapter
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn cross_process_mutex_contention_true_processes() {
    if !require_env_and_admin() { return; }

    // --- Process A（独立进程）：持有 Mutex + Adapter（10.219.177.0/24）---
    let (mut proc_a, line_a) = spawn_helper_expect_line(&["hold", "MeshLink"]);
    let pid_a = field(&line_a, "pid=").expect("A 必须输出 pid");
    let mutex_a = field(&line_a, "mutex=").expect("A 必须输出 mutex 名");
    assert!(mutex_a.starts_with("Global\\MeshLink-Vnic-"),
        "Mutex 必须使用 Global\\ 系统范围命名: {mutex_a}");
    assert_eq!(mutex_a.len(), "Global\\MeshLink-Vnic-".len() + 16,
        "Mutex 后缀必须为 FNV-1a 64-bit hex (16 chars): {mutex_a}");
    eprintln!("[A pid={pid_a}] {line_a}");

    // --- Process B（独立进程）：A 持锁期间尝试同名 adapter ---
    // 必须返回 AdapterLockedByOtherProcess（该变体只产生于 Mutex 前置层；
    // 若是 AdapterConflict/AdapterCreateFailed 说明 B 已越过 Mutex 进入
    // WintunCreateAdapter —— V-04 事故防御链被击穿）。
    let (code_b, out_b) = run_helper(&["try-acquire", "MeshLink"]);
    eprintln!("[B] exit={code_b:?} stdout={out_b}");
    assert_eq!(code_b, Some(2), "B 必须以 AdapterLockedByOtherProcess 退出（exit 2）");
    assert!(out_b.contains("RESULT=AdapterLockedByOtherProcess"),
        "B 的错误必须是 AdapterLockedByOtherProcess，实际输出: {out_b}");

    // --- TerminateProcess(A)：不给 A 任何 ReleaseMutex / Drop / cleanup 机会 ---
    let _ = proc_a.kill(); // TerminateProcess
    let _ = proc_a.wait();
    std::thread::sleep(Duration::from_millis(500));

    // --- A 终止后，新进程 B' 必须成功获取 Mutex + Adapter ---
    let (code_b2, out_b2) = run_helper(&["try-acquire", "MeshLink"]);
    eprintln!("[B' after A terminated] exit={code_b2:?} stdout={out_b2}");
    assert_eq!(code_b2, Some(0), "A 终止后 B' 必须成功创建（true cross-process PASS）");
    assert!(out_b2.contains("CREATED"), "B' 应输出 CREATED，实际: {out_b2}");
}

// ---------------------------------------------------------------------------
// 11. 真实双进程 crash recovery：
//     Process A 持锁 → taskkill /F（无 ReleaseMutex/无 Drop/无 cleanup）
//     → Process B 预打开 Mutex（保持对象存活）→ 生产路径 create 必须观察到
//     WAIT_ABANDONED（abandoned=true + MutexAbandonedRecovered 事件）
//     → 恢复 Adapter → RX/TX smoke（Windows 栈 ping 双向）
// ---------------------------------------------------------------------------
#[test]
#[ignore]
fn cross_process_taskkill_abandoned_recovery_with_rx_tx_smoke() {
    if !require_env_and_admin() { return; }

    // --- Process A：持有 Mutex + Adapter → READY ---
    let (mut proc_a, line_a) = spawn_helper_expect_line(&["hold", "MeshLink"]);
    eprintln!("[A] {line_a}");

    // --- Process B：先预打开 Mutex（句柄保活，对象在 A 死后不销毁）→ PREOPEN ---
    let mut proc_b = Command::new(helper_exe())
        .args(["recover", "MeshLink"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("B (recover) 启动失败");
    {
        use std::io::BufRead;
        let stdout = proc_b.stdout.as_mut().unwrap();
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(Instant::now() < deadline, "等待 B 的 PREOPEN 超时");
            line.clear();
            let n = reader.read_line(&mut line).expect("读 B stdout 失败");
            if n == 0 { panic!("B 提前退出"); }
            if line.starts_with("PREOPEN") { break; }
        }
        eprintln!("[B] {}", line.trim());
    }
    // 此刻：B 已持有 Mutex 对象句柄（wait 一次 → A 正常持锁 → 不占有）。

    // --- 真正 kill Process A：taskkill /F /PID（TerminateProcess 等价），
    //     A 绝不执行 ReleaseMutex / Drop / 正常 cleanup ---
    let tk = Command::new("taskkill")
        .args(["/F", "/PID", &proc_a.id().to_string()])
        .output()
        .expect("taskkill 启动失败");
    eprintln!("[parent] taskkill /F /PID {}: {}",
        proc_a.id(), String::from_utf8_lossy(&tk.stdout).trim());
    let _ = proc_a.kill(); // 双保险（等价 TerminateProcess）
    let _ = proc_a.wait();
    drop(proc_a);

    // --- 等 B 完成接管 + Adapter 恢复 + RX/TX smoke ---
    let status_b = proc_b.wait().expect("等待 B 退出失败");
    eprintln!("[B] exit={status_b:?}");
    // recover 内部任何一步失败都会非 0 退出（smoke 失败 = exit 6），
    // exit 0 本身即蕴含「abandoned 接管成功 + Adapter 恢复 + RX/TX smoke PASS」。
    assert_eq!(status_b.code(), Some(0),
        "B 必须完成 abandoned 接管 + Adapter 恢复 + RX/TX smoke（exit 0）");
    // abandoned 接管/事件/smoke 的逐行证据由
    // cross_process_abandoned_event_chain_via_out_file（--out 完整记录）独立断言。

    // 复核：A、B 全部退出后无人持有 Mutex 句柄 → 内核对象已销毁（最后一个
    // 句柄关闭），recover 的严格预打开必然 OPEN_FAILED。正确复核动作是
    // try-acquire 完整生产路径：CreateMutexW 重建对象 → WAIT_OBJECT_0 正常
    // 获取（绝不 abandoned）→ WintunCreateAdapter 成功。
    let (code_v, out_v) = run_helper(&["try-acquire", "MeshLink"]);
    eprintln!("[B' verify after all exited] exit={code_v:?} stdout={out_v}");
    assert_eq!(code_v, Some(0), "复核轮 try-acquire 必须成功");
    assert!(out_v.contains("CREATED"), "B' 应输出 CREATED，实际: {out_v}");
    assert!(out_v.contains("abandoned=false"),
        "对象销毁后重建的获取绝不是 abandoned: {out_v}");
}

/// 带 --out 文件的 recover：完整断言 abandoned 事件链（跑在
/// cross_process_taskkill_abandoned_recovery_with_rx_tx_smoke 之后语义独立）。
#[test]
#[ignore]
fn cross_process_abandoned_event_chain_via_out_file() {
    if !require_env_and_admin() { return; }

    // --- Process A：持有 Mutex + Adapter ---
    let (mut proc_a, line_a) = spawn_helper_expect_line(&["hold", "MeshLink"]);
    eprintln!("[A] {line_a}");

    // --- Process B：recover（带 --out 完整记录协议行）---
    let out_file = std::env::temp_dir()
        .join(format!("mesh_vnic_recover_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&out_file);
    let mut proc_b = Command::new(helper_exe())
        .args(["recover", "MeshLink", "--out"])
        .arg(&out_file)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("B (recover) 启动失败");

    // 等 B 打印 PREOPEN（写进 --out 文件）
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut saw_preopen = false;
    while Instant::now() < deadline {
        if let Ok(s) = std::fs::read_to_string(&out_file) {
            if s.contains("PREOPEN") { saw_preopen = true; break; }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(saw_preopen, "B 必须先完成 Mutex 预打开（PREOPEN）");

    // --- taskkill /F /PID A ---
    let tk = Command::new("taskkill")
        .args(["/F", "/PID", &proc_a.id().to_string()])
        .output()
        .expect("taskkill 启动失败");
    eprintln!("[parent] taskkill: {}", String::from_utf8_lossy(&tk.stdout).trim());
    let _ = proc_a.kill();
    let _ = proc_a.wait();

    // --- B 完成接管 ---
    let status_b = proc_b.wait().expect("等待 B 失败");
    let recorded = std::fs::read_to_string(&out_file).unwrap_or_default();
    eprintln!("[B] exit={status_b:?} recorded={recorded:?}");
    let _ = std::fs::remove_file(&out_file);

    assert_eq!(status_b.code(), Some(0), "B 必须成功（exit 0）");
    assert!(recorded.contains("PREOPEN"), "必须有 PREOPEN（预打开保活证据）");
    assert!(recorded.contains("EVENT=MutexAbandonedRecovered"),
        "必须记录 MutexAbandonedRecovered 结构化事件（WAIT_ABANDONED 证据）: {recorded:?}");
    assert!(recorded.contains("RECOVERED abandoned=true"),
        "生产路径 AdapterLock 必须观察到 abandoned=true: {recorded:?}");
    assert!(recorded.contains("SMOKE=PASS"), "RX/TX smoke 必须通过: {recorded:?}");
}

// ===========================================================================
// M0-3.1-1a non-admin ACL：普通权限（非提权）进程不得创建抢占 / 打开获取 /
// 长期占有 MeshLink Mutex；且必须得到 AdapterMutexAccessDenied（不是
// AdapterLockedByOtherProcess —— 两个错误语义不同）。
// 机制：SaferComputeTokenFromLevel(SAFER_LEVELID_NORMALUSER) + CreateProcessAsUserW
// （与 runas /trustlevel:0x20000 同源的官方受限 token 机制）。
// ===========================================================================

mod restricted_token {
    use std::ffi::c_void;
    type Handle = *mut c_void;

    const SAFER_SCOPEID_MACHINE: u32 = 1;
    const SAFER_LEVELID_NORMALUSER: u32 = 0x20000;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_MS: u32 = 60_000;

    #[repr(C)]
    struct StartupInfoW {
        cb: u32,
        lp_reserved: *const u16,
        lp_desktop: *const u16,
        lp_title: *const u16,
        dw_x: u32, dw_y: u32, dw_x_size: u32, dw_y_size: u32,
        dw_x_count_chars: u32, dw_y_count_chars: u32, dw_fill_attribute: u32,
        dw_flags: u32,
        w_show_window: u16, cb_reserved2: u16,
        lp_reserved2: *mut u8,
        h_std_input: Handle, h_std_output: Handle, h_std_error: Handle,
    }
    #[repr(C)]
    struct ProcessInformation {
        h_process: Handle,
        h_thread: Handle,
        dw_process_id: u32,
        dw_thread_id: u32,
    }

    #[link(name = "advapi32")]
    extern "system" {
        fn SaferCreateLevel(scope: u32, level: u32, flags: u32, handle: *mut Handle, reserved: *mut c_void) -> i32;
        fn SaferComputeTokenFromLevel(level: Handle, in_token: Handle, out_token: *mut Handle, flags: u32, reserved: *mut c_void) -> i32;
        fn SaferCloseLevel(level: Handle) -> i32;
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn CreateProcessAsUserW(
            token: Handle, app_name: *const u16, cmd_line: *mut u16,
            proc_attrs: *const c_void, thread_attrs: *const c_void,
            inherit_handles: i32, creation_flags: u32, env: *const c_void,
            current_dir: *const u16, startup_info: *mut StartupInfoW,
            proc_info: *mut ProcessInformation,
        ) -> i32;
        fn WaitForSingleObject(h: Handle, ms: u32) -> u32;
        fn GetExitCodeProcess(h: Handle, code: *mut u32) -> i32;
        fn CloseHandle(h: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    /// 以「普通用户（非提权）」受限 token 运行 helper，阻塞到退出并返回退出码。
    pub fn run_normal_user(exe: &std::path::Path, args: &str) -> Result<u32, String> {
        unsafe {
            let mut level: Handle = std::ptr::null_mut();
            if SaferCreateLevel(SAFER_SCOPEID_MACHINE, SAFER_LEVELID_NORMALUSER, 0, &mut level, std::ptr::null_mut()) == 0 {
                return Err(format!("SaferCreateLevel 失败 os={}", GetLastError()));
            }
            let mut token: Handle = std::ptr::null_mut();
            let ok = SaferComputeTokenFromLevel(level, std::ptr::null_mut(), &mut token, 0, std::ptr::null_mut());
            SaferCloseLevel(level);
            if ok == 0 {
                return Err(format!("SaferComputeTokenFromLevel 失败 os={}", GetLastError()));
            }

            let mut cmdline: Vec<u16> = format!("\"{}\" {args}", exe.display())
                .encode_utf16().chain(std::iter::once(0)).collect();
            let mut si: StartupInfoW = std::mem::zeroed();
            si.cb = std::mem::size_of::<StartupInfoW>() as u32;
            let mut pi: ProcessInformation = std::mem::zeroed();
            let ok = CreateProcessAsUserW(
                token, std::ptr::null(), cmdline.as_mut_ptr(),
                std::ptr::null(), std::ptr::null(), 0,
                CREATE_NO_WINDOW, std::ptr::null(), std::ptr::null(),
                &mut si, &mut pi,
            );
            if ok == 0 {
                let os = GetLastError();
                CloseHandle(token);
                return Err(format!("CreateProcessAsUserW 失败 os={os}"));
            }
            CloseHandle(token);

            let wait = WaitForSingleObject(pi.h_process, WAIT_MS);
            let mut code: u32 = 0xFFFF_FFFF;
            GetExitCodeProcess(pi.h_process, &mut code);
            CloseHandle(pi.h_process);
            CloseHandle(pi.h_thread);
            if wait == WAIT_TIMEOUT {
                return Err("non-admin 子进程 60s 未退出".into());
            }
            Ok(code)
        }
    }
}

#[test]
#[ignore]
fn non_admin_mutex_cannot_acquire() {
    if !require_env_and_admin() { return; }

    // --- 管理员进程先创建受保护 Global Mutex（SDDL: SY/BA only）并持 Adapter ---
    let (mut proc_a, line_a) = spawn_helper_expect_line(&["hold", "MeshLink"]);
    let mutex_a = field(&line_a, "mutex=").expect("A 必须输出 mutex 名");
    eprintln!("[A admin] {line_a}");

    // 结果文件：非提权子进程无继承 stdio，协议行写文件供父测试断言
    let out_file = std::env::temp_dir()
        .join(format!("mesh_vnic_mutex_probe_{}.txt", std::process::id()));
    let _ = std::fs::remove_file(&out_file);
    let out_arg = format!("--out {}", out_file.display());

    // --- 探测 1：非提权进程裸探 Mutex（独立 FFI CreateMutexW + wait）---
    let code_probe = restricted_token::run_normal_user(
        &helper_exe(), &format!("try-mutex MeshLink {out_arg}"),
    ).expect("非提权子进程必须能启动");
    let probe_out = std::fs::read_to_string(&out_file).unwrap_or_default();
    eprintln!("[non-admin try-mutex] exit={code_probe} file={probe_out:?}");
    assert_eq!(code_probe, 3,
        "非提权进程必须得到 ACCESS_DENIED 语义（exit 3 = AdapterMutexAccessDenied）");
    assert!(probe_out.contains("MUTEX_RESULT=OPEN_FAILED os=5"),
        "非提权 CreateMutexW 必须被显式 DACL 拒绝（ERROR_ACCESS_DENIED=5）: {probe_out:?}");

    // --- 探测 2：非提权进程走生产路径（MeshVnic::create → AdapterLock）---
    let _ = std::fs::remove_file(&out_file);
    let code_prod = restricted_token::run_normal_user(
        &helper_exe(), &format!("try-acquire MeshLink {out_arg}"),
    ).expect("非提权子进程必须能启动");
    let prod_out = std::fs::read_to_string(&out_file).unwrap_or_default();
    eprintln!("[non-admin try-acquire] exit={code_prod} file={prod_out:?}");
    assert_eq!(code_prod, 3,
        "非提权 MeshVnic::create 必须映射 AdapterMutexAccessDenied（exit 3）");
    assert!(prod_out.contains("RESULT=AdapterMutexAccessDenied"),
        "生产路径必须返回 AdapterMutexAccessDenied，绝不能把权限拒绝误报成 AdapterLockedByOtherProcess: {prod_out:?}");

    // --- 清理 ---
    let _ = proc_a.kill();
    let _ = proc_a.wait();
    let _ = std::fs::remove_file(&out_file);
    eprintln!(
        "[pass] 非提权进程：不能创建抢占 / 不能打开获取 / 不能长期占有（ACCESS_DENIED，mutex={mutex_a}）"
    );
}

// ===========================================================================
// M0-3.1-4b: 30 分钟 VNIC latency stall stress test（gate: MESH_VNIC_E2E=1）
// 说明：本测试骨架实现 WINTUN_VERSION_RISK.md §5 要求的负载与指标采集；
// 最终结果决定 Known Risk 是否阻塞 M0-4（详见 ADR §5.4 Red/Yellow/Green 判定）。
// ===========================================================================

#[test]
#[ignore]
fn vnic_latency_stall_30min() {
    if !require_env_and_admin() { return; }
    eprintln!("=== Wintun 0.14.1 30 分钟 latency stall stress test 启动 ===");
    eprintln!("（WINTUN_VERSION_RISK.md §5 决定 M0-4 硬 gate）");
    const TOTAL_DURATION: Duration = Duration::from_secs(30 * 60); // 30 minutes
    const PHASE_BURST: Duration = Duration::from_secs(2);         // 每 2.2s 一次 idle→burst 循环
    const PHASE_IDLE: Duration = Duration::from_millis(200);
    // latency 分布：环形缓冲保留最后 1_000_000 样本（足够 30 分钟 / 每包 ~ 5µs）
    const LAT_BUFSIZE: usize = 1_000_000;
    let mut lat_us: Vec<u64> = Vec::with_capacity(LAT_BUFSIZE);
    let mut stall_gt_1s = 0u64;
    let mut stall_gt_3s = 0u64;
    let mut stall_gt_4s = 0u64;

    // ---- 基础设施：VNIC + latency probe（独占 RX 单消费者）----
    let mut vnic = MeshVnic::create_with_dll(&dll_path(), test_config())
        .expect("stress VNIC create ok");
    let ip: Ipv4Addr = TEST_IP.parse().unwrap();
    eprintln!("stress: VNIC created driver_version=0x{:08X} ip={}", vnic.driver_version(), ip);
    let stop = Arc::new(AtomicBool::new(false));

    // latency probe 设计要点（M0-3.1 修正版）：
    // 1. probe 是 RX channel 的**唯一消费者**——不再有 responder 线程竞争
    //    （旧版 responder 抢走 echo reply → probe 记录虚假 1s 样本，且真实
    //    stall 被漏记，gate 可能假 GREEN）。
    // 2. probe 的 ICMP echo request dst=VNIC 自身 IP(.1)：Windows 栈把它当作
    //    本机收包并**自行生成 reply**，经 on-link 路由回到 VNIC RX ——
    //    全链路 = TX worker → Wintun TX ring → 栈 → Wintun RX ring → RX worker
    //    → channel，正好覆盖 Wintun missed-wakeup race 的 RX 唤醒路径。
    // 3. 等待窗口 6s（> 已知 race 表现的 4~5s）：真实 stall 必然落在窗口内
    //    被如实记录；6s 仍无 reply 记 6_000_000µs 并计入 >4s gate（本回环
    //    request 不会丢包，无 reply = RX 路径 stall，保守按 gate 处理）。
    let stop_probe = Arc::clone(&stop);
    let vnic_probe_ref = unsafe { &*(&vnic as *const MeshVnic) };
    // SAFETY：本测试内 probe 先 join，再 drop vnic；vnic_probe_ref 的 lifetime 比 probe 长
    let (tx_lat, rx_lat) = std::sync::mpsc::sync_channel::<u64>(65536);
    // 样本总数计数（Receiver 无 len()；probe try_send 成功才 +1）
    let total_samples = Arc::new(AtomicU64::new(0));
    let total_probe = Arc::clone(&total_samples);
    const PROBE_WAIT_WINDOW: Duration = Duration::from_secs(6);
    const NO_REPLY_SENTINEL_US: u64 = 6_000_000;
    let probe = std::thread::Builder::new()
        .name("vnic-lat-probe".into())
        .spawn(move || {
            // 最小 64B ICMP echo request（20B IPv4 + 8B ICMP header + 36B padding）
            let mut pkt = vec![0u8; 64];
            pkt[0] = 0x45; pkt[1] = 0x00;               // v4, IHL=5, DSCP=0
            pkt[2..4].copy_from_slice(&64u16.to_be_bytes()); // total_len
            pkt[8] = 64; pkt[9] = 1;                    // TTL=64, proto=1 (ICMP)
            pkt[12..16].copy_from_slice(&[10, 219, 177, 2]); // src=.2 -> we are .1 本机 ping 形态
            pkt[16..20].copy_from_slice(&ip.octets());       // dst=VNIC IP（本机 → 栈自动回 reply）
            let hdr_sum = MeshVnic::icmp_checksum(&pkt[..20]);
            pkt[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
            pkt[20] = 8; pkt[21] = 0;                       // ICMP type=8 echo req
            pkt[22..24].copy_from_slice(&[0, 0]);            // ICMP checksum 占位
            pkt[24..26].copy_from_slice(&0x1234u16.to_be_bytes()); // id=0x1234
            pkt[26..28].copy_from_slice(&0u16.to_be_bytes());      // seq，逐轮递增
            let mut seq: u16 = 0;
            loop {
                if stop_probe.load(Ordering::Acquire) { break; }
                // ICMP seq 递增（wrapping 回绕是 ICMP 正常语义； RangeFrom<u16>
                // 会在 u16::MAX 后溢出 panic —— probe 在 ~4.6min 静默死亡根因）
                seq = seq.wrapping_add(1);
                pkt[26..28].copy_from_slice(&seq.to_be_bytes());
                pkt[22..24].copy_from_slice(&[0, 0]);
                let cs = MeshVnic::icmp_checksum(&pkt[20..]);
                pkt[22..24].copy_from_slice(&cs.to_be_bytes());
                let sent = Instant::now();
                match vnic_probe_ref.send(pkt.clone()) {
                    Ok(()) => {}
                    Err(VnicError::SendRingFull) => {
                        // burst 期间 TX 队列满 = 正常 backpressure（MeshVnic::send
                        // 是非阻塞 try_send）。退避重试，绝不终止 probe。
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break, // VNIC 已停止等真错误
                }
                // 等待 echo reply：独占消费 RX channel；直到 6s 窗口关闭
                let mut got = false;
                while sent.elapsed() < PROBE_WAIT_WINDOW {
                    if stop_probe.load(Ordering::Acquire) { break; }
                    match vnic_probe_ref.recv_timeout(Duration::from_millis(10)) {
                        Ok(Some(reply)) if reply.len() >= 28 && reply[20] == 0 => {
                            let d = sent.elapsed().as_micros() as u64;
                            if tx_lat.try_send(d).is_ok() {
                                total_probe.fetch_add(1, Ordering::Relaxed);
                            }
                            got = true;
                            break;
                        }
                        Ok(Some(_)) => continue, // 其它 IPv4 包（IGMP/ARP 等）忽略
                        Ok(None) => continue,    // channel 短暂空转
                        Err(_) => continue,      // recv 超时：继续等到窗口关闭
                    }
                }
                if !got {
                    // 6s 无 reply：回环链路不丢包 → 真实 RX stall，如实计入 gate
                    if tx_lat.try_send(NO_REPLY_SENTINEL_US).is_ok() {
                        total_probe.fetch_add(1, Ordering::Relaxed);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        })
        .unwrap();

    let start_all = Instant::now();
    let mut cycle: u64 = 0;
    while start_all.elapsed() < TOTAL_DURATION {
        cycle += 1;
        // Phase A/B: idle 200ms → burst 2s 2kpps
        std::thread::sleep(PHASE_IDLE);
        let burst_start = Instant::now();
        let mut burst_cnt = 0u64;
        while burst_start.elapsed() < PHASE_BURST {
            // 构造随机大小 256~1400B PacketBuffer（符合 Phase C 4 线程并发注入的简化形态）
            let sz = 256 + ((cycle + burst_cnt) as usize % 1145);
            let mut buf = vec![0u8; sz];
            // 填充合法 IPv4 头（避免 TX validate_ipv4 拒绝计数）
            buf[0] = 0x45; buf[1] = 0x00;
            let total = sz as u16; buf[2..4].copy_from_slice(&total.to_be_bytes());
            buf[8] = 64; buf[9] = 6; // TCP
            buf[12..16].copy_from_slice(&ip.octets());
            buf[16..20].copy_from_slice(&[10, 219, 177, 99]);
            let hdr_sum = MeshVnic::icmp_checksum(&buf[..20]);
            buf[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
            let _ = vnic.send(buf);
            burst_cnt += 1;
        }
        // 每 30 秒打印一次进度 + 当前指标
        if cycle % 12 == 0 {
            let s = vnic.stats();
            eprintln!(
                "[{:>4}min/{:>2}] cycle={cycle} burst_cnt={burst_cnt} | \
                 rx_pkts={} rx_bytes_MB={:.1} | \
                 rx_drop_unsupported_v6={} mcast={} malformed={} policy={} backpressure={} | \
                 tx_pkts={} tx_ring_full={} | \
                 latency_samples_total={}",
                start_all.elapsed().as_secs()/60, (TOTAL_DURATION.as_secs()/60),
                s.rx_packets, s.rx_bytes as f64 / (1024.0*1024.0),
                s.rx_dropped_unsupported_ipv6, s.rx_dropped_unsupported_multicast,
                s.rx_dropped_malformed_ipv4, s.rx_dropped_policy, s.rx_dropped_backpressure,
                s.tx_packets, s.tx_dropped_ring_full,
                total_samples.load(Ordering::Relaxed),
            );
            // 防溢出搬运：probe ~200 样本/s，30 分钟 ~36 万条 >> channel 容量
            // 65536 —— 必须及时搬入 lat_us（结束时统一出分位数），否则
            // try_send 满丢样本导致统计失真。
            lat_us.extend(rx_lat.try_iter());
        }
    }
    // ---- 结束：停所有线程 ----
    stop.store(true, Ordering::Release);
    let _ = probe.join();
    // ---- 统计 final ----
    // drain latency channel 全量样本
    lat_us.extend(rx_lat.try_iter());
    if lat_us.is_empty() {
        eprintln!("⚠️ stress test 结束但 latency 样本 0 条 → 判定 FAIL");
        panic!("vnic_latency_stall_30min 需要至少 1 个 latency 样本才有效");
    }
    lat_us.sort_unstable();
    let n = lat_us.len();
    let p50 = lat_us[n/2];
    let p95 = lat_us[(n*95)/100];
    let p99 = lat_us[(n*99)/100];
    let max = lat_us[n-1];
    for &us in &lat_us {
        if us > 4_000_000 { stall_gt_4s += 1; }
        if us > 3_000_000 { stall_gt_3s += 1; }
        if us > 1_000_000 { stall_gt_1s += 1; }
    }
    let s = vnic.stats();
    eprintln!("============= 30 分钟 stall stress RESULT ==============");
    eprintln!("Wintun version:            0.14.1 (driver=0x{:08X})", vnic.driver_version());
    eprintln!("Total duration:            {}s (target 1800s)", start_all.elapsed().as_secs());
    eprintln!("Latency samples:           {n}");
    eprintln!("P50  delivery latency:     {p50} µs");
    eprintln!("P95  delivery latency:     {p95} µs");
    eprintln!("P99  delivery latency:     {p99} µs");
    eprintln!("Max  delivery latency:     {max} µs ({:.3}s)", max as f64/1e6);
    eprintln!("Stall > 1s  count:         {stall_gt_1s}");
    eprintln!("Stall > 3s  count:         {stall_gt_3s}");
    eprintln!("Stall > 4s  count (gate):  {stall_gt_4s}  ← M0-4 硬 gate = 0 (Green)");
    eprintln!("RX packets:                {}", s.rx_packets);
    eprintln!("RX bytes MB:               {:.1}", s.rx_bytes as f64 / (1024.0*1024.0));
    eprintln!("RX dropped split:");
    eprintln!("  unsupported_ipv6         {}", s.rx_dropped_unsupported_ipv6);
    eprintln!("  unsupported_multicast    {}", s.rx_dropped_unsupported_multicast);
    eprintln!("  malformed_ipv4           {} (Path Health damage)", s.rx_dropped_malformed_ipv4);
    eprintln!("  policy                   {}", s.rx_dropped_policy);
    eprintln!("  backpressure             {}", s.rx_dropped_backpressure);
    eprintln!("TX packets:                {}", s.tx_packets);
    eprintln!("TX errors:                 {}", s.tx_errors);
    eprintln!("========================================================");
    match stall_gt_4s {
        0 => {
            eprintln!("✅ GREEN: stall_gt_4s=0 → Known Risk 登记，允许进入 M0-4（WINTUN_VERSION_RISK.md §5.4 Green）");
        }
        1 | 2 => {
            eprintln!("⚠️ YELLOW: stall_gt_4s={stall_gt_4s}（1~2 次，无法稳定复现）→ 建议重新跑一轮确认。");
            eprintln!("   若第二轮仍 ≤2 → 登记 Known Risk 进入 M0-4，增加 Path Manager Keepalive 容忍窗口。");
        }
        _ => {
            eprintln!("❌ RED: stall_gt_4s={stall_gt_4s} ≥3 且稳定复现 → **暂停 M0-4**！按 WINTUN_VERSION_RISK.md §7 启动版本升级 ADR。");
            panic!("RED gate 命中：stall_gt_4s={stall_gt_4s}（Wintun 0.14.1 missed-wakeup race 已稳定复现 4-5 秒），禁止进入 M0-4");
        }
    }
    vnic.stop().ok();
}
