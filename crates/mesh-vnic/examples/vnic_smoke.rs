//! mesh-vnic 实机冒烟工具（M0-3i）。
//!
//! 用途：
//! 1. 手动验证：`vnic_smoke.exe` —— 创建 VNIC 并回送 ICMP Echo Reply，
//!    此时从系统 `ping 10.219.177.2`（对端伪 IP）验证双向通路；Ctrl+C 优雅退出。
//! 2. Crash Recovery 测试子进程：`vnic_smoke.exe --hold` —— 创建后打印
//!    `READY luid=0x...` 并永久驻留，供测试进程 kill 模拟进程崩溃。
//!
//! 仅用于开发/验收；生产入口是 MeshAgentService。

use mesh_vnic::{MeshVnic, VnicConfig};
use std::time::Duration;

const DLL_REL: &str = r"..\..\third_party\wintun\bin\amd64\wintun.dll";

fn test_config() -> VnicConfig {
    let p = config_manager::VnicParams {
        virtual_ip: "10.219.177.1".into(),
        overlay_cidr: "10.219.177.0/24".into(),
        ..Default::default()
    };
    VnicConfig::from_params(&p).expect("测试配置必须合法")
}

fn dll_path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(DLL_REL)
}

fn main() {
    // 极简订阅器：tracing 走 stderr，stdout 只留协议行（READY/SMOKE_DONE）
    tracing_subscriber::fmt()
        .with_target(true)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(std::io::stderr)
        .init();

    let hold = std::env::args().any(|a| a == "--hold");
    let quick = std::env::args().any(|a| a == "--quick");
    let mut vnic = match MeshVnic::create_with_dll(&dll_path(), test_config()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("CREATE_FAILED: {e}");
            std::process::exit(1);
        }
    };
    println!(
        "READY luid=0x{:X} driver=0x{:X}",
        vnic.luid().unwrap_or(0),
        vnic.driver_version()
    );

    // 诊断：枚举本机地址 / 本机路由（复现 E2E 第一个用例崩溃位置）
    match MeshVnic::local_ipv4_addresses() {
        Ok(addrs) => println!("ADDRS n={}", addrs.len()),
        Err(e) => println!("ADDRS_ERR: {e}"),
    }
    match vnic.routes_via_self() {
        Ok(r) => println!("ROUTES n={}: {:?}", r.len(), r),
        Err(e) => println!("ROUTES_ERR: {e}"),
    }

    if hold {
        // Crash 测试模式：驻留直到被外部 kill（模拟进程崩溃，无清理路径）
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }

    // 诊断二分：如果 quick 且 --bailout-after-routes，不跑收发 worker，直接停
    let bailout = std::env::args().any(|a| a == "--bailout");
    if bailout {
        println!("BAILOUT_BEFORE_LOOP");
        match vnic.stop() { Ok(()) => println!("STOP_OK"), Err(e) => println!("STOP_ERR: {e}") }
        println!("SMOKE_BAILOUT_DONE stats={:?}", vnic.stats());
        return;
    }

    // 诊断二分：--no-loop 只 sleep（保留 worker 存活），不收发。
    let no_loop = std::env::args().any(|a| a == "--no-loop");

    // 冒烟模式：ICMP Echo Responder，Ctrl+C 触发 Drop/stop
    let secs = if quick { 2 } else { 3600 };
    if no_loop {
        println!("NO_LOOP_SLEEP_{secs}s");
        std::thread::sleep(Duration::from_secs(secs));
    } else {
        let deadline = std::time::Instant::now() + Duration::from_secs(secs);
        while std::time::Instant::now() < deadline {
            match vnic.recv_timeout(Duration::from_millis(200)) {
                Ok(Some(pkt)) => {
                    let _ = vnic.send_icmp_echo_reply_for(&pkt);
                }
                Ok(None) => continue,
                Err(e) => {
                    eprintln!("RECV_ERR: {e}");
                    break;
                }
            }
        }
    }
    match vnic.stop() {
        Ok(()) => println!("STOP_OK"),
        Err(e) => println!("STOP_ERR: {e}"),
    }
    // 再次枚举（复现 E2E 停止后不残留断言路径）
    let remain = MeshVnic::local_ipv4_addresses().map(|a| a.len()).unwrap_or(0);
    println!("POST_STOP_ADDRS_N={remain}");
    println!("SMOKE_DONE stats={:?}", vnic.stats());
}
