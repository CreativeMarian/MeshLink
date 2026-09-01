//! n2n-supernode：真实 N2N Supernode 独立进程（M1-2 Gate：真实 N2N Supernode process）。
//!
//! 无参数启动默认监听 127.0.0.1:7654；打印就绪行
//! `N2N_SUPERNODE_READY <sn_id> <bind_addr>` 供测试探测。

use std::net::SocketAddr;
use transport_n2n::{N2NSupernode, SupernodeConfig};

fn parse_addr(v: &str, default_port: u16) -> Result<SocketAddr, String> {
    if let Ok(a) = v.parse::<SocketAddr>() {
        return Ok(a);
    }
    if let Ok(ip) = v.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, default_port));
    }
    // host:port
    let mut parts = v.rsplitn(2, ':');
    let port = parts.next().ok_or("地址格式错误")?.parse::<u16>().map_err(|e| e.to_string())?;
    let host = parts.next().ok_or("地址格式错误")?;
    let ip: std::net::IpAddr = host.parse().map_err(|e: std::net::AddrParseError| e.to_string())?;
    Ok(SocketAddr::new(ip, port))
}

fn main() {
    let mut sn_id = "sn-local".to_string();
    let mut bind = "0.0.0.0:7654".to_string();
    let mut community_ttl_ms: u64 = 60_000;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--id" => sn_id = args.next().unwrap_or_default(),
            "--listen" | "-l" => bind = args.next().unwrap_or_default(),
            "--ttl-ms" => community_ttl_ms = args.next().and_then(|v| v.parse().ok()).unwrap_or(60_000),
            "--help" | "-h" => {
                println!("usage: n2n-supernode [--id sn-local] [--listen 0.0.0.0:7654] [--ttl-ms 60000]");
                return;
            }
            other => {
                eprintln!("未知参数: {other}");
                std::process::exit(2);
            }
        }
    }
    let addr = match parse_addr(&bind, 7654) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("监听地址非法 {bind}: {e}");
            std::process::exit(2);
        }
    };
    let cfg = SupernodeConfig {
        sn_id,
        bind_addr: addr,
        member_ttl: std::time::Duration::from_millis(community_ttl_ms),
    };
    let sn = match N2NSupernode::bind(cfg) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Supernode 启动失败: {e}");
            std::process::exit(1);
        }
    };
    // 就绪行（stdout 行缓冲刷新——测试轮询就绪用）
    println!("N2N_SUPERNODE_READY {} {}", sn.state().sn_id, sn.local_addr());
    use std::io::Write;
    let _ = std::io::stdout().flush();
    // 保持进程存活
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}
