//! MeshAgentService 入口（Overlay MVP 规格三）。
//!
//! 网络/身份/密钥/UDP socket 全部由本进程独占；Tauri UI 仅经
//! `\\.\pipe\MeshLink-Agent`（mesh-ipc，显式 DACL）下发命令、接收事件。
//!
//! 配置（环境变量，生产由服务安装器/启动参数覆盖）：
//! - `MESHLINK_CONTROLLER_URL`：DEV `http://127.0.0.1:18080`（默认）；
//!   PROD 必须 `https://…`（controller-client scheme 白名单强制，无降级）。
//! - `MESHLINK_OVERLAY`：`wintun`（默认）| `mock`（自动化测试）。
//! - `MESHLINK_DATA_DIR`：设备身份持久化目录（默认 %LOCALAPPDATA%\MeshLink\agent）。
//! - `MESHLINK_PIPE_NAME`：IPC 管道名（默认 `\\.\pipe\MeshLink-Agent`）。

use mesh_agent::{spawn_service, AgentConfig, OverlayKind};
use std::time::Duration;

fn main() {
    let log_level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into());
    mesh_common::logging::init_logging(&log_level, false);

    let mut cfg = AgentConfig::default();
    if let Ok(url) = std::env::var("MESHLINK_CONTROLLER_URL") {
        cfg.controller_url = url;
    }
    if let Ok(dir) = std::env::var("MESHLINK_DATA_DIR") {
        cfg.data_dir = dir.into();
    }
    if let Ok(dir) = std::env::var("MESHLINK_RUNTIME_DIR") {
        cfg.runtime_dir = dir.into();
    }
    if let Ok(name) = std::env::var("MESHLINK_DEVICE_NAME") {
        cfg.device_name = Some(name);
    }
    if let Ok(kind) = std::env::var("MESHLINK_OVERLAY") {
        cfg.overlay = match kind.as_str() {
            "mock" => OverlayKind::Mock,
            _ => OverlayKind::Wintun,
        };
    }
    if let Ok(stun) = std::env::var("MESHLINK_STUN") {
        cfg.stun_servers = stun
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }
    let pipe = std::env::var("MESHLINK_PIPE_NAME")
        .unwrap_or_else(|_| mesh_ipc::DEFAULT_PIPE_NAME.into());

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        controller = %cfg.controller_url,
        overlay = if cfg.overlay == OverlayKind::Mock { "mock" } else { "wintun" },
        pipe = %pipe,
        "MeshAgentService 启动"
    );

    let (agent, server) = match spawn_service(cfg, &pipe) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "MeshAgentService 启动失败");
            std::process::exit(1);
        }
    };
    tracing::info!(pipe = %server.pipe_name(), "IPC 管道服务已就绪，等待 UI 命令");

    // 阻塞主线程直到 shutdown（Windows 服务管理器/任务栏托盘将发送停止信号）。
    loop {
        if agent.is_stopped() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    server.stop();
    tracing::info!("MeshAgentService 已退出");
}
