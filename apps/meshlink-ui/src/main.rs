//! MeshLink 桌面客户端（Tauri 2 UI）。
//!
//! 规格三：网络功能（Controller/Identity/DirectLink/Noise/Overlay/Wintun）
//! 全部在 MeshAgentService 进程；本进程只做用户操作、状态展示、命令下发、
//! 事件接收（经 `\\.\pipe\MeshLink-Agent`）。
//!
//! M1-1：启动参数 `--invite <meshlink://invite/…|token>` 或自定义 URI 触发时，
//! 通过 `meshlink-invite` 事件把邀请透传给 webview（规格三：粘贴邀请 / 启动参数）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod ipc;
mod supervisor;

use tauri::{Emitter, Manager};

fn main() {
    let invite_arg: Option<String> = std::env::args().collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--invite")
        .and_then(|w| Some(w[1].clone()))
        .or_else(|| {
            // meshlink://invite/<token> 作为单个 argv 传入时。
            std::env::args().nth(1).filter(|a| a.starts_with("meshlink://"))
        });

    tauri::Builder::default()
        .manage(ipc::IpcState::new())
        .setup(move |app| {
            if let Some(value) = invite_arg {
                let _ = app.emit("meshlink-invite", serde_json::json!({ "value": value }));
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            ipc::agent_connect,
            ipc::ensure_agent_running,
            ipc::ipc_request,
            ipc::load_ui_config,
            ipc::save_controller_url,
            ipc::save_controller_config,
            ipc::get_controller_config,
            ipc::get_controller_default,
            ipc::read_log_files,
        ])
        .build(tauri::generate_context!())
        .expect("MeshLink UI 构建失败")
        .run(|app, event| {
            if matches!(event, tauri::RunEvent::Exit) {
                ipc::shutdown(&app.state::<ipc::IpcState>());
            }
        });
}
