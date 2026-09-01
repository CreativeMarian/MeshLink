//! MeshLink 本地 IPC（Overlay MVP 规格四）：
//!
//! UI（Tauri）与 MeshAgentService 之间的唯一通道——Windows Named Pipe
//! `\\.\pipe\MeshLink-Agent`，JSON Lines（每行一条消息，UTF-8，LF 结尾）。
//!
//! 安全边界：
//! - 管道创建时挂**显式 DACL**（当前用户 + SYSTEM，PROTECTED）——任意低权限
//!   进程无法连接（无法读事件 / 下发连接、断开、邀请、网络配置命令）；
//! - 本 crate 不含任何密钥 / credential 逻辑：UI 进程依赖本 crate 只能通过
//!   命令/事件与 Agent 通信（`ui_process_does_not_receive_private_key` 的
//!   结构性保证）。
//!
//! 协议（mesh-ipc 是纯协议层，data 载荷为 JSON Value，由 mesh-agent 构造）：
//! - 请求：`{"id":1,"cmd":"JoinQuickSession","code":"482731"}`
//! - 响应：`{"id":1,"ok":true,"data":{...}}` / `{"id":1,"ok":false,"error":{"code":"...","message":"..."}}`
//! - 事件：`{"event":"Punching","data":{...}}`（Agent → UI 单向推送）

pub mod client;
pub mod proto;
pub mod server;

pub use client::PipeClient;
pub use proto::{Command, Event, IpcError, Request, Response, ServerMessage};
pub use server::{spawn_server, PipeServerHandle, RequestHandler};

use std::sync::atomic::{AtomicU64, Ordering};

/// 由 UI 层 (cmd, payload) 构造 IPC `Request`——Tauri GUI 桥接 `ipc_request`
/// 与 GUI Bridge 集成测试**共用同一条** wire 构造路径（用户规格四：
/// 测试必须从 bridge 层进入 Agent IPC，禁止直连 AgentCore 绕过 UI bridge）。
///
/// 注意：**不**直接反序列化 `Request`（其 `id` 字段对调用方不可见）；
/// 仅反序列化内部标签 `Command`（`{"cmd": ...}` + payload 展平字段），
/// 再由本桥生成递增 id。payload 非对象时忽略。
///
/// Request id 规则（协议硬化，用户规格）：
/// - `id = 0` 为 **RESERVED / INVALID**，Agent 侧收到即回 `IPC_INVALID_REQUEST_ID`
///   且不进入正常 response correlation；
/// - 本函数保证返回 id **永不为 0 且严格递增**：即使调用方误把 `next_id`
///   初始化为 0，也会强制跳过首个 0。
pub fn build_request(
    next_id: &AtomicU64,
    cmd: &str,
    payload: Option<&serde_json::Value>,
) -> Result<Request, String> {
    let mut v = serde_json::json!({ "cmd": cmd });
    if let Some(extra) = payload.as_ref().and_then(|p| p.as_object()) {
        let obj = v.as_object_mut().unwrap();
        for (k, val) in extra {
            obj.insert(k.clone(), val.clone());
        }
    }
    let command: Command = serde_json::from_value(v).map_err(|e| format!("命令非法：{e}"))?;
    let mut id = next_id.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        // next_id 被误初始化为 0 的边角：跳过 id=0（已 fetch 到 1，返回 1，
        // 下一个 fetch 返回 2 → 仍严格递增、无碰撞）。
        id = next_id.fetch_add(1, Ordering::Relaxed);
    }
    Ok(Request { id, command })
}

/// 默认管道名（用户规格四：`\\.\pipe\MeshLink-Agent`）。
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\MeshLink-Agent";

/// 全局唯一默认 Controller 地址（用户规格二：单一 Default）。
/// 必须与 Go controller DefaultAddr（127.0.0.1:18080）保持一致——
/// 任何改动需同步两端，并由 default_port_alignment 集成测试拦截漂移。
/// mesh-agent 与 meshlink-ui 均从本常量取值，禁止在各自 crate 再硬编码。
pub const DEFAULT_CONTROLLER_URL: &str = "http://127.0.0.1:18080";

/// 单行消息上限（防内存攻击；正常命令/事件远小于此）。
pub const MAX_LINE_LEN: usize = 1 << 20;
