//! MeshAgentService（用户规格三/九/十二）：
//!
//! 后台服务整合 Controller Client / Device Identity / DirectLink / Noise /
//! Overlay(Wintun|Mock) / 最小路由，经 mesh-ipc Named Pipe 对 UI 暴露
//! 9 命令 / 10 事件。
//!
//! 架构硬性规则（规格三）：
//! - Tauri UI 不直接操作 Wintun / 持有 Noise 私钥 / 持有 Controller credential /
//!   打开 DirectLink UDP socket——全部由本服务独占；
//! - 状态机唯一权威在 Agent（规格九：UI 不推断状态，只显示 Agent 事件）；
//! - Connected 事件只在规格十二的 8 个条件全部满足后发出。

pub mod agent;
pub mod icmp;
pub mod overlay;
pub mod runtime;
pub mod state;

pub use agent::{spawn_service, AgentConfig, AgentHandle, OverlayKind};
pub use overlay::{MockOverlay, OverlayBackend, OverlayConfig, WintunOverlay};
pub use runtime::RuntimeState;
pub use state::{AgentState, PeerView, SessionSnapshot, StatusSnapshot};
