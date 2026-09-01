//! DirectLink 独立 P2P 引擎（M0-4 / M0-5 实现）。
//!
//! 边界硬性规则：
//! - webrtc-rs（Track A）符号只允许出现在本 crate 内，禁止导出到上层
//!   （`tests/gate_webrtc_boundary.rs` cargo tree 门禁强制）。
//! - 对外只暴露 transport-api::TransportProvider 实现与本 crate 自有类型。
//!
//! 模块布局：
//! - ice:      M0-4 双轨对比——Track B 自研精简（stun/candidate/agent/mtu）
//!             + Track A webrtc-rs 封装（webrtc_track），产出 ADR DIRECTLINK_ICE.md
//! - transport: DirectLinkTransport（Track B 接线：Dispatcher + TransportProvider）
//! - crypto:   M0-5 Noise_IK（snow StatelessTransportState）+ 防重放 + 重握手
//! - session:  会话管理、RTT/Loss/Jitter 测量（与 transport 合并演进）

pub mod crypto;
pub mod ice;
pub mod transport;

pub use transport::{DirectLinkParams, DirectLinkTransport};

pub mod placeholder {
    pub const TASK_CRYPTO: &str = "M0-5: Noise_IK + ChaCha20-Poly1305 + anti-replay + rekey";
}
