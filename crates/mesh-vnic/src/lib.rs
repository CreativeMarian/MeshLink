//! Wintun 虚拟网卡抽象（M0-3）。
//!
//! 生命周期硬性规则（确认版 §1）：
//! - Wintun 由 MeshAgentService 独占持有；N2N/SN/CF/Controller 任何故障
//!   都不得导致 Wintun 退出或虚拟 IP 变化。
//! - 本 crate 是系统唯一与 wintun.dll 交互的位置。
//!
//! 分层（M0-3 要求四）：`api` / `adapter` / `session` / `ip_config` 全部私有，
//! Wintun FFI 不外泄。上层（mesh-agent / overlay-router / directlink /
//! transport-n2n）只允许使用 [`MeshVnic`] 门面与配套类型。

mod adapter;
mod api;
mod error;
mod ip_config;
mod packet;
mod session;
mod vnic;

pub use error::VnicError;
pub use packet::{
    icmp_checksum, icmp_echo_reply, PacketBuffer, PacketDisposition, PacketInfo,
    PacketRejectReason,
};
pub use vnic::{MeshVnic, VnicConfig, VnicStats};
