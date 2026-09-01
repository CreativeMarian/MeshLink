//! DirectLink 连通性子系统（M0-4）。
//!
//! 双轨对比（ADR-003 DIRECTLINK_ICE.md，命名必须准确）：
//! - Track B = **MinimalPunchAgent**（Purpose-built UDP Hole Punch Engine，
//!   STUN-assisted simultaneous open，**非** RFC 8445 ICE）：[`stun`] / [`candidate`] /
//!   [`agent`] / [`mtu`]
//! - Track A = **Standards-based ICE**（rtc-ice 0.20.4 封装）：[`webrtc_track`]——
//!   webrtc 符号只允许存在于本 crate（tests/gate_webrtc_boundary.rs 门禁）
//!
//! 硬性要求（两条轨都必须满足）：srflx STUN 查询、connectivity check / punch、
//! P2P payload、Keepalive **共用同一个 UDP socket**（NAT 映射按五元组分配，
//! 换 socket = 映射失效）。见 tests/single_socket_assertion.rs。
//!
//! 所有网络交互函数均为注入式（send/recvfrom 闭包），生产侧由
//! `crate::transport::DirectLinkTransport` 的 Dispatcher 接线，测试侧注入内存总线。

pub mod agent;
pub mod candidate;
pub mod ifinfo;
pub mod mtu;
pub mod stun;
pub mod webrtc_track;

pub use agent::{IceError, Keepalive, NatMapping, NatObservation, PunchConfig, PunchOutcome};
pub use candidate::{Candidate, CandidateKind, GatherError};
pub use mtu::{MtuError, MtuProbe};
pub use stun::StunError;
