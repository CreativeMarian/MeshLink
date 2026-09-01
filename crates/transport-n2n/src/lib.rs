//! transport-n2n：MeshLink 第二个独立 TransportProvider（M1-2 N2N + Supernode）。
//!
//! 架构（用户规格 M1-2 硬规则）：
//! ```text
//! MeshLink Wintun
//!      ↓
//! Overlay Router
//!   ├─ DirectLinkProvider   （crates/directlink，已验收）
//!   └─ N2NProvider          （本 crate）
//! ```text
//! - 锁定 N2N 3.0 baseline：本仓库以 Rust 实现 N2N 3.0 线协议
//!   （REGISTER_SUPER / QUERY_PEER / PUNCH / PACKET + 社区模型 + 社区层
//!   AES-256-GCM），不依赖官方 C 二进制（环境无 cmake/gcc 编译链）。
//! - **无第二 TAP**：N2NProvider 不创建任何网卡，帧全部经 TransportProvider
//!   trait 与内存通道流转。
//! - N2N 不管理 Overlay IP、不修改系统 Route/DNS；Wintun 仍归 Agent 管理。
//! - MeshLink Noise（directlink::crypto 复用）身份认证与加密必须继续存在；
//!   Supernode 不持有社区密钥，只能路由密文帧（看不到 Noise 密文/明文 Overlay）。
//!
//! 模块：
//! - `proto`：N2N 3.0 线协议 + 社区层 AES-256-GCM；
//! - `supernode`：N2NSupernode（嵌入式库 + `n2n-supernode` 独立进程）；
//! - `n2n_transport`：N2NTransport（TransportProvider 实现 + Agent 会话 API）。

pub mod n2n_transport;
pub mod proto;
pub mod supernode;

pub use n2n_transport::{N2NParams, N2NTransport, SupernodeEndpoint};
pub use supernode::{N2NSupernode, SupernodeConfig, SupernodeStats};

pub mod placeholder {
    pub const TASK_BASELINE: &str = "M1-2: N2N 3.0 baseline（Rust 实现）+ Supernode Registry + Force DirectLink/N2N";
}
