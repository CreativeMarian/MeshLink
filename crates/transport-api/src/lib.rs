//! 传输层统一契约（文档 7.1 / 确认版 §2）。
//!
//! 解耦硬性规则：
//! - Overlay Router / Path Manager / Controller 只允许依赖本 crate 的类型，
//!   禁止出现 `if n2n` / `if cloudflare` / `if webrtc` 等具体实现判断。
//! - webrtc-rs 符号只允许存在于 directlink crate 内；n2n fork 符号只允许
//!   存在于 transport-n2n crate 内（CI 用 `cargo tree` 门禁检查）。

use async_trait::async_trait;
use mesh_common::{ErrorCode, MeshError};
use serde::{Deserialize, Serialize};
use std::time::Duration;

/// L3 IPv4 报文（Wintun 读到的原始字节，不含以太网帧头）。
/// 校验逻辑（版本号/长度/校验和透传）由 overlay-router 在收发边界执行。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4Packet {
    pub bytes: Vec<u8>,
}

/// 设备/对端唯一标识（与 Controller devices.id 一致，如 `dev_xxx`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

/// Supernode 唯一标识（如 `sn_hk_01`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SupernodeId(pub String);

/// 路径种类。PathKind 只描述"哪一类路径"，不绑定任何实现细节。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    DirectLink,
    N2nP2p,
    /// 经某个 Supernode 中继
    N2nRelay(SupernodeId),
    CloudflareRelay,
}

impl PathKind {
    /// 五级路径的默认优先级（文档 9.1）。数值越小越优先。
    /// 策略（PathPolicy）可改变该顺序，但此默认值与 schemas 保持一致。
    pub fn default_rank(&self) -> u8 {
        match self {
            Self::DirectLink => 1,
            Self::N2nP2p => 2,
            Self::N2nRelay(_) => 3, // Primary/Backup 由 Scheduler 的 priority 决定
            Self::CloudflareRelay => 5,
        }
    }
}

/// 候选端点（STUN 反射地址 / host 地址等）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
    /// host / server_reflexive / relay
    pub kind: String,
}

/// PeerHints：connect_peer 的发现信息，由 Controller（Peer Discovery / Candidate 交换）提供。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerHints {
    pub endpoints: Vec<Endpoint>,
    /// 对端设备静态公钥指纹（SHA256:...），用于 Noise IK 握手后的身份绑定校验
    pub static_key_fingerprint: Option<String>,
    /// 对端 overlay MAC（Controller 分配，设备生命周期稳定，见 schemas/identity/overlay_mac.md）
    pub overlay_mac: Option<[u8; 6]>,
}

/// 传输启动配置。实现内部自行解析 `params`，对外不暴露任何实现专有类型。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportConfig {
    /// provider 名称：directlink / n2n / cf-ws（仅用于日志与指标，不用于逻辑分支）
    pub name: String,
    pub params: serde_json::Value,
}

/// 健康快照（文档 9.4 健康分的输入）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthSnapshot {
    /// 综合健康分 0-100；90-100 Healthy / 70-89 Degraded / 40-69 Warning / 0-39 Critical
    pub score: u8,
    pub rtt_ms: Option<f64>,
    pub loss_pct: Option<f64>,
    pub jitter_ms: Option<f64>,
    /// ACK/数据停滞计数
    pub stall_events: u32,
    /// 进程/Socket 健康（Transport Health 权重项）
    pub transport_alive: bool,
}

/// 主动探测结果。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    pub ok: bool,
    pub rtt_ms: Option<f64>,
}

/// 路径信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathInfo {
    pub kind: PathKind,
    pub rtt_ms: Option<f64>,
    /// 本路径连续稳定时长（防抖：P2P 回切前须稳定 10s）
    pub stable_for: Duration,
    pub detail: String,
}

/// 传输统计。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub peer_count: u32,
}

/// 传输事件回流：Path Manager 依据事件驱动 Hard Failure 熔断与切换。
#[derive(Debug, Clone)]
pub enum TransportEvent {
    PeerReachable(PeerId, PathKind),
    PeerUnreachable(PeerId, PathKind, ErrorCode),
    HealthChanged(PeerId, HealthSnapshot),
    /// Fatal：进程崩溃/引擎不可恢复错误 → 立即 OPEN 对应熔断器（事件驱动，不等健康评分窗口）
    Fatal(ErrorCode),
}

/// 路径策略（文档 15.4 / 确认版 §2.4）。默认 DirectFirst。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathPolicy {
    DirectFirst,
    RelayFirst,
    LowestRtt,
    P2pOnly,
    ForceRelay,
}

/// 传输 Provider 统一接口（九方法，确认版 §2.1）。
///
/// 实现方：DirectLinkTransport / N2NTransport / CloudflareRelayTransport。
#[async_trait]
pub trait TransportProvider: Send + Sync {
    async fn start(&self, cfg: TransportConfig) -> Result<(), MeshError>;
    async fn stop(&self, timeout: Duration) -> Result<(), MeshError>;
    async fn connect_peer(&self, peer: PeerId, hints: PeerHints) -> Result<(), MeshError>;
    async fn disconnect_peer(&self, peer: PeerId) -> Result<(), MeshError>;
    /// 发送一个 L3 IPv4 报文（Overlay Router 从 Wintun 读到的原始载荷）
    async fn send_packet(&self, peer: PeerId, pkt: Ipv4Packet) -> Result<(), MeshError>;
    fn health(&self, peer: Option<PeerId>) -> HealthSnapshot;
    fn stats(&self) -> TransportStats;
    async fn probe(&self, peer: PeerId) -> ProbeResult;
    fn path_info(&self, peer: PeerId) -> Option<PathInfo>;

    /// 事件接收端注册（由 Overlay Router 注入 channel sender）。
    async fn subscribe_events(&self, tx: tokio::sync::mpsc::Sender<TransportEvent>);
}
