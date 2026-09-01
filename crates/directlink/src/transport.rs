//! DirectLinkTransport：`transport-api::TransportProvider` 的 DirectLink 实现（Track B）。
//!
//! 架构（M0-4 PoC，ADR DIRECTLINK_ICE.md）：
//! ```text
//! ┌─ async (TransportProvider 九方法) ──┐   ┌─ Dispatcher 线程（单 socket 独占 recvfrom）─┐
//! │ connect_peer → spawn_blocking(punch)│   │ STUN Request  → 立即回应（server 角色）      │
//! │ send_packet  → socket.send_to       │   │ STUN Response → outstanding[txid]/未匹配队列 │
//! │ probe/health ← outstanding 队列     │←─│ MTU echo      → mtu 队列                     │
//! └─────────────────────────────────────┘   │ IPv4 数据     → session rx channel           │
//!                                            └──────────────────────────────────────────────┘
//! ```
//! 帧分派规则（单 socket 复用）：
//! 1. 可解码为 STUN（magic cookie 校验）→ 按上表；
//! 2. `[0x4D54][len][payload]` → MTU echo（ice::mtu 同构）；
//! 3. `[0x4D44][ver][flags]...` → Noise 帧（M0-5：握手 / 加密数据，见 crypto::frame；
//!    首字节 0x4D 与 IPv4 版本位重叠，**必须先于** IPv4 分派判断）；
//! 4. 其余按 IPv4 数据帧（长度 ≥20 且版本号 4）→ session rx（M0-4 未握手兼容路径）。

use crate::crypto::{self, CryptoPolicy, NoiseChannel, RecvOutcome, Role, StaticIdentity};
use crate::ice::agent::{check_request_attrs, check_response, probe_nat_mapping_with, punch_with, Keepalive, NatMapping, NatObservation, PunchConfig, PunchOutcome};
use crate::ice::candidate::{gather_host_candidates, primary_local_ipv4, Candidate, CandidateKind};
use crate::ice::mtu::{probe_mtu_with, MtuProbe};
use crate::ice::stun::{binding_exchange_with, new_txid, StunMessage};
use async_trait::async_trait;
use mesh_common::{ErrorCode, MeshError};
use std::cell::Cell;
use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc as std_mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use transport_api::{
    Endpoint, HealthSnapshot, Ipv4Packet, PathInfo, PathKind, PeerHints, PeerId, ProbeResult,
    TransportConfig, TransportEvent, TransportProvider, TransportStats,
};

/// MTU echo 帧魔数（与 ice::mtu 模块一致；pub(crate) 供 crypto::frame 单测断言互斥）
pub(crate) const MTU_MAGIC: [u8; 2] = [0x4D, 0x54];

/// M0-5 加密帧发送缓冲初始容量（头部 32 + AEAD tag 16 + 常规负载）
const FRAME_WIRE_CAP: usize = 1600;

/// `directlink.params` JSON 配置。
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct DirectLinkParams {
    pub listen_port: u16,
    pub stun_servers: Vec<String>,
    pub punch_window_ms: u64,
    pub punch_rto_ms: u64,
    pub punch_retries: u32,
    pub keepalive_interval_ms: u64,
    pub keepalive_miss_limit: u32,
    pub mtu_ladder: Vec<u16>,
    /// M0-5：Noise 握手/重握手策略
    pub crypto: CryptoPolicy,
}

impl Default for DirectLinkParams {
    fn default() -> Self {
        Self {
            listen_port: 0,
            stun_servers: vec!["stun.l.google.com:19302".into(), "stun.cloudflare.com:3478".into()],
            punch_window_ms: 5000,
            punch_rto_ms: 200,
            punch_retries: 1,
            keepalive_interval_ms: 15_000,
            keepalive_miss_limit: 3,
            // M0-4 Final Gate：用户指定阶梯（1200~1450），覆盖典型 PMTU 与隧道开销；
            // 最终 Overlay MTU 在 M0-7 决定，不因一次测试写死
            mtu_ladder: vec![1200, 1280, 1300, 1350, 1400, 1450],
            crypto: CryptoPolicy::default(),
        }
    }
}

/// 等待者队列（STUN 响应 / MTU echo 投递目标）。
/// 用 std mpsc：Sender 可 Clone（多请求共享一个响应队列），且消费端在
/// spawn_blocking/keepalive 线程里用 `recv_timeout` 同步等待。
type WaiterTx = std_mpsc::Sender<(SocketAddrV4, Vec<u8>)>;

fn waiter_recv(rx: &std_mpsc::Receiver<(SocketAddrV4, Vec<u8>)>, timeout: Duration) -> Option<(SocketAddrV4, Vec<u8>)> {
    rx.recv_timeout(timeout).ok()
}

/// 单 peer 会话。
struct PeerSession {
    remote: SocketAddrV4,
    /// 选定对端候选的类型（host/srflx；punch 命中的 peer_cands 类型，未知来源 = prflx）
    remote_kind: CandidateKind,
    /// 数据帧发送端（dispatcher 投递目标；M0-5 = 解密后明文）
    rx_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// 数据帧接收端（单消费者，`packet_rx` 取走）
    rx_rx: Mutex<Option<mpsc::UnboundedReceiver<Vec<u8>>>>,
    keepalive: Mutex<Option<Keepalive>>,
    last_rtt: Arc<Mutex<Option<Duration>>>,
    /// 路径稳定起点（防抖输入）
    since: std::time::Instant,
    path_mtu: Arc<Mutex<Option<u16>>>,
    /// M0-5：该 peer 的 Noise 加密通道（握手完成后填充；None = 未加密兼容路径）
    channel: Arc<Mutex<Option<NoiseChannel>>>,
    /// 双向身份验证（用户规格二）：responder 侧 msg1 校验用的对端（initiator）
    /// 静态公钥——来自 Controller Device Registry / session members 快照。
    /// None = PoC 遗留路径（无注册表，不校验 initiator 密钥）。
    expected_initiator: Mutex<Option<[u8; 32]>>,
}

#[derive(Default)]
struct Stats {
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    punch_failures: AtomicU64,
    /// M0-5 收尾：msg1 状态机拒绝数（epoch 回退/跳变、session 不匹配、无会话）
    noise_msg1_rejected: AtomicU64,
}

struct Running {
    socket: Arc<UdpSocket>,
    local_base: SocketAddrV4,
    host_cands: Vec<Candidate>,
    /// start 后异步填充（需 dispatcher 先行运转以路由响应）
    srflx: Mutex<Vec<Candidate>>,
    sessions: Mutex<HashMap<PeerId, PeerSession>>,
    params: DirectLinkParams,
    started: std::time::Instant,
    dispatcher_stop: Arc<AtomicBool>,
    dispatcher: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// STUN 响应等待者（txid → 队列）：probe / keepalive / srflx 注册
    /// （Arc：connect_peer 需克隆进 keepalive 闭包）
    outstanding: Arc<Mutex<HashMap<[u8; 12], WaiterTx>>>,
    /// 无主 STUN 响应（punch/nat-mapping 内部生成 txid）→ 匹配队列
    unmatched_stun: Mutex<Option<WaiterTx>>,
    /// MTU echo 队列
    mtu_waiter: Mutex<Option<WaiterTx>>,
    /// punch 串行化（PoC：同一时刻只允许一个打洞会话占用 unmatched 队列）
    punch_lock: Mutex<()>,
    /// accept 模式（PoC create 端）：等待被 join 端打洞接入的 peer（来自第一个
    /// BINDING_REQUEST 来源）；None = 纯 dial 模式，收到的请求仅回应不建会话
    accept_peer: Mutex<Option<PeerId>>,
    /// M0-4 双向 punch 修正：accept 模式的 session-scoped tag
    /// （`meshlink-poc:{session_id}:{nonce}`）——dispatcher 只建会话于精确匹配的
    /// probe（§四：不允许退回全局 USERNAME 匹配）。与 accept_peer 同生命周期。
    accept_tag: Mutex<Option<String>>,
    /// join 端 punch 请求的 USERNAME（set_punch_session 设置；默认全局 tag 兼容单测）
    punch_tag: Mutex<String>,
    /// join 端随 punch 请求携带的本端候选集（双向 punch 的 candidate exchange 逆向通道）
    self_cands: Mutex<Vec<crate::ice::stun::CandidateWire>>,
    /// M0-4R.2 §三：simultaneous punch 时间证据（诊断字段，随 result 输出）
    punch_evidence: Arc<PunchEvidence>,
    /// M0-5：Noise responder 配置（creator 侧 msg1 到达前须 configure_noise）
    noise_cfg: Mutex<Option<NoiseCfg>>,
    /// M0-5：msg2 等待者（initiator 侧握手 / rekey；单 slot，PoC 单 peer 场景）
    noise_waiter: Mutex<Option<WaiterTx>>,
    /// Controller-era 双向验证（用户规格二）：预置 initiator 公钥表。
    /// **会话未建立（punch 未发生）时也可登记**——`set_expected_initiator`
    /// 写入此处，msg1 处理时按 peer 取用。修复竞态：此前仅写 session 字段，
    /// 而 session 在 punch probe 到达才创建，登记往往被静默丢弃。
    expected_keys: Mutex<HashMap<PeerId, [u8; 32]>>,
    /// 严格模式：该 peer 的 msg1 在预置公钥缺失时**拒绝**（而非放行不校验）。
    /// initiator 握手自带重试（同字节串重传），等待 creator 侧登记后重试成功。
    require_initiator: Mutex<Option<PeerId>>,
    stats: Arc<Stats>,
}

/// M0-5：本端 Noise 身份与 prologue network_id。
#[derive(Clone)]
struct NoiseCfg {
    identity: Arc<StaticIdentity>,
    network_id: String,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.dispatcher_stop.store(true, Ordering::Release);
        self.sessions.lock().unwrap().clear();
        if let Some(h) = self.dispatcher.lock().unwrap().take() {
            let _ = h.join();
        }
    }
}

/// DirectLink 传输 Provider（Track B 精简 ICE）。
pub struct DirectLinkTransport {
    running: Mutex<Option<Arc<Running>>>,
    events: Mutex<Option<mpsc::Sender<TransportEvent>>>,
}

impl Default for DirectLinkTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectLinkTransport {
    pub fn new() -> Self {
        Self { running: Mutex::new(None), events: Mutex::new(None) }
    }

    /// M0-4 PoC：无加密数据帧接收端（M0-5 换 Noise 帧后由解密层取代）。
    /// 单消费者：取走后不再重复提供。
    pub fn packet_rx(&self, peer: &PeerId) -> Option<mpsc::UnboundedReceiver<Vec<u8>>> {
        let running = self.running.lock().unwrap().clone()?;
        let mut sessions = running.sessions.lock().unwrap();
        let s = sessions.get_mut(peer)?;
        let mut slot = s.rx_rx.lock().unwrap();
        slot.take()
    }

    /// NAT 映射观测（两个不同 IP 的 STUN server 可做保守二分类；单 server 只记
    /// Observed Mapping 明细，分类保守 Unknown——禁止用一次查询宣称 NAT 行为）。
    pub async fn nat_mapping(&self) -> Option<NatObservation> {
        let running = self.running.lock().unwrap().clone()?;
        let servers = resolve_servers(&running.params.stun_servers);
        let running2 = running.clone();
        tokio::task::spawn_blocking(move || {
            let _guard = running2.punch_lock.lock().unwrap();
            let (tx, rx) = std_mpsc::channel();
            *running2.unmatched_stun.lock().unwrap() = Some(tx);
            let observation = if servers.len() >= 2 {
                let [s1, s2] = [servers[0], servers[1]];
                probe_nat_mapping_with(
                    [s1, s2],
                    // 修复：必须按事务目的地址发送——曾固定发第一个 server，
                    // 第二个观测永远超时 → Unknown（ADR-003 §已知修复）
                    |buf, to| running2.socket.send_to(buf, to),
                    |timeout| waiter_recv(&rx, timeout),
                    Duration::from_millis(500),
                    2,
                )
            } else if let Some(s1) = servers.first().copied() {
                // 单 server：仅记 Observed Mapping（Final Gate §五：不做 NAT 分类）
                match binding_exchange_with(
                    new_txid(),
                    s1,
                    |buf| running2.socket.send_to(buf, s1),
                    |timeout| waiter_recv(&rx, timeout),
                    Duration::from_millis(500),
                    2,
                ) {
                    Ok(r) => NatObservation { classification: NatMapping::Unknown, observed: vec![(s1, r.mapped)] },
                    Err(_) => NatObservation { classification: NatMapping::Unknown, observed: Vec::new() },
                }
            } else {
                *running2.unmatched_stun.lock().unwrap() = None;
                return NatObservation { classification: NatMapping::Unknown, observed: Vec::new() };
            };
            *running2.unmatched_stun.lock().unwrap() = None;
            observation
        })
        .await
        .ok()
    }

    /// 对指定 peer 发起 MTU 阶梯探测（需已 connect）。
    pub async fn probe_mtu(&self, peer: &PeerId) -> Result<MtuProbe, MeshError> {
        let running = self
            .running
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| MeshError::from(ErrorCode::TransportStartFailed))?;
        let (remote, path_mtu, ladder) = {
            let sessions = running.sessions.lock().unwrap();
            let s = sessions
                .get(peer)
                .ok_or_else(|| MeshError::new(ErrorCode::TransportPeerUnreachable, format!("{peer:?} 未连接")))?;
            (s.remote, s.path_mtu.clone(), running.params.mtu_ladder.clone())
        };
        let running2 = running.clone();
        tokio::task::spawn_blocking(move || {
            let (tx, rx) = std_mpsc::channel();
            *running2.mtu_waiter.lock().unwrap() = Some(tx);
            let result = probe_mtu_with(
                remote,
                &ladder,
                |buf, to| running2.socket.send_to(buf, to),
                |timeout| waiter_recv(&rx, timeout),
                Duration::from_secs(1),
            );
            *running2.mtu_waiter.lock().unwrap() = None;
            if let Ok(probe) = &result {
                *path_mtu.lock().unwrap() = Some(probe.path_mtu);
            }
            result.map_err(|e| MeshError::new(ErrorCode::TransportTimeout, e.to_string()))
        })
        .await
        .map_err(|e| MeshError::new(ErrorCode::Internal, e.to_string()))?
    }

    fn emit(&self, ev: TransportEvent) {
        if let Some(tx) = self.events.lock().unwrap().as_ref() {
            let _ = tx.try_send(ev);
        }
    }

    /// 本端 host candidate（双轨对比 harness / Controller hints 上报用）。
    /// **剔除 loopback**：跨机/虚拟机场景对端连 127.0.0.1 会命中它自己的 socket
    /// （若两端恰好同端口则 punch 假成功、数据全丢——M0-4R 虚拟机实测教训）。
    /// 同机 loopback 对比测试走真实网卡 IP，不受影响。
    pub fn local_candidates(&self) -> Vec<Candidate> {
        match self.running.lock().unwrap().as_ref() {
            Some(r) => r.host_cands.iter().filter(|c| !c.addr.ip().is_loopback()).cloned().collect(),
            None => Vec::new(),
        }
    }

    /// 本端 srflx candidate（start 时已 gathering；失败容忍为空）。
    pub fn srflx_candidates(&self) -> Vec<Candidate> {
        match self.running.lock().unwrap().as_ref() {
            Some(r) => r.srflx.lock().unwrap().clone(),
            None => Vec::new(),
        }
    }

    /// PoC create 端：进入 accept 模式——此后对端首个**session 精确匹配**的
    /// Binding Request 即建立会话（directlink-poc create / 漫游重连场景）。
    /// M0-4 双向 punch 修正：
    /// - `tag` = `meshlink-poc:{session_id}:{nonce}`，dispatcher 只接受精确匹配
    ///   的 probe（§四 session demux 硬规则，不允许全局匹配）；
    /// - 等待期间周期向 STUN server 发 Binding 刷新本端 NAT 映射（修复：此前
    ///   create 静默等待，映射在 join 到达前可能已过期）；
    /// - 收到对端 probe（携带对端候选集）后主动反向出站 probe（双向确认）。
    pub fn start_accepting(&self, peer: PeerId, tag: String) {
        if let Some(r) = self.running.lock().unwrap().as_ref() {
            *r.accept_peer.lock().unwrap() = Some(peer);
            *r.accept_tag.lock().unwrap() = Some(tag);
            // M0-4R.2 §三：creator 侧证据锚点（等待期起点）
            r.punch_evidence.mark_anchor();
            spawn_stun_refresh(r);
        }
    }

    /// join 端：设置 punch 请求的 session tag 与本端候选集
    /// （随每个 probe 的 MeshCandidates 属性携带——对端据此反向出站）。
    pub fn set_punch_session(&self, tag: String, self_cands: Vec<crate::ice::stun::CandidateWire>) {
        if let Some(r) = self.running.lock().unwrap().as_ref() {
            *r.punch_tag.lock().unwrap() = tag;
            *r.self_cands.lock().unwrap() = self_cands;
        }
    }

    /// join 端随 punch 携带的本端候选集（wire 形态）：物理 host + srflx。
    /// 虚拟接口不发（对端不可达，与 offer 裁剪口径一致）。
    pub fn punch_candidates_wire(&self) -> Vec<crate::ice::stun::CandidateWire> {
        let mut out: Vec<_> =
            self.local_candidates().iter().filter(|c| !c.is_virtual).map(candidate_to_wire).collect();
        out.extend(self.srflx_candidates().iter().map(candidate_to_wire));
        out
    }

    /// 选定 pair 信息（connect 成功后可查；Candidate/selected-pair 证据输出用）。
    /// 返回 (本端 selected 地址, 对端地址, 对端候选类型)。
    /// Track B 单 socket 架构：本端 selected = local_base（srflx/check/data 同 socket）；
    /// local_base 的 IP 用 primary 网卡地址（socket 绑 0.0.0.0 时 local_addr 无信息量）。
    pub fn session_info(&self, peer: &PeerId) -> Option<(SocketAddrV4, SocketAddrV4, CandidateKind)> {
        let running = self.running.lock().unwrap().as_ref()?.clone();
        let local = primary_local_ipv4()
            .map(|ip| SocketAddrV4::new(ip, running.local_base.port()))
            .unwrap_or(running.local_base);
        let sessions = running.sessions.lock().unwrap();
        sessions.get(peer).map(|s| (local, s.remote, s.remote_kind.clone()))
    }

    /// 实际使用的第一个 STUN server（DNS 解析成功者；报告证据用）。
    pub fn first_stun_server(&self) -> Option<String> {
        let running = self.running.lock().unwrap().as_ref()?.clone();
        resolve_servers(&running.params.stun_servers).first().map(|s| s.to_string())
    }

    /// M0-4R.2 §三：本端 simultaneous punch 时间证据（诊断字段）。
    /// anchor_epoch_ms 仅留档（两侧时钟不同步不可横向比绝对值）；
    /// first_punch_tx_ms / first_peer_rx_ms 为相对本端锚点的毫秒，用于
    /// 同端先后关系证明（join 端期望 tx < rx；creator 端 rx < tx 为设计必然）。
    pub fn punch_evidence(&self) -> serde_json::Value {
        match self.running.lock().unwrap().as_ref() {
            Some(r) => r.punch_evidence.report(),
            None => serde_json::Value::Null,
        }
    }

    /// 停止对指定 peer 的 Keepalive（M0-4R idle mapping 对照组专用：
    /// 停止后不再刷新 NAT mapping，分时点发业务包探测映射存活）。
    pub fn stop_keepalive(&self, peer: &PeerId) {
        if let Some(r) = self.running.lock().unwrap().as_ref() {
            if let Some(s) = r.sessions.lock().unwrap().get(peer) {
                // take 后 drop：Keepalive::Drop 置 stop 标志并 join 线程
                drop(s.keepalive.lock().unwrap().take());
            }
        }
    }

    /// start 起点时刻（ADR 对比数据用：gathering/首个连接的时延锚点）。
    pub fn started_at(&self) -> Option<std::time::Instant> {
        self.running.lock().unwrap().as_ref().map(|r| r.started)
    }

    /// M0-5：配置本端 Noise 身份（create/creator 侧必须在收到 msg1 前调用；
    /// join 侧由 `start_noise_initiator` 参数直接传入）。
    /// `network_id` 进 Noise prologue，双方必须一致（PoC = session tag）。
    pub fn configure_noise(&self, identity: Arc<StaticIdentity>, network_id: String) {
        if let Some(r) = self.running.lock().unwrap().as_ref() {
            *r.noise_cfg.lock().unwrap() = Some(NoiseCfg { identity, network_id });
        }
    }

    /// 双向身份验证（用户规格二）：creator 侧登记 initiator（joiner）静态公钥
    /// ——Controller Device Registry / session members 快照。msg1 解出的公钥
    /// 与此不符 → DEVICE_KEY_MISMATCH，握手立即终止。
    ///
    /// 写入 running 级预置表（会话尚未建立也生效）；若会话已存在则同步
    /// session 字段（两条读路径都覆盖）。调用时机竞态安全：joiner 加入后
    /// 任意时刻调用均可，punch 建会话时预置表已被 `handle_noise_msg1` 消费。
    pub fn set_expected_initiator(&self, peer: &PeerId, public_key: [u8; 32]) {
        if let Some(r) = self.running.lock().unwrap().as_ref() {
            r.expected_keys.lock().unwrap().insert(peer.clone(), public_key);
            let sessions = r.sessions.lock().unwrap();
            if let Some(s) = sessions.get(peer) {
                *s.expected_initiator.lock().unwrap() = Some(public_key);
            }
        }
    }

    /// 严格双向验证（用户规格二）：开启后该 peer 的 msg1 若无预置公钥 →
    /// 直接拒绝（而非遗留 PoC 的不校验路径），等待 initiator 重试。
    /// Controller-era（Agent）必须调用；PoC create 流程不调用保持兼容。
    pub fn require_initiator_identity(&self, peer: &PeerId) {
        if let Some(r) = self.running.lock().unwrap().as_ref() {
            *r.require_initiator.lock().unwrap() = Some(peer.clone());
        }
    }

    /// M0-5：join 侧发起 Noise IK 握手（punch 连接成功后调用）。
    /// - `expected_remote`：creator 静态公钥（Session Code v4 `k` 字段）；
    /// - `remote_device_id`：creator 设备 ID（prologue 绑定）；
    /// - 完成后该 peer 的 send_packet/接收自动走加密帧路径，并启动 rekey 监视线程
    ///   （仅初始 initiator 发起 rekey——crypto 模块头约定）。
    /// 返回 16 字节会话标识（PoC 报告输出用）。
    pub async fn start_noise_initiator(
        &self,
        peer: &PeerId,
        identity: Arc<StaticIdentity>,
        network_id: &str,
        remote_device_id: &str,
        expected_remote: &[u8; 32],
    ) -> Result<[u8; 16], MeshError> {
        let running = self
            .running
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| MeshError::from(ErrorCode::TransportStartFailed))?;
        let (remote, policy) = {
            let sessions = running.sessions.lock().unwrap();
            let s = sessions
                .get(peer)
                .ok_or_else(|| MeshError::new(ErrorCode::TransportPeerUnreachable, format!("{peer:?} 未连接")))?;
            (s.remote, running.params.crypto.clone())
        };
        let expected_remote = *expected_remote;
        let network_id = network_id.to_string();
        let remote_device_id = remote_device_id.to_string();
        let peer2 = peer.clone();
        let r2 = running.clone();
        let identity_for_hs = identity.clone();
        let network_id_for_hs = network_id.clone();
        let remote_device_id_for_hs = remote_device_id.clone();
        let sid = tokio::task::spawn_blocking(move || {
            run_initiator_handshake(
                &r2, &peer2, &identity_for_hs, &network_id_for_hs, &remote_device_id_for_hs, &expected_remote,
                1, None, remote, policy,
            )
        })
        .await
        .map_err(|e| MeshError::new(ErrorCode::Internal, e.to_string()))??;

        spawn_rekey_monitor(
            running.clone(),
            peer.clone(),
            identity,
            network_id,
            remote_device_id,
            expected_remote,
        );
        Ok(sid)
    }

    /// M0-5：指定 peer 的加密通道诊断报告（未握手 = established:false）。
    /// 附带 transport 级 msg1 状态机拒绝计数（M0-5 收尾）。
    pub fn crypto_report(&self, peer: &PeerId) -> serde_json::Value {
        let running = self.running.lock().unwrap().clone();
        let Some(r) = running.as_ref() else {
            return serde_json::Value::Null;
        };
        let rejected = r.stats.noise_msg1_rejected.load(Ordering::Relaxed);
        let sessions = r.sessions.lock().unwrap();
        match sessions.get(peer) {
            Some(s) => {
                let ch = s.channel.lock().unwrap();
                match ch.as_ref() {
                    Some(ch) => {
                        let mut v = ch.report();
                        if let Some(obj) = v.as_object_mut() {
                            obj.insert("msg1_rejected".into(), serde_json::json!(rejected));
                        }
                        v
                    }
                    None => serde_json::json!({"established": false, "msg1_rejected": rejected}),
                }
            }
            None => serde_json::Value::Null,
        }
    }
}

fn resolve_servers(specs: &[String]) -> Vec<SocketAddrV4> {
    let mut out = Vec::new();
    for s in specs {
        if let Ok(mut it) = s.to_socket_addrs() {
            if let Some(SocketAddr::V4(v4)) = it.next() {
                out.push(v4);
            }
        }
    }
    out
}

// ---------- M0-4 双向 simultaneous punch 基础件 ----------

/// M0-4R.2 §三：simultaneous punch 时间证据（仅诊断字段，不扩协议）。
///
/// 两侧机器时钟不同步：`anchor_epoch_ms` 仅作留档，**相对毫秒**才是横向安全的
/// 时间量（同一端内单调时钟）。判读口径：
/// - join 端：`first_punch_tx_ms < first_peer_rx_ms` 证明先主动出站、后收到反向；
/// - creator 端：`first_peer_rx_ms` 先于 `first_punch_tx_ms` 是**设计必然**
///   （反向出站以收到对端候选集为前提，候选集随对端 probe 携带）；
///   其主动出站证据 = first_punch_tx 存在且距 first_peer_rx 间隔为出站阶梯起点。
/// 两者合起来即「双方都主动出洞，非一方被动等待」。
#[derive(Default)]
pub struct PunchEvidence {
    /// 锚点（首事件 first-wins）：join = connect_peer 进入；creator = start_accepting
    anchor: Mutex<Option<(std::time::SystemTime, std::time::Instant)>>,
    /// 本端首次主动发出 punch probe（相对锚点）
    first_punch_tx: Mutex<Option<Duration>>,
    /// 本端首次收到对端 session-tagged probe（相对锚点）
    first_peer_rx: Mutex<Option<Duration>>,
}

impl PunchEvidence {
    fn mark_anchor(&self) {
        let mut a = self.anchor.lock().unwrap();
        if a.is_none() {
            *a = Some((std::time::SystemTime::now(), std::time::Instant::now()));
        }
    }

    fn rel_ms(&self) -> u64 {
        self.anchor.lock().unwrap().as_ref().map(|(_, i)| i.elapsed().as_millis() as u64).unwrap_or(0)
    }

    fn mark_punch_tx(&self) {
        self.mark_anchor();
        let mut t = self.first_punch_tx.lock().unwrap();
        if t.is_none() {
            *t = Some(Duration::from_millis(self.rel_ms()));
            tracing::info!(target: "directlink", rel_ms = self.rel_ms(), "PUNCH_EVIDENCE FIRST_PUNCH_TX（本端首次主动出站 probe）");
        }
    }

    fn mark_peer_rx(&self) {
        self.mark_anchor();
        let mut t = self.first_peer_rx.lock().unwrap();
        if t.is_none() {
            *t = Some(Duration::from_millis(self.rel_ms()));
            tracing::info!(target: "directlink", rel_ms = self.rel_ms(), "PUNCH_EVIDENCE FIRST_PEER_RX（本端首次收到对端 session probe）");
        }
    }

    /// 诊断 JSON：anchor_epoch_ms 留档；两个相对毫秒只做同端先后关系证明。
    pub fn report(&self) -> serde_json::Value {
        let Some((epoch, _)) = &*self.anchor.lock().unwrap() else { return serde_json::Value::Null };
        serde_json::json!({
            "anchor_epoch_ms": epoch.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0),
            "first_punch_tx_ms": self.first_punch_tx.lock().unwrap().map(|d| d.as_millis() as u64),
            "first_peer_rx_ms": self.first_peer_rx.lock().unwrap().map(|d| d.as_millis() as u64),
        })
    }
}

/// Candidate → MeshCandidates 属性 wire 形态（srflx=1，其余按 host=0）。
fn candidate_to_wire(c: &Candidate) -> crate::ice::stun::CandidateWire {
    crate::ice::stun::CandidateWire {
        ip: u32::from_be_bytes(c.addr.ip().octets()),
        port: c.addr.port(),
        kind: if matches!(c.kind, CandidateKind::ServerReflexive) { 1 } else { 0 },
    }
}

/// MeshCandidates wire → 对端可达地址（打洞目标）。
fn wire_to_addr(w: &crate::ice::stun::CandidateWire) -> Option<SocketAddrV4> {
    Some(SocketAddrV4::new(std::net::Ipv4Addr::from(u32::to_be_bytes(w.ip)), w.port))
}

/// create 端等待期 NAT 映射保活：周期向首个 STUN server 发 Binding Request。
/// 首个会话建立（sessions 非空）或 transport stop 后退出——会话内 keepalive 接管。
fn spawn_stun_refresh(running: &Arc<Running>) {
    let r = running.clone();
    std::thread::Builder::new()
        .name("dl-stun-refresh".into())
        .spawn(move || {
            let Some(server) = resolve_servers(&r.params.stun_servers).into_iter().next() else {
                return;
            };
            loop {
                if r.dispatcher_stop.load(Ordering::Acquire) || !r.sessions.lock().unwrap().is_empty() {
                    return;
                }
                let txid = new_txid();
                let (tx, rx) = std_mpsc::channel();
                r.outstanding.lock().unwrap().insert(txid, tx);
                let req = StunMessage::binding_request(txid);
                let _ = r.socket.send_to(&req.encode(), server);
                // 映射漂移记录（EIM 下 XOR-MAPPED 应恒定；漂移说明 NAT 重新分配端口）
                if let Some((_, buf)) = waiter_recv(&rx, Duration::from_millis(2500)) {
                    if let Ok(m) = StunMessage::decode(&buf) {
                        if let Some(mapped) = m.get_xor_mapped() {
                            tracing::debug!(target: "directlink", mapped = %mapped, "STUN refresh（等待期 NAT 映射保活）");
                        }
                    }
                }
                r.outstanding.lock().unwrap().remove(&txid);
                std::thread::sleep(Duration::from_secs(20));
            }
        })
        .ok();
}

/// create 端反向 probe（双向 simultaneous punch 的 A 侧）：
/// 收到 join 首个 probe（携带其候选集）后，向 [probe 源地址] + 对端 srflx
/// 主动出站 probe（阶梯间隔），收到任一 response 即确认双向可达后停止。
/// 出站动作同时在本端 NAT 上为对端地址建立过滤豁免（EAF 场景的双向关键）。
fn spawn_reverse_probe(running: &Arc<Running>, first: SocketAddrV4, peer_cands: Vec<crate::ice::stun::CandidateWire>, tag: String) {
    let mut targets: Vec<SocketAddrV4> = vec![first];
    for c in &peer_cands {
        if let Some(a) = wire_to_addr(c) {
            if !targets.contains(&a) {
                targets.push(a);
            }
        }
    }
    targets.truncate(9);
    let r = running.clone();
    std::thread::Builder::new()
        .name("dl-reverse-probe".into())
        .spawn(move || {
            // T+0/100/250/500/1000/1500/2000/2500/3000ms（§二阶梯）
            for wait in [0u64, 100, 250, 500, 1000, 1500, 2000, 2500, 3000] {
                if wait > 0 {
                    std::thread::sleep(Duration::from_millis(wait));
                }
                for &t in &targets {
                    let txid = new_txid();
                    let (tx, rx) = std_mpsc::channel();
                    r.outstanding.lock().unwrap().insert(txid, tx);
                    let req = check_request_attrs(&tag, &[]);
                    // M0-4R.2 §三：creator 侧首次主动出站即打点（反向出站阶梯起点）
                    r.punch_evidence.mark_punch_tx();
                    let _ = r.socket.send_to(&req.encode(), t);
                    let got = waiter_recv(&rx, Duration::from_millis(700))
                        .map(|(from, _)| targets.contains(&from))
                        .unwrap_or(false);
                    r.outstanding.lock().unwrap().remove(&txid);
                    if got {
                        tracing::info!(target: "directlink", remote = %t, "双向 punch：反向 probe 收到 response（bidirectional reachability 确认）");
                        return;
                    }
                }
            }
            tracing::info!(target: "directlink", "双向 punch：反向 probe 窗口结束（对端方向未确认；会话保持，依赖 keepalive）");
        })
        .ok();
}

fn parse_endpoint(ep: &Endpoint) -> Option<Candidate> {
    let addr: SocketAddr = format!("{}:{}", ep.ip, ep.port).parse().ok()?;
    let SocketAddr::V4(v4) = addr else { return None };
    match ep.kind.as_str() {
        "host" => Some(Candidate::host(v4)),
        _ => Some(Candidate::srflx(v4, v4)),
    }
}

/// 就地建立会话 + keepalive（accept 模式收到对端首个 Binding Request 时调用）。
///
/// 与 `connect_peer` 尾部同构但无 events 回调（dispatcher 线程内，down 由
/// health 轮询感知）；remote 类型按对端 probe 携带的候选集匹配来源得出，
/// 未命中（来源不在对端通告集内）才记 prflx。
fn ensure_session(
    running: &Arc<Running>,
    peer: PeerId,
    from: SocketAddrV4,
    rtt: Duration,
    peer_cands: Option<&[crate::ice::stun::CandidateWire]>,
) {
    let remote_kind = peer_cands
        .and_then(|cs| cs.iter().find(|w| wire_to_addr(w) == Some(from)))
        .map(|w| if w.kind == 1 { CandidateKind::ServerReflexive } else { CandidateKind::Host })
        .unwrap_or(CandidateKind::PeerReflexive);
    let (rx_tx, rx_rx) = mpsc::unbounded_channel();
    let last_rtt = Arc::new(Mutex::new(if rtt.is_zero() { None } else { Some(rtt) }));
    let ka_sock = running.socket.clone();
    let ka_outstanding = running.outstanding.clone();
    let keepalive = {
        let (ka_tx, ka_rx) = std_mpsc::channel();
        let outstanding_for_send = ka_outstanding.clone();
        let outstanding_for_recv = ka_outstanding.clone();
        let send = {
            let last_txid: Cell<Option<[u8; 12]>> = Cell::new(None);
            move |buf: &[u8], to: SocketAddrV4| {
                if let Ok(msg) = StunMessage::decode(buf) {
                    if let Some(prev) = last_txid.replace(Some(msg.txid)) {
                        outstanding_for_send.lock().unwrap().remove(&prev);
                    }
                    outstanding_for_send.lock().unwrap().insert(msg.txid, ka_tx.clone());
                }
                ka_sock.send_to(buf, to)
            }
        };
        let recv = move |timeout: Duration| {
            let (from, buf) = ka_rx.recv_timeout(timeout).ok()?;
            if let Ok(m) = StunMessage::decode(&buf) {
                outstanding_for_recv.lock().unwrap().remove(&m.txid);
            }
            Some((from, buf))
        };
        Keepalive::start(
            send,
            recv,
            from,
            Duration::from_millis(running.params.keepalive_interval_ms),
            running.params.keepalive_miss_limit,
            |_misses| {},
        )
        .0
    };
    let session = PeerSession {
        remote: from,
        remote_kind,
        rx_tx,
        rx_rx: Mutex::new(Some(rx_rx)),
        keepalive: Mutex::new(Some(keepalive)),
        last_rtt,
        since: std::time::Instant::now(),
        path_mtu: Arc::new(Mutex::new(None)),
        channel: Arc::new(Mutex::new(None)),
        expected_initiator: Mutex::new(None),
    };
    running.sessions.lock().unwrap().insert(peer, session);
}

// ---------- M0-5：Noise 帧分派 / 握手 / rekey ----------

/// dispatcher 收到 0x4D44 帧的总入口。
/// - 握手 msg1（bit2|bit3）→ responder 处理（幂等重发 / 初始 / rekey）；
/// - 握手 msg2（bit2）→ 投递给等待中的 initiator；
/// - 加密数据帧（bit0）→ 来源地址匹配会话 → 解密 → session rx。
fn handle_noise_frame(r: &Arc<Running>, sock: &Arc<UdpSocket>, from: SocketAddrV4, payload: &[u8]) {
    let f = match crypto::decode_frame(payload) {
        Ok(f) => f,
        Err(e) => {
            tracing::debug!(target: "directlink", from = %from, error = %e, "Noise 帧解码失败（丢弃）");
            return;
        }
    };
    if f.is_handshake() {
        if f.has_intro() {
            handle_noise_msg1(r, sock, from, payload, &f);
        } else {
            let waiter = r.noise_waiter.lock().unwrap().clone();
            match waiter {
                Some(tx) => {
                    let _ = tx.send((from, payload.to_vec()));
                }
                None => tracing::debug!(target: "directlink", from = %from, "无等待者的 msg2（丢弃）"),
            }
        }
        return;
    }
    // 加密数据帧：来源地址匹配会话 → 解密 → 明文投递 session rx
    let map = r.sessions.lock().unwrap();
    for s in map.values() {
        if s.remote != from {
            continue;
        }
        let mut ch = s.channel.lock().unwrap();
        match ch.as_mut() {
            Some(channel) => match channel.recv(&f) {
                RecvOutcome::Accepted(pt) => {
                    tracing::info!(target: "gatedbg", from = %from, len = pt.len(), "noise 数据帧解密投递 rx");
                    r.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                    r.stats.rx_bytes.fetch_add(pt.len() as u64, Ordering::Relaxed);
                    let _ = s.rx_tx.send(pt);
                }
                RecvOutcome::Rejected(reason) => {
                    tracing::info!(target: "gatedbg", from = %from, reason, "加密帧拒绝（丢弃）");
                }
            },
            None => tracing::info!(target: "gatedbg", from = %from, "数据帧到达但会话无 Noise 通道（丢弃）"),
        }
        break;
    }
}

/// responder（creator）侧处理 msg1（dispatcher 线程内，天然串行）。
/// M0-5 收尾：严格 epoch/session 状态机——已建立通道时**只接受**
/// `new_epoch == current + 1`（rekey）；同 session+epoch 的重复 msg1 幂等重发
/// 缓存 msg2（不重装纪元、不推进 epoch）；其余一律拒绝：
/// - epoch < current（回退/旧纪元重放）；
/// - epoch > current + 1（跳变）；
/// - session_id 不匹配（未知会话）；
/// - 无来源会话（未 punch 先握手——防半开连接）；
/// - 未建通道时 epoch != 1（初始握手必须从纪元 1 开始）。
/// 对端重启的合法路径 = 漫游重连/新会话流程（地址变化重建会话 + epoch 1）。
fn handle_noise_msg1(r: &Arc<Running>, sock: &Arc<UdpSocket>, from: SocketAddrV4, payload: &[u8], f: &crypto::FrameView) {
    let cfg = r.noise_cfg.lock().unwrap().clone();
    let Some(cfg) = cfg else {
        tracing::debug!(target: "directlink", from = %from, "msg1 到达但本端未配置 Noise responder（丢弃）");
        return;
    };
    // 定位来源会话 + 状态机判定（单遍加锁；PoC 流程 punch 先行，msg1 时会话必存在）
    let map = r.sessions.lock().unwrap();
    let Some((pid, s)) = map.iter().find(|(_, s)| s.remote == from) else {
        r.stats.noise_msg1_rejected.fetch_add(1, Ordering::Relaxed);
        tracing::warn!(target: "directlink", from = %from, reason = "no_session", "Noise msg1 拒绝：来源会话不存在（未 punch 先握手）");
        return;
    };
    let pid = pid.clone();
    let policy = r.params.crypto.clone();
    // 判定结果（持有 sessions 锁期间完成，避免 respond 后状态被并发改写）
    enum Verdict {
        /// 同 session+epoch 重复 → 重发缓存 msg2
        Resend(Vec<u8>),
        /// rekey：epoch = current+1
        Rekey,
        /// 无通道初始握手（epoch 必须为 1）
        Fresh,
        Reject(&'static str),
    }
    let verdict = {
        let ch = s.channel.lock().unwrap();
        match ch.as_ref() {
            Some(ch) => {
                if ch.session_id() != f.session_id {
                    Verdict::Reject("session_mismatch")
                } else if f.epoch_id == ch.current_epoch_id() {
                    match ch.msg2_cache() {
                        Some(msg2) => Verdict::Resend(msg2.to_vec()),
                        None => Verdict::Reject("no_msg2_cache"),
                    }
                } else if f.epoch_id < ch.current_epoch_id() {
                    Verdict::Reject("epoch_rollback")
                } else if f.epoch_id > ch.current_epoch_id() + 1 {
                    Verdict::Reject("epoch_skip")
                } else {
                    Verdict::Rekey
                }
            }
            None => {
                if f.epoch_id == 1 {
                    Verdict::Fresh
                } else {
                    Verdict::Reject("epoch_skip")
                }
            }
        }
    };
    let is_rekey = matches!(verdict, Verdict::Rekey);
    match verdict {
        Verdict::Resend(msg2) => {
            drop(map);
            let _ = sock.send_to(&msg2, from);
            tracing::debug!(target: "directlink", from = %from, "重复 msg1 → 重发缓存 msg2（幂等，不重装纪元）");
        }
        Verdict::Reject(reason) => {
            r.stats.noise_msg1_rejected.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(target: "directlink", from = %from, reason, epoch = f.epoch_id, "Noise msg1 拒绝（状态机）");
        }
        Verdict::Rekey | Verdict::Fresh => {
            // respond() 用帧内 session_id/epoch 构造 prologue（transcript 绑定），
            // 密钥/prologue/帧篡改在此处一并校验；expected_initiator 优先读
            // session 字段，回落 running 级预置表（会话建立前登记的公钥）。
            // 严格模式（require_initiator）下无预置公钥 → 拒绝（initiator
            // 握手重试会再次到达，等 creator 完成登记——绝不放行未验证身份）。
            let expected_initiator = {
                let from_session = *s.expected_initiator.lock().unwrap();
                from_session.or_else(|| r.expected_keys.lock().unwrap().get(&pid).copied())
            };
            let strict_no_key = expected_initiator.is_none()
                && *r.require_initiator.lock().unwrap() == Some(pid.clone());
            if strict_no_key {
                r.stats.noise_msg1_rejected.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(target: "directlink", from = %from, "Noise msg1 拒绝：严格模式下未预置 initiator 公钥（等待 Controller 登记后重试）");
                return;
            }
            let (new_epoch, msg2) = match crypto::respond(
                &cfg.identity,
                &cfg.network_id,
                payload,
                expected_initiator.as_ref(),
            ) {
                Ok(x) => x,
                Err(e) => {
                    r.stats.noise_msg1_rejected.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(target: "directlink", from = %from, error = ?e, "Noise msg1 校验失败（丢弃）");
                    return;
                }
            };
            let _ = sock.send_to(&msg2, from);
            let initiator_dev = f.intro().map(|(d, _)| d.to_string()).unwrap_or_default();
            let mut ch = s.channel.lock().unwrap();
            if is_rekey {
                if let Some(old) = ch.as_mut() {
                    old.apply_new_epoch(new_epoch);
                    tracing::info!(target: "directlink", peer = %pid.0, epoch = f.epoch_id, "Noise rekey 完成（responder）");
                }
            } else {
                *ch = Some(
                    NoiseChannel::from_epoch(new_epoch, Role::Responder, cfg.identity.device_id(), initiator_dev, policy)
                        .with_session_id(f.session_id),
                );
                tracing::info!(target: "directlink", peer = %pid.0, epoch = f.epoch_id, "Noise 握手完成（responder）");
            }
        }
    }
}

/// initiator 侧握手驱动（初始握手与 rekey 共用）：
/// 注册 msg2 等待者 → 发 msg1（重传同一字节串，responder 幂等）→ 收 msg2 →
/// complete → 附加/升级通道。`session_id = None` = 初始（自动派生）。
fn run_initiator_handshake(
    r: &Arc<Running>,
    peer: &PeerId,
    identity: &Arc<StaticIdentity>,
    network_id: &str,
    remote_device_id: &str,
    expected_remote: &[u8; 32],
    target_epoch: u32,
    session_id: Option<[u8; 16]>,
    remote: SocketAddrV4,
    policy: CryptoPolicy,
) -> Result<[u8; 16], MeshError> {
    let (tx, rx) = std_mpsc::channel();
    *r.noise_waiter.lock().unwrap() = Some(tx);
    let result = (|| {
        let hs = crypto::initiate(identity, network_id, remote_device_id, expected_remote, target_epoch, session_id)?;
        let sid = hs.session_id();
        let msg1 = hs.msg1_frame().to_vec();
        let mut msg2: Option<Vec<u8>> = None;
        for _ in 0..policy.handshake_retries.max(1) {
            let _ = r.socket.send_to(&msg1, remote);
            if let Some((from, buf)) = waiter_recv(&rx, Duration::from_millis(policy.handshake_rto_ms)) {
                if from == remote {
                    msg2 = Some(buf);
                    break;
                }
                // 异常来源（msg2 加密保证 + 来源校验双保险）：本轮回合作废继续重试
            }
        }
        let msg2 = msg2
            .ok_or_else(|| MeshError::new(ErrorCode::CryptoHandshakeFailed, "Noise 握手超时：msg2 未到达"))?;
        let new_epoch = hs.complete(&msg2)?;
        let sessions = r.sessions.lock().unwrap();
        let s = sessions
            .get(peer)
            .ok_or_else(|| MeshError::new(ErrorCode::TransportPeerUnreachable, "握手完成时会话已消失"))?;
        let mut ch = s.channel.lock().unwrap();
        match (ch.as_mut(), session_id) {
            (Some(old), Some(_)) => old.apply_new_epoch(new_epoch),
            _ => {
                *ch = Some(
                    NoiseChannel::from_epoch(new_epoch, Role::Initiator, identity.device_id(), remote_device_id, policy.clone())
                        .with_session_id(sid),
                )
            }
        }
        tracing::info!(target: "directlink", peer = %peer.0, epoch = target_epoch, "Noise 握手完成（initiator）");
        Ok(sid)
    })();
    *r.noise_waiter.lock().unwrap() = None;
    result
}

/// rekey 监视线程（仅初始 initiator 发起——双方同时重握手会冲突，见 crypto 模块头）。
/// 周期检查 should_rekey（时间/流量阈值），触发后以 current+1 重新 IK 握手；
/// 失败清除 in-flight 标记下轮重试，会话消失或 transport 停止即退出。
fn spawn_rekey_monitor(
    running: Arc<Running>,
    peer: PeerId,
    identity: Arc<StaticIdentity>,
    network_id: String,
    remote_device_id: String,
    expected_remote: [u8; 32],
) {
    let r = running.clone();
    std::thread::Builder::new()
        .name("dl-rekey".into())
        .spawn(move || {
            loop {
                if r.dispatcher_stop.load(Ordering::Acquire) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(1000));
                // 触发判定 + in-flight 标记（一次加锁完成，防重入）
                let (remote, cur_epoch, sid) = {
                    let sessions = r.sessions.lock().unwrap();
                    let Some(s) = sessions.get(&peer) else { return };
                    let mut ch = s.channel.lock().unwrap();
                    let Some(ch) = ch.as_mut() else { return };
                    if !ch.should_rekey() {
                        continue;
                    }
                    ch.set_rekey_in_flight(true);
                    (s.remote, ch.current_epoch_id(), ch.session_id())
                };
                let policy = r.params.crypto.clone();
                let result = run_initiator_handshake(
                    &r, &peer, &identity, &network_id, &remote_device_id, &expected_remote,
                    cur_epoch + 1, Some(sid), remote, policy,
                );
                if let Err(e) = result {
                    tracing::warn!(target: "directlink", peer = %peer.0, error = ?e, "rekey 失败（下轮重试）");
                    let sessions = r.sessions.lock().unwrap();
                    if let Some(s) = sessions.get(&peer) {
                        if let Some(ch) = s.channel.lock().unwrap().as_mut() {
                            ch.set_rekey_in_flight(false);
                        }
                    }
                }
            }
        })
        .ok();
}

#[async_trait]
impl TransportProvider for DirectLinkTransport {
    async fn start(&self, cfg: TransportConfig) -> Result<(), MeshError> {
        let params: DirectLinkParams = serde_json::from_value(cfg.params)
            .map_err(|e| MeshError::new(ErrorCode::ConfigInvalid, format!("directlink.params: {e}")))?;

        let (sock, host_cands) = gather_host_candidates(params.listen_port)
            .map_err(|e| MeshError::new(ErrorCode::TransportStartFailed, e.to_string()))?;
        let sock = Arc::new(sock);
        let local_base = match sock.local_addr() {
            Ok(SocketAddr::V4(v4)) => v4,
            _ => return Err(MeshError::new(ErrorCode::TransportStartFailed, "socket 无本地 IPv4 地址")),
        };

        let running = Arc::new(Running {
            socket: sock.clone(),
            local_base,
            host_cands,
            srflx: Mutex::new(Vec::new()),
            sessions: Mutex::new(HashMap::new()),
            params: params.clone(),
            started: std::time::Instant::now(),
            dispatcher_stop: Arc::new(AtomicBool::new(false)),
            dispatcher: Mutex::new(None),
            outstanding: Arc::new(Mutex::new(HashMap::new())),
            unmatched_stun: Mutex::new(None),
            mtu_waiter: Mutex::new(None),
            punch_lock: Mutex::new(()),
            accept_peer: Mutex::new(None),
            accept_tag: Mutex::new(None),
            punch_tag: Mutex::new("meshlink-poc".into()),
            self_cands: Mutex::new(Vec::new()),
            punch_evidence: Arc::new(PunchEvidence::default()),
            noise_cfg: Mutex::new(None),
            noise_waiter: Mutex::new(None),
            expected_keys: Mutex::new(HashMap::new()),
            require_initiator: Mutex::new(None),
            stats: Arc::new(Stats::default()),
        });

        // Dispatcher 线程（模块头表格的分派规则）
        let disp_sock = sock.clone();
        let disp_stop = running.dispatcher_stop.clone();
        let running2 = running.clone();
        let dispatcher = std::thread::Builder::new()
            .name("directlink-dispatcher".into())
            .spawn(move || {
                let mut buf = [0u8; 0xFFFF];
                while !disp_stop.load(Ordering::Acquire) {
                    let (n, from) = match disp_sock.recv_from(&mut buf) {
                        Ok(x) => x,
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    };
                    let payload = &buf[..n];
                    let SocketAddr::V4(from) = from else { continue };
                    if let Ok(msg) = StunMessage::decode(payload) {
                        match msg.msg_type {
                            crate::ice::stun::BINDING_REQUEST => {
                                let resp = check_response(&msg, from);
                                let _ = disp_sock.send_to(&resp.encode(), from);
                                // M0-4 双向 punch 修正：session-scoped demux（§四硬规则）。
                                // 只有 USERNAME 精确等于本端 accept tag 的 probe 才建会话；
                                // Controller 时代 tag = Controller session_id（session 级唯一，
                                // 双端均知），PoC 时代为 meshlink-poc:{session}:{nonce}——
                                // 此处不再要求固定前缀（隔离完全由下方 tag 精确匹配保证）。
                                // LAN 内其他设备/其他 session 的请求仅回应不建会话。
                                // keepalive（meshlink-keepalive）不触发重建（只刷新既有映射）。
                                let req_tag = msg.attrs.iter().find_map(|a| match a {
                                    crate::ice::stun::StunAttr::Username(u) => Some(u.clone()),
                                    _ => None,
                                });
                                let Some(req_tag) = req_tag else { continue };
                                let accept = running2.accept_peer.lock().unwrap().clone();
                                let accept_tag = running2.accept_tag.lock().unwrap().clone();
                                // M0-4R.2 §三：本端首次收到对端 session-tagged probe 的
                                // 时间证据。join 侧经 punch_tag 判定（无 accept 状态），
                                // creator 侧经 accept_tag 精确匹配判定——两处都是
                                // session-scoped（§四），keepalive tag 不入证据。
                                if *running2.punch_tag.lock().unwrap() == req_tag
                                    || accept_tag.as_deref() == Some(req_tag.as_str())
                                {
                                    running2.punch_evidence.mark_peer_rx();
                                }
                                let Some(peer) = accept else { continue };
                                if accept_tag.as_deref() != Some(req_tag.as_str()) {
                                    continue; // 非本 Session 的 probe：不建会话
                                }
                                // 双向 punch：提取对端候选集（随 probe 携带）
                                let peer_cands = msg.attrs.iter().find_map(|a| match a {
                                    crate::ice::stun::StunAttr::MeshCandidates(v) => Some(v.clone()),
                                    _ => None,
                                });
                                // 漫游重连：来源地址变化时覆盖旧会话（旧 keepalive
                                // 随 PeerSession Drop 停止）
                                let mut map = running2.sessions.lock().unwrap();
                                let stale = map.get(&peer).map(|s| s.remote != from).unwrap_or(true);
                                if stale {
                                    tracing::info!(target: "gatedbg", peer = %peer.0, from = %from, had = map.contains_key(&peer), "会话重建（漫游/首建）");
                                    map.remove(&peer);
                                    drop(map);
                                    ensure_session(&running2, peer, from, Duration::ZERO, peer_cands.as_deref());
                                    if let Some(cands) = peer_cands {
                                        spawn_reverse_probe(&running2, from, cands, req_tag);
                                    }
                                }
                            }
                            _ => {
                                let waiter = running2
                                    .outstanding
                                    .lock()
                                    .unwrap()
                                    .get(&msg.txid)
                                    .cloned()
                                    .or_else(|| running2.unmatched_stun.lock().unwrap().clone());
                                if let Some(tx) = waiter {
                                    let _ = tx.send((from, payload.to_vec()));
                                }
                            }
                        }
                        continue;
                    }
                    if payload.len() >= 4 && payload[0..2] == MTU_MAGIC {
                        // MTU echo 双角色：本端在探测 → 帧是回显响应，投递 waiter；
                        // 本端未探测 → 帧是对端的探测请求，整帧原样回显
                        // （曾缺回显逻辑：请求被静默丢弃，probe 全档超时 FAIL）
                        let waiter = running2.mtu_waiter.lock().unwrap().clone();
                        match waiter {
                            Some(tx) => {
                                let _ = tx.send((from, payload.to_vec()));
                            }
                            None => {
                                let _ = running2.socket.send_to(&payload, from);
                            }
                        }
                        continue;
                    }
                    // M0-5：Noise 帧（0x4D44）。首字节 0x4D 与 IPv4 版本位（4）重叠，
                    // 必须先于 IPv4 数据分派判断（模块头帧分派规则 §3/§4）
                    if payload.len() >= crypto::FRAME_HEADER_LEN && payload[0..2] == crypto::FRAME_MAGIC {
                        handle_noise_frame(&running2, &disp_sock, from, payload);
                        continue;
                    }
                    // 数据帧 → session rx（按来源地址匹配会话）
                    if n >= 20 && (payload[0] >> 4) == 4 {
                        running2.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                        running2.stats.rx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                        let map = running2.sessions.lock().unwrap();
                        for s in map.values() {
                            if s.remote == from {
                                tracing::info!(target: "gatedbg", from = %from, len = n, "明文 IPv4 数据帧投递 rx（M0-4 兼容路径）");
                                let _ = s.rx_tx.send(payload.to_vec());
                                break;
                            }
                        }
                    }
                }
            })
            .map_err(|e| MeshError::new(ErrorCode::TransportStartFailed, e.to_string()))?;
        *running.dispatcher.lock().unwrap() = Some(dispatcher);

        // srflx gathering（失败容忍：内网/离线仍可 host 直连）——dispatcher 已运转
        for server in resolve_servers(&params.stun_servers).into_iter().take(2) {
            let txid = new_txid();
            let (tx, rx) = std_mpsc::channel();
            running.outstanding.lock().unwrap().insert(txid, tx);
            let result = binding_exchange_with(
                txid,
                server,
                |buf| sock.send_to(buf, server),
                |timeout| waiter_recv(&rx, timeout),
                Duration::from_millis(500),
                2,
            );
            running.outstanding.lock().unwrap().remove(&txid);
            match result {
                Ok(b) => {
                    tracing::info!(target: "directlink", server = %server, mapped = %b.mapped, "srflx gathering 成功");
                    // base 用 primary 网卡地址：socket 绑 0.0.0.0 时 local_addr 不含
                    // 具体 IP（0.0.0.0 不是有效 base，Candidate 证据输出要求真实地址）
                    let base = primary_local_ipv4()
                        .map(|ip| SocketAddrV4::new(ip, local_base.port()))
                        .unwrap_or(local_base);
                    running.srflx.lock().unwrap().push(Candidate::srflx(b.mapped, base));
                }
                Err(e) => {
                    tracing::warn!(target: "directlink", server = %server, error = ?e, "srflx gathering 失败（容忍）");
                }
            }
        }

        *self.running.lock().unwrap() = Some(running);
        Ok(())
    }

    async fn stop(&self, _timeout: Duration) -> Result<(), MeshError> {
        *self.running.lock().unwrap() = None; // Drop Running：停 dispatcher、清会话
        Ok(())
    }

    async fn connect_peer(&self, peer: PeerId, hints: PeerHints) -> Result<(), MeshError> {
        let running = self
            .running
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| MeshError::from(ErrorCode::TransportStartFailed))?;
        let peer_cands: Vec<Candidate> = hints.endpoints.iter().filter_map(parse_endpoint).collect();
        if peer_cands.is_empty() {
            return Err(MeshError::new(ErrorCode::ControllerProtocol, "hints 无可解析候选"));
        }

        // punch 串行化 + 未匹配 STUN 响应队列（守卫与队列注册都在阻塞闭包内，
        // 避免跨 .await 持有 std MutexGuard 导致 future 非 Send）
        let cfg = PunchConfig {
            rto: Duration::from_millis(running.params.punch_rto_ms),
            retries: running.params.punch_retries,
            window: Duration::from_millis(running.params.punch_window_ms),
        };
        // M0-4 双向 punch：session-scoped tag + 本端候选集（对端据此反向出站）
        let (punch_tag, self_cands) = {
            let t = running.punch_tag.lock().unwrap().clone();
            let c = running.self_cands.lock().unwrap().clone();
            (t, c)
        };
        let extra_attrs: Vec<crate::ice::stun::StunAttr> = if self_cands.is_empty() {
            Vec::new()
        } else {
            vec![crate::ice::stun::StunAttr::MeshCandidates(self_cands)]
        };
        let local_base = running.local_base;
        let running2 = running.clone();
        // M0-4R.2 §三：join 侧证据锚点（punch 阶段起点）
        running.punch_evidence.mark_anchor();
        let evidence_for_send = running.punch_evidence.clone();
        let peer_cands_for_punch = peer_cands.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _guard = running2.punch_lock.lock().unwrap();
            let (punch_tx, punch_rx) = std_mpsc::channel();
            *running2.unmatched_stun.lock().unwrap() = Some(punch_tx);
            let outcome = punch_with(
                // §三：首次主动出站即打点（punch_with 内对入站请求的 Response 也走
                // 此闭包，但 join 端首包必然先于任何入站——对端反向出站以收到
                // 本端 probe 为前提，first-wins 语义下记录的必是首个出站 probe）
                |buf, to| {
                    evidence_for_send.mark_punch_tx();
                    running2.socket.send_to(buf, to)
                },
                |timeout| waiter_recv(&punch_rx, timeout),
                local_base,
                &peer_cands_for_punch,
                // LAN host 直连时 XOR-MAPPED=host base ≠ srflx；expected 校验只在
                // 全 srflx 场景有效——精确 pair 级校验由单测覆盖，transport 层暂传 None
                None,
                &cfg,
                &punch_tag,
                &extra_attrs,
            );
            *running2.unmatched_stun.lock().unwrap() = None;
            outcome
        })
        .await
        .map_err(|e| MeshError::new(ErrorCode::Internal, e.to_string()))?;

        let outcome: PunchOutcome = match result {
            Ok(o) => o,
            Err(e) => {
                running.stats.punch_failures.fetch_add(1, Ordering::Relaxed);
                self.emit(TransportEvent::PeerUnreachable(peer.clone(), PathKind::DirectLink, ErrorCode::TransportPeerUnreachable));
                return Err(MeshError::new(ErrorCode::TransportPeerUnreachable, e.to_string()));
            }
        };

        // 会话 + keepalive（txid 注册 → dispatcher 投递 → ka_rx 消费并反注册）
        let (rx_tx, rx_rx) = mpsc::unbounded_channel();
        let last_rtt = Arc::new(Mutex::new(Some(outcome.rtt)));
        let events = self.events.lock().unwrap().clone();
        let ka_outstanding = running.outstanding.clone();
        let ka_sock = running.socket.clone();
        let ka_peer2 = peer.clone();
        let (keepalive, _ka_rtt) = {
            let (ka_tx, ka_rx) = std_mpsc::channel();
            let outstanding_for_send = ka_outstanding.clone();
            let outstanding_for_recv = ka_outstanding.clone();
            let send = {
                let last_txid: Cell<Option<[u8; 12]>> = Cell::new(None);
                move |buf: &[u8], to: SocketAddrV4| {
                    if let Ok(msg) = StunMessage::decode(buf) {
                        // 注册当前 txid → 共享通道；清理上一请求（防 map 泄漏）
                        if let Some(prev) = last_txid.replace(Some(msg.txid)) {
                            outstanding_for_send.lock().unwrap().remove(&prev);
                        }
                        outstanding_for_send.lock().unwrap().insert(msg.txid, ka_tx.clone());
                    }
                    ka_sock.send_to(buf, to)
                }
            };
            let recv = move |timeout: Duration| {
                let (from, buf) = ka_rx.recv_timeout(timeout).ok()?;
                if let Ok(m) = StunMessage::decode(&buf) {
                    outstanding_for_recv.lock().unwrap().remove(&m.txid);
                }
                Some((from, buf))
            };
            Keepalive::start(
                send,
                recv,
                outcome.remote,
                Duration::from_millis(running.params.keepalive_interval_ms),
                running.params.keepalive_miss_limit,
                move |_misses| {
                    if let Some(tx) = events.as_ref() {
                        let _ = tx.try_send(TransportEvent::HealthChanged(
                            ka_peer2.clone(),
                            HealthSnapshot { score: 0, transport_alive: false, ..Default::default() },
                        ));
                    }
                },
            )
        };

        let session = PeerSession {
            remote: outcome.remote,
            remote_kind: peer_cands
                .iter()
                .find(|c| c.addr == outcome.remote)
                .map(|c| c.kind.clone())
                .unwrap_or(CandidateKind::PeerReflexive),
            rx_tx,
            rx_rx: Mutex::new(Some(rx_rx)),
            keepalive: Mutex::new(Some(keepalive)),
            last_rtt,
            since: std::time::Instant::now(),
            path_mtu: Arc::new(Mutex::new(None)),
            channel: Arc::new(Mutex::new(None)),
            expected_initiator: Mutex::new(None),
        };
        running.sessions.lock().unwrap().insert(peer.clone(), session);
        self.emit(TransportEvent::PeerReachable(peer.clone(), PathKind::DirectLink));
        tracing::info!(target: "directlink", peer = %peer.0, remote = %outcome.remote, rtt_us = outcome.rtt.as_micros() as u64, "ICE punch 成功");
        Ok(())
    }

    async fn disconnect_peer(&self, peer: PeerId) -> Result<(), MeshError> {
        if let Some(running) = self.running.lock().unwrap().as_ref() {
            running.sessions.lock().unwrap().remove(&peer);
        }
        Ok(())
    }

    async fn send_packet(&self, peer: PeerId, pkt: Ipv4Packet) -> Result<(), MeshError> {
        let running = self
            .running
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| MeshError::from(ErrorCode::TransportStartFailed))?;
        let (remote, encrypted) = {
            let sessions = running.sessions.lock().unwrap();
            let s = sessions
                .get(&peer)
                .ok_or_else(|| MeshError::new(ErrorCode::TransportPeerUnreachable, format!("{peer:?} 未连接")))?;
            // M0-5：已建立 Noise 通道 → 加密发送；未握手 → 明文（M0-4 兼容路径）
            let mut ch = s.channel.lock().unwrap();
            match ch.as_mut() {
                Some(channel) => {
                    let mut wire = Vec::with_capacity(FRAME_WIRE_CAP);
                    channel.send(&pkt.bytes, &mut wire)?;
                    (s.remote, Some(wire))
                }
                None => (s.remote, None),
            }
        };
        let out: &[u8] = encrypted.as_deref().unwrap_or(&pkt.bytes);
        tracing::info!(
            target: "gatedbg",
            peer = %peer.0,
            remote = %remote,
            len = out.len(),
            encrypted = encrypted.is_some(),
            "send_packet"
        );
        if out.len() > 0xFFFF {
            return Err(MeshError::new(ErrorCode::TransportSendFailed, "包超长"));
        }
        running
            .socket
            .send_to(out, remote)
            .map_err(|e| MeshError::new(ErrorCode::TransportSendFailed, e.to_string()))?;
        running.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        running.stats.tx_bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    fn health(&self, peer: Option<PeerId>) -> HealthSnapshot {
        let Some(running) = self.running.lock().unwrap().clone() else {
            return HealthSnapshot::default();
        };
        let Some(peer) = peer else {
            return HealthSnapshot { score: 50, transport_alive: true, ..Default::default() };
        };
        let sessions = running.sessions.lock().unwrap();
        match sessions.get(&peer) {
            Some(s) => {
                let rtt_ms = s.last_rtt.lock().unwrap().map(|d| d.as_secs_f64() * 1000.0);
                let alive = s.keepalive.lock().unwrap().is_some();
                HealthSnapshot {
                    score: if alive { 100 } else { 0 },
                    rtt_ms,
                    loss_pct: None,
                    jitter_ms: None,
                    stall_events: 0,
                    transport_alive: alive,
                }
            }
            None => HealthSnapshot::default(),
        }
    }

    fn stats(&self) -> TransportStats {
        let Some(running) = self.running.lock().unwrap().clone() else {
            return TransportStats::default();
        };
        // 先取出所有值再构造返回值：MutexGuard 临时值不能出现在块尾表达式
        // （会在块局部变量之后 Drop，导致借用超龄）
        let peer_count = running.sessions.lock().unwrap().len() as u32;
        TransportStats {
            tx_bytes: running.stats.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: running.stats.rx_bytes.load(Ordering::Relaxed),
            tx_packets: running.stats.tx_packets.load(Ordering::Relaxed),
            rx_packets: running.stats.rx_packets.load(Ordering::Relaxed),
            peer_count,
        }
    }

    async fn probe(&self, peer: PeerId) -> ProbeResult {
        let running = self.running.lock().unwrap().clone();
        let Some(running) = running else { return ProbeResult { ok: false, rtt_ms: None } };
        let remote = running.sessions.lock().unwrap().get(&peer).map(|s| s.remote);
        let Some(remote) = remote else { return ProbeResult { ok: false, rtt_ms: None } };
        let sock = running.socket.clone();
        let outstanding = running.outstanding.clone();
        let result = tokio::task::spawn_blocking(move || {
            let txid = new_txid();
            let (tx, rx) = std_mpsc::channel();
            outstanding.lock().unwrap().insert(txid, tx);
            let r = binding_exchange_with(
                txid,
                remote,
                |buf| sock.send_to(buf, remote),
                |timeout| waiter_recv(&rx, timeout),
                Duration::from_millis(500),
                1,
            );
            outstanding.lock().unwrap().remove(&txid);
            r
        })
        .await;
        match result {
            Ok(Ok(b)) => ProbeResult { ok: true, rtt_ms: Some(b.rtt.as_secs_f64() * 1000.0) },
            _ => ProbeResult { ok: false, rtt_ms: None },
        }
    }

    fn path_info(&self, peer: PeerId) -> Option<PathInfo> {
        let running = self.running.lock().unwrap().clone()?;
        let sessions = running.sessions.lock().unwrap();
        let s = sessions.get(&peer)?;
        let rtt_ms = s.last_rtt.lock().unwrap().map(|d| d.as_secs_f64() * 1000.0);
        let detail = format!("ice/udp punched → {}", s.remote);
        let stable_for = s.since.elapsed();
        Some(PathInfo {
            kind: PathKind::DirectLink,
            rtt_ms,
            stable_for,
            detail,
        })
    }

    async fn subscribe_events(&self, tx: mpsc::Sender<TransportEvent>) {
        *self.events.lock().unwrap() = Some(tx);
    }
}
