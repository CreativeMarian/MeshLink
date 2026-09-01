//! N2NTransport（M1-2）：MeshLink 第二个独立 TransportProvider。
//!
//! 架构（用户规格 M1-2 硬规则）：
//! ```text
//! MeshLink Wintun
//!      ↓
//! Overlay Router
//!   ├─ DirectLinkProvider   （已验收：crates/directlink）
//!   └─ N2NProvider          （本文件：crates/transport-n2n）
//! ```text
//! - N2NProvider 走**独立** UDP socket 与 N2N Supernode（真实独立进程）；
//! - 数据面：Wintun L3 → Noise 加密（directlink::crypto 复用）→ N2N PACKET
//!   （社区层 AES-256-GCM）→ Supernode 原样中继 → 对端反向解密；
//! - **无第二 TAP**：本 Provider 不创建任何网卡，帧全部经 trait 与内存通道流转；
//! - N2N 不管理 Overlay IP / 不修改系统 Route / DNS；
//! - Supernode 不持有社区密钥，只能路由密文帧（看不到 MeshLink Noise 密文）。
//!
//! 熔断（每 Supernode 独立 scope + Provider 级 scope）：
//! - n2n.supernode.<sn_id>：注册/查询/健康探测失败累计 → OPEN；
//! - n2n.provider：引擎级 Fatal（socket 失效等）→ 立即 OPEN；
//! - Supernode 重启 → 健康探测成功 → HALF_OPEN probe → CLOSED。
//!
//! 路径语义（M1-2）：数据经当前 Supernode 中继（A → SN → B）；
//! PUNCH/P2P 直连为协议保留位，自动选路留给 M1-3。

use crate::proto::*;
use async_trait::async_trait;
use circuit_breaker::manager::CircuitBreakerManager;
use circuit_breaker::scope::BreakerScope;
use circuit_breaker::{Decision, MonotonicClock};
use config_manager::RuntimeParams;
use directlink::crypto::{self, CryptoPolicy, InitiatorHandshake, NoiseChannel, RecvOutcome, Role, StaticIdentity};
use mesh_common::{ErrorCode, MeshError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use transport_api::{
    HealthSnapshot, Ipv4Packet, PathInfo, PathKind, PeerHints, PeerId, ProbeResult,
    SupernodeId, TransportConfig, TransportEvent, TransportProvider, TransportStats,
};

/// 一个可用的 N2N Supernode 端点。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupernodeEndpoint {
    pub id: String,
    pub host: String,
    pub port: u16,
    /// 越小越优先（第一版仅 priority + health，不做复杂 Path Manager）。
    pub priority: u8,
}

impl SupernodeEndpoint {
    pub fn addr(&self) -> Result<SocketAddr, MeshError> {
        use std::net::ToSocketAddrs;
        (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| MeshError::new(ErrorCode::ConfigInvalid, format!("Supernode {} 解析失败: {e}", self.id)))?
            .next()
            .ok_or_else(|| MeshError::new(ErrorCode::ConfigInvalid, format!("Supernode {} 无地址", self.id)))
    }
}

/// N2N Transport 参数。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct N2NParams {
    pub supernodes: Vec<SupernodeEndpoint>,
    pub community: String,
    pub network_id: String,
    /// 健康探测间隔（毫秒）。
    pub health_interval_ms: u64,
    /// 控制面请求超时（毫秒）。
    pub request_timeout_ms: u64,
    /// 连续失败阈值 → OPEN。
    pub failure_threshold: u32,
    /// OPEN → HALF_OPEN 冷却秒数。
    pub open_cooldown_secs: u64,
    /// HALF_OPEN 连续探测成功次数 → CLOSED。
    pub half_open_success_threshold: u32,
}

impl Default for N2NParams {
    fn default() -> Self {
        Self {
            supernodes: vec![],
            community: "meshlink".into(),
            network_id: "default".into(),
            health_interval_ms: 3000,
            request_timeout_ms: 1500,
            failure_threshold: 3,
            open_cooldown_secs: 2,
            half_open_success_threshold: 2,
        }
    }
}

impl N2NParams {
    fn breaker_params(&self) -> circuit_breaker::params::BreakerParams {
        circuit_breaker::params::BreakerParams {
            failure_threshold: self.failure_threshold,
            cooldown: circuit_breaker::params::CooldownStrategy::Fixed {
                secs: self.open_cooldown_secs,
            },
            half_open_success_threshold: self.half_open_success_threshold,
            max_half_open_probes: 1,
        }
    }
}

/// 单 peer N2N 会话。
struct PeerN2NSession {
    peer_device_id: String,
    /// 对端直连端点（QUERY_PEER 获知；M1-2 仅诊断，数据仍走 SN 中继）。
    peer_addr: Mutex<Option<SocketAddr>>,
    channel: Mutex<Option<NoiseChannel>>,
    rx_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    /// 解密后 plaintext 接收端（packet_rx 取走一次）。
    rx_rx: Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>>,
    connected: AtomicBool,
    established_at: Mutex<Option<Instant>>,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
}

/// N2NTransport 内部共享状态。
struct N2NState {
    params: N2NParams,
    socket: Arc<UdpSocket>,
    community_key: [u8; 32],
    /// 当前选中 Supernode（优先选 priority + 未熔断）。
    current_sn: Mutex<Option<SupernodeEndpoint>>,
    /// 动态 Supernode 池（Controller Registry 下发；默认 = params.supernodes）。
    sn_pool: Mutex<Vec<SupernodeEndpoint>>,
    sessions: Mutex<HashMap<PeerId, Arc<PeerN2NSession>>>,
    /// 控制面等待器（cookie → sender）。
    pending_acks: Mutex<HashMap<u64, std_mpsc::Sender<Vec<u8>>>>,
    /// 未完成 initiator 握手（peer_device_id → handshake）。
    pending_handshakes: Mutex<HashMap<String, InitiatorHandshake>>,
    /// initiator 握手完成通知（peer_device_id → sender(NewEpoch)）。
    noise_notify: Mutex<HashMap<String, std_mpsc::Sender<()>>>,
    /// 接受方状态。
    accept_peer: Mutex<Option<PeerId>>,
    expected_keys: Mutex<HashMap<String, [u8; 32]>>,
    require_initiator: Mutex<HashMap<String, bool>>,
    /// Noise 身份配置（identity + network_id）。
    noise_cfg: Mutex<Option<(Arc<StaticIdentity>, String)>>,
    cookie: AtomicU64,
    /// AES-GCM 社区层 nonce 全局计数器。
    nonce_seq: AtomicU64,
    /// 熔断管理器（n2n.supernode.<id> + n2n.provider）。
    breakers: Mutex<CircuitBreakerManager>,
    clock: MonotonicClock,
    stop: AtomicBool,
    join: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// 引擎级健康（Provider breaker 状态）。
    provider_open: AtomicBool,
    last_health_at: Mutex<Instant>,
    last_health_ok: AtomicBool,
}

impl N2NState {
    /// 生成社区层 nonce（全局单调计数 → 12 字节）。
    fn nonce(&self) -> [u8; 12] {
        let seq = self.nonce_seq.fetch_add(1, Ordering::Relaxed);
        let mut n = [0u8; 12];
        n[4..12].copy_from_slice(&seq.to_be_bytes());
        n
    }

    fn record_sn_success(&self, sn_id: &str) {
        let scope = BreakerScope::N2NSupernode { sn_id: sn_id.into() };
        let mut b = self.breakers.lock().unwrap();
        b.record_success(&scope, &self.clock);
        self.last_health_ok.store(true, Ordering::Release);
    }

    fn record_sn_failure(&self, sn_id: &str, fatal: bool) {
        let scope = BreakerScope::N2NSupernode { sn_id: sn_id.into() };
        let mut b = self.breakers.lock().unwrap();
        if fatal {
            b.record_fatal(&scope, &self.clock, "supernode fatal");
            self.provider_open.store(true, Ordering::Release);
        } else {
            b.record_failure(&scope, &self.clock);
        }
    }
}

/// 健康探测模式：CLOSED 业务路径 / HALF_OPEN 探测窗口 / OPEN 冷却跳过。
enum ProbeMode {
    Closed,
    HalfOpen,
    Skip,
}

impl N2NState {
    /// 单次健康探测（REGISTER_SUPER 往返）→ 驱动熔断状态机。
    /// 返回 true = 探测成功（SN 存活）；false = 失败/超时。
    /// 规则（用户规格 M1-2）：kill → 失败累计 OPEN；restart → HALF_OPEN probe → CLOSED。
    fn sn_health_probe(
        &self,
        sn: &SupernodeEndpoint,
        addr: SocketAddr,
        timeout: Duration,
    ) -> bool {
        let scope = BreakerScope::N2NSupernode { sn_id: sn.id.clone() };
        let mode = {
            let mut b = self.breakers.lock().unwrap();
            match b.allow_request(&scope, &self.clock) {
                Decision::Allowed => ProbeMode::Closed,
                Decision::Rejected(circuit_breaker::RejectReason::HalfOpenProbeOnly) => {
                    if b.begin_probe(&scope, &self.clock) {
                        ProbeMode::HalfOpen
                    } else {
                        ProbeMode::Skip
                    }
                }
                Decision::Rejected(circuit_breaker::RejectReason::CircuitOpen) => {
                    // 冷却未到：本轮跳过（evaluate 在 allow_request 内已推进）
                    ProbeMode::Skip
                }
            }
        };
        match mode {
            ProbeMode::Skip => return true,
            _ => {}
        }

        let cookie = self.cookie.fetch_add(1, Ordering::Relaxed);
        let device_id = self
            .noise_cfg
            .lock()
            .unwrap()
            .as_ref()
            .map(|(id, _)| id.device_id().to_string())
            .unwrap_or_default();
        let body = serde_json::to_vec(&RegisterSuper { device_id, cookie }).unwrap_or_default();
        let header = match N2nHeader::new(&self.params.community, PacketType::RegisterSuper) {
            Ok(h) => h,
            Err(_) => return false,
        };
        let wire = encode(&header, &body);
        let ok = match self.socket.send_to(&wire, addr) {
            Ok(_) => {
                let (tx, rx) = std_mpsc::channel::<Vec<u8>>();
                self.pending_acks.lock().unwrap().insert(cookie, tx);
                let got = rx.recv_timeout(timeout).is_ok();
                self.pending_acks.lock().unwrap().remove(&cookie);
                got
            }
            Err(_) => false,
        };

        let mut b = self.breakers.lock().unwrap();
        match mode {
            ProbeMode::Closed => {
                if ok {
                    b.record_success(&scope, &self.clock);
                } else {
                    b.record_failure(&scope, &self.clock);
                }
            }
            ProbeMode::HalfOpen => {
                if ok {
                    b.probe_success(&scope, &self.clock);
                } else {
                    b.probe_failure(&scope, &self.clock);
                }
            }
            ProbeMode::Skip => {}
        }
        self.last_health_ok.store(ok, Ordering::Release);
        ok
    }
}

/// 错误码辅助。
fn err(code: ErrorCode, msg: impl Into<String>) -> MeshError {
    MeshError::new(code, msg)
}

/// N2N Transport Provider。
pub struct N2NTransport {
    state: Arc<N2NState>,
}

impl N2NTransport {
    pub fn new(params: N2NParams) -> Result<Self, MeshError> {
        // Supernode 池可为空（M1-2：Controller Registry 动态下发后再 set_supernodes）。
        if params.community.is_empty() || params.community.len() > COMMUNITY_MAX_LEN {
            return Err(err(ErrorCode::ConfigInvalid, "N2N community 长度非法"));
        }
        let socket = Arc::new(
            UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| err(ErrorCode::TransportStartFailed, format!("N2N socket 绑定失败: {e}")))?,
        );
        socket
            .set_nonblocking(true)
            .map_err(|e| err(ErrorCode::TransportStartFailed, format!("N2N socket 非阻塞设置失败: {e}")))?;
        let community_key = community_key(&params.network_id, &params.community);
        let runtime = RuntimeParams {
            circuit_failure_threshold: params.failure_threshold,
            circuit_open_cooldown_secs: params.open_cooldown_secs,
            half_open_success_threshold: params.half_open_success_threshold,
            max_half_open_probes: 1,
            sn_health_interval_secs: (params.health_interval_ms / 1000).max(1) as u32,
            sn_offline_threshold: params.failure_threshold,
            ..RuntimeParams::default()
        };
        let breakers = Mutex::new(CircuitBreakerManager::new(runtime));
        let state = Arc::new(N2NState {
            params: params.clone(),
            socket,
            community_key,
            current_sn: Mutex::new(None),
            sn_pool: Mutex::new(params.supernodes.clone()),
            sessions: Mutex::new(HashMap::new()),
            pending_acks: Mutex::new(HashMap::new()),
            pending_handshakes: Mutex::new(HashMap::new()),
            noise_notify: Mutex::new(HashMap::new()),
            accept_peer: Mutex::new(None),
            expected_keys: Mutex::new(HashMap::new()),
            require_initiator: Mutex::new(HashMap::new()),
            noise_cfg: Mutex::new(None),
            cookie: AtomicU64::new(1),
            nonce_seq: AtomicU64::new(1),
            breakers,
            clock: MonotonicClock::new(),
            stop: AtomicBool::new(false),
            join: Mutex::new(None),
            provider_open: AtomicBool::new(false),
            last_health_at: Mutex::new(Instant::now()),
            last_health_ok: AtomicBool::new(false),
        });

        // 后台接收线程（N2N 帧分派）。
        let st = state.clone();
        let join = std::thread::Builder::new()
            .name("n2n-rx".into())
            .spawn(move || Self::rx_loop(st))
            .map_err(|e| err(ErrorCode::TransportStartFailed, format!("N2N RX 线程启动失败: {e}")))?;
        *state.join.lock().unwrap() = Some(join);

        // 健康探测线程（SN kill → OPEN；restart → HALF_OPEN → CLOSED）。
        let st = state.clone();
        let health_join = std::thread::Builder::new()
            .name("n2n-health".into())
            .spawn(move || Self::health_loop(st))
            .map_err(|e| err(ErrorCode::TransportStartFailed, format!("N2N 健康线程启动失败: {e}")))?;
        state
            .join
            .lock()
            .unwrap()
            .as_mut()
            .map(|_j| ());
        // 第二线程句柄单独保存：为简化生命周期，健康线程随 stop 标志自行退出。
        let _ = health_join;
        Ok(Self { state })
    }

    fn next_cookie(&self) -> u64 {
        self.state.cookie.fetch_add(1, Ordering::Relaxed)
    }

    /// 动态更新 Supernode 池（Controller Supernode Registry 下发；可随时替换）。
    pub fn set_supernodes(&self, supernodes: Vec<SupernodeEndpoint>) {
        *self.state.sn_pool.lock().unwrap() = supernodes;
    }

    /// 当前 Supernode 池。
    pub fn supernodes(&self) -> Vec<SupernodeEndpoint> {
        self.state.sn_pool.lock().unwrap().clone()
    }

    /// 当前 Supernode 地址（熔断门 + priority 选择）。
    fn select_supernode(&self) -> Option<(SupernodeEndpoint, SocketAddr)> {
        let mut candidates: Vec<SupernodeEndpoint> = self.state.sn_pool.lock().unwrap().clone();
        candidates.sort_by_key(|s| s.priority);
        for sn in candidates {
            let scope = BreakerScope::N2NSupernode { sn_id: sn.id.clone() };
            let decision = {
                let mut b = self.state.breakers.lock().unwrap();
                b.allow_request(&scope, &self.state.clock)
            };
            match decision {
                Decision::Allowed => {
                    let addr = sn.addr().ok()?;
                    return Some((sn, addr));
                }
                Decision::Rejected(_) => continue,
            }
        }
        None
    }

    /// 发送一个控制面/数据帧到指定地址。
    fn send_frame(&self, community: &str, ptype: PacketType, body: &[u8], dst: SocketAddr) -> Result<(), MeshError> {
        let header = N2nHeader::new(community, ptype)
            .map_err(|e| err(ErrorCode::Internal, e))?;
        let wire = encode(&header, body);
        self.state
            .socket
            .send_to(&wire, dst)
            .map(|_| ())
            .map_err(|e| err(ErrorCode::TransportSendFailed, format!("N2N 发送失败: {e}")))
    }

    /// 等待某个 cookie 的 ACK（带超时）。
    fn wait_ack(&self, cookie: u64, timeout: Duration) -> Result<Vec<u8>, MeshError> {
        let (tx, rx) = std_mpsc::channel::<Vec<u8>>();
        self.state.pending_acks.lock().unwrap().insert(cookie, tx);
        let result = rx.recv_timeout(timeout);
        self.state.pending_acks.lock().unwrap().remove(&cookie);
        match result {
            Ok(body) => Ok(body),
            Err(_) => Err(err(ErrorCode::TransportTimeout, "N2N 控制面响应超时")),
        }
    }

    /// 注册到 Supernode 并确认（健康/建连共用）。
    fn register_with(&self, sn: &SupernodeEndpoint, addr: SocketAddr, cookie: u64, timeout: Duration) -> Result<RegisterSuperAck, MeshError> {
        let body = serde_json::to_vec(&RegisterSuper { device_id: self.device_id().to_string(), cookie })
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        self.send_frame(&self.state.params.community, PacketType::RegisterSuper, &body, addr)?;
        let ack_body = self.wait_ack(cookie, timeout)?;
        let ack: RegisterSuperAck = serde_json::from_slice(&ack_body)
            .map_err(|e| err(ErrorCode::ControllerProtocol, format!("REGISTER_SUPER_ACK 解析失败: {e}")))?;
        Ok(ack)
    }

    fn device_id(&self) -> String {
        // device_id 在 configure_noise 前由调用方设置；connect 前必已配置。
        self.state
            .noise_cfg
            .lock()
            .unwrap()
            .as_ref()
            .map(|(id, _)| id.device_id().to_string())
            .unwrap_or_else(|| "unconfigured".to_string())
    }

    fn record_sn_success(&self, sn_id: &str) {
        self.state.record_sn_success(sn_id)
    }

    fn record_sn_failure(&self, sn_id: &str, fatal: bool) {
        self.state.record_sn_failure(sn_id, fatal)
    }

    /// 每 Supernode 熔断状态（诊断用）。
    pub fn breaker_states(&self) -> Vec<serde_json::Value> {
        let mut b = self.state.breakers.lock().unwrap();
        let mut out = Vec::new();
        for sn in &self.state.sn_pool.lock().unwrap().clone() {
            let scope = BreakerScope::N2NSupernode { sn_id: sn.id.clone() };
            let st = b.state(&scope, &self.state.clock);
            let fails = b.status(&scope, &self.state.clock).consecutive_failures;
            out.push(serde_json::json!({
                "sn_id": sn.id,
                "host": sn.host,
                "port": sn.port,
                "priority": sn.priority,
                "state": st.as_str(),
                "consecutive_failures": fails,
            }));
        }
        out
    }

    /// N2N 运行状态（诊断用）。
    pub fn n2n_status(&self) -> serde_json::Value {
        let sn = self.state.current_sn.lock().unwrap().clone();
        let session_count = self.state.sessions.lock().unwrap().len();
        serde_json::json!({
            "provider_state": if self.state.provider_open.load(Ordering::Acquire) { "open" } else { "closed" },
            "current_supernode": sn.map(|s| serde_json::json!({
                "id": s.id, "host": s.host, "port": s.port, "priority": s.priority,
            })),
            "community": self.state.params.community,
            "sessions": session_count,
            "last_health_ok": self.state.last_health_ok.load(Ordering::Acquire),
            "breakers": self.breaker_states(),
        })
    }

    /// 指定 Supernode 熔断状态（closed/half_open/open）。
    pub fn breaker_state(&self, sn_id: &str) -> String {
        let scope = BreakerScope::N2NSupernode { sn_id: sn_id.into() };
        let mut b = self.state.breakers.lock().unwrap();
        b.state(&scope, &self.state.clock).as_str().to_string()
    }

    /// Provider 级熔断（引擎致命）。
    pub fn provider_open(&self) -> bool {
        self.state.provider_open.load(Ordering::Acquire)
    }

    /// 最近一次健康探测结果。
    pub fn last_health_ok(&self) -> bool {
        self.state.last_health_ok.load(Ordering::Acquire)
    }

    /// 会话概要列表（诊断用）。
    pub fn session_info_all(&self) -> Vec<serde_json::Value> {
        let sessions = self.state.sessions.lock().unwrap();
        sessions
            .iter()
            .map(|(peer, s)| {
                serde_json::json!({
                    "peer": peer,
                    "peer_device_id": s.peer_device_id,
                    "connected": s.connected.load(Ordering::Acquire),
                    "peer_addr": s.peer_addr.lock().unwrap().map(|a| a.to_string()),
                    "tx_packets": s.tx_packets.load(Ordering::Relaxed),
                    "rx_packets": s.rx_packets.load(Ordering::Relaxed),
                })
            })
            .collect()
    }

    // ------------------------------------------------------------------
    // 对外会话 API（mesh-agent N2N 流程调用；镜像 DirectLinkTransport 形状）
    // ------------------------------------------------------------------

    /// 配置 Noise 身份（M1-2：复用 directlink::crypto 的 Noise_IK）。
    pub fn configure_noise(&self, identity: Arc<StaticIdentity>, network_id: String) {
        *self.state.noise_cfg.lock().unwrap() = Some((identity, network_id));
    }

    /// 设置期望的 initiator 公钥（Controller Registry 下发，双向身份验证）。
    pub fn set_expected_initiator(&self, peer: &PeerId, public_key: [u8; 32]) {
        self.state.expected_keys.lock().unwrap().insert(peer.0.clone(), public_key);
    }

    /// 要求 initiator 身份与 Registry 一致（不匹配 → 拒绝握手）。
    pub fn require_initiator_identity(&self, peer: &PeerId) {
        self.state.require_initiator.lock().unwrap().insert(peer.0.clone(), true);
    }

    /// 进入接受模式（creator 侧）。
    pub fn start_accepting(&self, peer: PeerId, _tag: String) {
        *self.state.accept_peer.lock().unwrap() = Some(peer.clone());
        self.ensure_session(peer);
        // 注册到 Supernode（使本端可被发现；健康线程持续刷新）。
        if let Some((sn, addr)) = self.select_supernode() {
            let cookie = self.next_cookie();
            let timeout = Duration::from_millis(self.state.params.request_timeout_ms);
            match self.register_with(&sn, addr, cookie, timeout) {
                Ok(_) => {
                    self.record_sn_success(&sn.id);
                    *self.state.current_sn.lock().unwrap() = Some(sn.clone());
                }
                Err(_) => {
                    self.record_sn_failure(&sn.id, false);
                }
            }
        }
    }

    /// 对端 packet_rx 通道（与 DirectLinkTransport 同形状）。
    pub fn packet_rx(&self, peer: &PeerId) -> Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        self.state
            .sessions
            .lock()
            .unwrap()
            .get(peer)
            .and_then(|s| s.rx_rx.lock().unwrap().take())
    }

    pub fn session_info(&self, peer: &PeerId) -> Option<(SocketAddr, SocketAddr, String)> {
        let sessions = self.state.sessions.lock().unwrap();
        let s = sessions.get(peer)?;
        let peer_addr = s.peer_addr.lock().unwrap();
        let sn_addr = self.state.current_sn.lock().unwrap().as_ref().and_then(|sn| sn.addr().ok());
        Some((
            sn_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            peer_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
            "n2n-relay".into(),
        ))
    }

    pub fn crypto_report(&self, peer: &PeerId) -> serde_json::Value {
        let sessions = self.state.sessions.lock().unwrap();
        match sessions.get(peer) {
            Some(s) => {
                let ch = s.channel.lock().unwrap();
                match ch.as_ref() {
                    Some(c) => serde_json::json!({
                        "remote_fingerprint": c.remote_fingerprint(),
                        "role": c.role().as_str(),
                        "session_id_hex": hex_encode(&c.session_id()),
                        "epoch": c.current_epoch_id(),
                        "frames_tx": c.stats.frames_tx,
                        "frames_rx": c.stats.frames_rx,
                        "bytes_encrypted": c.stats.bytes_encrypted,
                        "replay_rejected": c.stats.replay_rejected,
                        "decrypt_failed": c.stats.decrypt_failed,
                    }),
                    None => serde_json::json!({ "state": "handshaking" }),
                }
            }
            None => serde_json::json!({ "state": "no_session" }),
        }
    }

    pub fn punch_evidence(&self) -> serde_json::Value {
        serde_json::json!({ "path": "n2n", "note": "N2N 数据面经 Supernode 中继（M1-2），无 ICE punch" })
    }

    /// 断开 peer。
    pub fn disconnect_peer(&self, peer: &PeerId) {
        let mut sessions = self.state.sessions.lock().unwrap();
        if let Some(s) = sessions.remove(peer) {
            s.connected.store(false, Ordering::Release);
        }
    }

    pub fn stop_keepalive(&self, _peer: &PeerId) {}

    pub fn connected(&self, peer: &PeerId) -> bool {
        self.state
            .sessions
            .lock()
            .unwrap()
            .get(peer)
            .map(|s| s.connected.load(Ordering::Acquire))
            .unwrap_or(false)
    }

    /// N2N 建连：注册 + 查询对端（M1-2 relay 路径）。
    pub fn connect_peer(&self, peer: PeerId, _hints: PeerHints) -> Result<(), MeshError> {
        let Some((sn, addr)) = self.select_supernode() else {
            return Err(err(ErrorCode::N2NSupernodeUnavailable, "所有 Supernode 均熔断或不可达"));
        };
        let timeout = Duration::from_millis(self.state.params.request_timeout_ms);
        // 1) 注册
        let reg_cookie = self.next_cookie();
        match self.register_with(&sn, addr, reg_cookie, timeout) {
            Ok(_) => {
                self.record_sn_success(&sn.id);
                *self.state.current_sn.lock().unwrap() = Some(sn.clone());
            }
            Err(e) => {
                self.record_sn_failure(&sn.id, false);
                return Err(e);
            }
        }
        // 2) 查询对端
        let q_cookie = self.next_cookie();
        let qbody = serde_json::to_vec(&QueryPeer { target_device_id: peer.0.clone(), cookie: q_cookie })
            .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        self.send_frame(&self.state.params.community, PacketType::QueryPeer, &qbody, addr)?;
        let ack_body = match self.wait_ack(q_cookie, timeout) {
            Ok(b) => b,
            Err(e) => {
                self.record_sn_failure(&sn.id, false);
                return Err(e);
            }
        };
        let ack: RegisterSuperAck = serde_json::from_slice(&ack_body)
            .map_err(|e| err(ErrorCode::ControllerProtocol, format!("QUERY_PEER 应答解析失败: {e}")))?;
        let peer_addr = ack.peer_public.as_deref().and_then(|s| s.parse().ok());
        if peer_addr.is_none() {
            return Err(err(ErrorCode::N2NPeerNotFound, format!("Supernode 未发现对端 {}（可能离线）", peer.0)));
        }
        self.ensure_session(peer.clone());
        if let Some(s) = self.state.sessions.lock().unwrap().get(&peer) {
            *s.peer_addr.lock().unwrap() = peer_addr;
        }
        self.record_sn_success(&sn.id);
        tracing::info!(target: "n2n", sn = %sn.id, peer = %peer.0, direct = ?peer_addr, "N2N 对端发现（relay 路径就绪）");
        Ok(())
    }

    fn ensure_session(&self, peer: PeerId) {
        let mut sessions = self.state.sessions.lock().unwrap();
        if !sessions.contains_key(&peer) {
            let (rx_tx, rx_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            sessions.insert(
                peer.clone(),
                Arc::new(PeerN2NSession {
                    peer_device_id: peer.0.clone(),
                    peer_addr: Mutex::new(None),
                    channel: Mutex::new(None),
                    rx_tx,
                    rx_rx: Mutex::new(Some(rx_rx)),
                    connected: AtomicBool::new(false),
                    established_at: Mutex::new(None),
                    tx_packets: AtomicU64::new(0),
                    rx_packets: AtomicU64::new(0),
                    tx_bytes: AtomicU64::new(0),
                    rx_bytes: AtomicU64::new(0),
                }),
            );
        }
    }

    /// Noise IK initiator（joiner 侧）：发 msg1 → 等 msg2 → 建立 NoiseChannel。
    pub async fn start_noise_initiator(
        &self,
        peer: &PeerId,
        identity: Arc<StaticIdentity>,
        network_id: &str,
        peer_device: &str,
        peer_key: &[u8; 32],
    ) -> Result<(), MeshError> {
        let (_, addr) = self
            .state
            .current_sn
            .lock()
            .unwrap()
            .clone()
            .and_then(|sn| sn.addr().ok().map(|a| (sn, a)))
            .ok_or_else(|| err(ErrorCode::N2NSupernodeUnavailable, "N2N 未连接 Supernode"))?;
        let hs = crypto::initiate(&identity, network_id, peer_device, peer_key, 0, None)?;
        let msg1 = hs.msg1_frame().to_vec();
        let (notify_tx, notify_rx) = std_mpsc::channel::<()>();
        self.state
            .pending_handshakes
            .lock()
            .unwrap()
            .insert(peer.0.clone(), hs);
        self.state
            .noise_notify
            .lock()
            .unwrap()
            .insert(peer.0.clone(), notify_tx);
        self.ensure_session(peer.clone());

        // 发 msg1（PACKET 中继）
        let nonce = self.nonce();
        let sealed = community_seal(&self.state.community_key, &nonce, &msg1)
            .map_err(|e| err(ErrorCode::Internal, e))?;
        let body = serde_json::to_vec(&Packet {
            src_device_id: self.device_id(),
            dst_device_id: peer.0.clone(),
            ciphertext: sealed,
            nonce,
        })
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        self.send_frame(&self.state.params.community, PacketType::Packet, &body, addr)?;

        let timeout = Duration::from_millis(self.state.params.request_timeout_ms.saturating_mul(4));
        let started = Instant::now();
        loop {
            match notify_rx.recv_timeout(Duration::from_millis(200)) {
                Ok(()) => {
                    let ok = self.state.sessions.lock().unwrap().get(peer).map(|s| s.connected.load(Ordering::Acquire)).unwrap_or(false);
                    if ok {
                        return Ok(());
                    }
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => {
                    if started.elapsed() > timeout {
                        self.state.pending_handshakes.lock().unwrap().remove(&peer.0);
                        self.state.noise_notify.lock().unwrap().remove(&peer.0);
                        return Err(err(ErrorCode::CryptoHandshakeFailed, "N2N Noise IK 握手超时"));
                    }
                    // 幂等重发 msg1
                    let nonce2 = self.nonce();
                    let sealed2 = community_seal(&self.state.community_key, &nonce2, &msg1)
                        .map_err(|e| err(ErrorCode::Internal, e))?;
                    let body2 = serde_json::to_vec(&Packet {
                        src_device_id: self.device_id(),
                        dst_device_id: peer.0.clone(),
                        ciphertext: sealed2,
                        nonce: nonce2,
                    })
                    .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
                    let _ = self.send_frame(&self.state.params.community, PacketType::Packet, &body2, addr);
                }
                Err(_) => return Err(err(ErrorCode::Internal, "N2N 握手通知通道关闭")),
            }
        }
    }

    /// 发送 L3 数据（Noise 加密 → 社区层 → Supernode 中继）。
    pub async fn send_packet(&self, peer: PeerId, pkt: Ipv4Packet) -> Result<(), MeshError> {
        let addr = self
            .state
            .current_sn
            .lock()
            .unwrap()
            .clone()
            .and_then(|sn| sn.addr().ok())
            .ok_or_else(|| err(ErrorCode::N2NSupernodeUnavailable, "N2N 未连接 Supernode"))?;
        let sessions = self.state.sessions.lock().unwrap();
        let s = sessions
            .get(&peer)
            .cloned()
            .ok_or_else(|| err(ErrorCode::TransportPeerUnreachable, format!("{peer:?} 未连接")))?;
        let wire = {
            let mut ch = s.channel.lock().unwrap();
            match ch.as_mut() {
                Some(c) => {
                    let mut w = Vec::with_capacity(pkt.bytes.len() + 64);
                    c.send(&pkt.bytes, &mut w)?;
                    w
                }
                None => return Err(err(ErrorCode::NoiseNotEstablished, "Noise 通道尚未建立")),
            }
        };
        s.tx_packets.fetch_add(1, Ordering::Relaxed);
        s.tx_bytes.fetch_add(wire.len() as u64, Ordering::Relaxed);
        let nonce = self.nonce();
        let sealed = community_seal(&self.state.community_key, &nonce, &wire)
            .map_err(|e| err(ErrorCode::Internal, e))?;
        let body = serde_json::to_vec(&Packet {
            src_device_id: self.device_id(),
            dst_device_id: peer.0.clone(),
            ciphertext: sealed,
            nonce,
        })
        .map_err(|e| err(ErrorCode::Internal, e.to_string()))?;
        self.send_frame(&self.state.params.community, PacketType::Packet, &body, addr)
    }

    /// 生成社区层 nonce（全局单调计数 → 12 字节）。
    fn nonce(&self) -> [u8; 12] {
        self.state.nonce()
    }

    /// 接收线程：N2N 帧分派。
    fn rx_loop(st: Arc<N2NState>) {
        let mut buf = [0u8; MAX_FRAME_LEN];
        while !st.stop.load(Ordering::Acquire) {
            let (n, from) = match st.socket.recv_from(&mut buf) {
                Ok(x) => x,
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
            };
            let frame = &buf[..n];
            let (header, payload) = match decode(frame) {
                Ok(x) => x,
                Err(_) => continue,
            };
            // 只处理本社区帧（防跨社区串扰）
            if header.community != st.params.community {
                continue;
            }
            match header.packet_type {
                PacketType::RegisterSuperAck => {
                    if let Ok(ack) = serde_json::from_slice::<RegisterSuperAck>(payload) {
                        if let Some(tx) = st.pending_acks.lock().unwrap().get(&ack.cookie).cloned() {
                            let _ = tx.send(payload.to_vec());
                        }
                    }
                }
                PacketType::Punch => {
                    // M1-2 记录对端端点（P2P 留给 M1-3）
                    if let Ok(punch) = serde_json::from_slice::<Punch>(payload) {
                        if let Some(addr) = punch.peer_endpoint.parse().ok() {
                            let sessions = st.sessions.lock().unwrap();
                            for s in sessions.values() {
                                if s.peer_device_id == punch.target_device_id {
                                    *s.peer_addr.lock().unwrap() = Some(addr);
                                }
                            }
                        }
                    }
                }
                PacketType::Packet => {
                    Self::handle_packet(&st, payload);
                }
                PacketType::RegisterSuper | PacketType::QueryPeer | PacketType::RegisterSuperNack => {
                    // 边缘不主动收这些
                }
            }
            let _ = from;
        }
    }

    /// 处理一个 PACKET 载荷。
    fn handle_packet(st: &Arc<N2NState>, payload: &[u8]) {
        let pkt: Packet = match serde_json::from_slice(payload) {
            Ok(p) => p,
            Err(_) => return,
        };
        // 社区层解密
        let plain = match community_open(&st.community_key, &pkt.nonce, &pkt.ciphertext) {
            Ok(p) => p,
            Err(_) => return,
        };
        // 解析 MeshLink Noise 帧
        let f = match directlink::crypto::frame::decode(&plain) {
            Ok(f) => f,
            Err(_) => return,
        };
        let peer = PeerId(pkt.src_device_id.clone());
        if f.is_handshake() {
            if f.has_intro() {
                // msg1：仅接受方处理
                Self::handle_msg1(st, &peer, &plain);
            } else {
                // msg2：完成 initiator 握手
                Self::handle_msg2(st, &peer, &plain);
            }
            return;
        }
        // 数据帧：Noise 解密 → packet_rx
        let sessions = st.sessions.lock().unwrap();
        let Some(s) = sessions.get(&peer) else { return };
        let mut ch = s.channel.lock().unwrap();
        let Some(c) = ch.as_mut() else { return };
        match c.recv(&f) {
            RecvOutcome::Accepted(pt) => {
                s.rx_packets.fetch_add(1, Ordering::Relaxed);
                s.rx_bytes.fetch_add(pt.len() as u64, Ordering::Relaxed);
                let _ = s.rx_tx.send(pt);
            }
            RecvOutcome::Rejected(why) => {
                tracing::warn!(target: "n2n", peer = %peer.0, why, "N2N Noise 数据帧拒绝");
            }
        }
    }

    /// msg1（responder 侧）：respond → 建 NoiseChannel → 回 msg2。
    fn handle_msg1(st: &Arc<N2NState>, peer: &PeerId, plain: &[u8]) {
        // 仅接受模式下处理
        let accept = st.accept_peer.lock().unwrap().clone();
        if accept.as_ref() != Some(peer) {
            return;
        }
        let expected = {
            let k = st.expected_keys.lock().unwrap().get(&peer.0).copied();
            let req = st.require_initiator.lock().unwrap().get(&peer.0).copied().unwrap_or(false);
            if req { k } else { None }
        };
        let (identity, network_id) = {
            let cfg = st.noise_cfg.lock().unwrap().clone();
            match cfg {
                Some((id, nid)) => (id, nid),
                None => return,
            }
        };
        match crypto::respond(&identity, &network_id, plain, expected.as_ref()) {
            Ok((epoch, msg2_wire)) => {
                // 建 NoiseChannel（responder 角色）
                let channel = NoiseChannel::from_epoch(epoch, Role::Responder, identity.device_id(), &peer.0, CryptoPolicy::default());
                {
                    let sessions = st.sessions.lock().unwrap();
                    if let Some(s) = sessions.get(peer) {
                        *s.channel.lock().unwrap() = Some(channel);
                        s.connected.store(true, Ordering::Release);
                        *s.established_at.lock().unwrap() = Some(Instant::now());
                    }
                }
                // 回 msg2（PACKET 中继）
                let addr = st.current_sn.lock().unwrap().clone().and_then(|sn| sn.addr().ok());
                let Some(addr) = addr else { return };
                let nonce = st.nonce();
                let sealed = community_seal(&st.community_key, &nonce, &msg2_wire).unwrap_or_default();
                let body = serde_json::to_vec(&Packet {
                    src_device_id: identity.device_id().to_string(),
                    dst_device_id: peer.0.clone(),
                    ciphertext: sealed,
                    nonce,
                })
                .unwrap_or_default();
                let header = N2nHeader::new(&st.params.community, PacketType::Packet).ok();
                if let Some(h) = header {
                    let _ = st.socket.send_to(&encode(&h, &body), addr);
                }
            }
            Err(e) => {
                tracing::warn!(target: "n2n", peer = %peer.0, error = %e, "N2N responder 握手失败（身份不符则 DEVICE_KEY_MISMATCH）");
            }
        }
    }

    /// msg2：完成 initiator 握手。
    fn handle_msg2(st: &Arc<N2NState>, peer: &PeerId, plain: &[u8]) {
        let hs = st.pending_handshakes.lock().unwrap().remove(&peer.0);
        let Some(hs) = hs else { return };
        let (identity, network_id) = match st.noise_cfg.lock().unwrap().clone() {
            Some((id, nid)) => (id, nid),
            None => return,
        };
        let epoch = match hs.complete(plain) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(target: "n2n", peer = %peer.0, error = %e, "N2N initiator 握手完成失败");
                return;
            }
        };
        let channel = NoiseChannel::from_epoch(epoch, Role::Initiator, identity.device_id(), &peer.0, CryptoPolicy::default());
        {
            let sessions = st.sessions.lock().unwrap();
            if let Some(s) = sessions.get(peer) {
                *s.channel.lock().unwrap() = Some(channel);
                s.connected.store(true, Ordering::Release);
                *s.established_at.lock().unwrap() = Some(Instant::now());
            }
        }
        if let Some(tx) = st.noise_notify.lock().unwrap().remove(&peer.0) {
            let _ = tx.send(());
        }
        let _ = network_id;
    }

    /// 健康探测线程：周期探测当前 Supernode → 驱动熔断
    /// （kill → 失败累计 OPEN；restart → HALF_OPEN probe → CLOSED）。
    fn health_loop(st: Arc<N2NState>) {
        let interval = Duration::from_millis(st.params.health_interval_ms.max(100));
        let timeout = Duration::from_millis(st.params.request_timeout_ms);
        while !st.stop.load(Ordering::Acquire) {
            std::thread::sleep(interval);
            let sn = st.current_sn.lock().unwrap().clone();
            let Some(sn) = sn else { continue };
            let Some(addr) = sn.addr().ok() else {
                st.record_sn_failure(&sn.id, false);
                continue;
            };
            let _ = st.sn_health_probe(&sn, addr, timeout);
        }
    }
}

impl Drop for N2NTransport {
    fn drop(&mut self) {
        self.state.stop.store(true, Ordering::Release);
    }
}

/// 错误码扩展：M1-2 新增 N2N 错误码。
pub mod error_codes {
    use mesh_common::{ErrorCode, MeshError};

    /// 构造 N2N 专属错误（保持 ErrorCode 枚举增量兼容）。
    pub fn n2n_err(msg: impl Into<String>) -> MeshError {
        MeshError::new(ErrorCode::TransportStartFailed, msg)
    }
}

// ---------------------------------------------------------------------------
// TransportProvider 实现
// ---------------------------------------------------------------------------

#[async_trait]
impl TransportProvider for N2NTransport {
    async fn start(&self, _cfg: TransportConfig) -> Result<(), MeshError> {
        Ok(())
    }

    async fn stop(&self, _timeout: Duration) -> Result<(), MeshError> {
        self.state.stop.store(true, Ordering::Release);
        Ok(())
    }

    async fn connect_peer(&self, peer: PeerId, hints: PeerHints) -> Result<(), MeshError> {
        self.connect_peer(peer, hints)
    }

    async fn disconnect_peer(&self, peer: PeerId) -> Result<(), MeshError> {
        self.disconnect_peer(&peer);
        Ok(())
    }

    async fn send_packet(&self, peer: PeerId, pkt: Ipv4Packet) -> Result<(), MeshError> {
        self.send_packet(peer, pkt).await
    }

    fn health(&self, peer: Option<PeerId>) -> HealthSnapshot {
        let provider_open = self.state.provider_open.load(Ordering::Acquire);
        match peer {
            Some(p) => {
                let connected = self.connected(&p);
                HealthSnapshot {
                    score: if connected && !provider_open { 100 } else { 0 },
                    rtt_ms: None,
                    loss_pct: None,
                    jitter_ms: None,
                    stall_events: 0,
                    transport_alive: connected && !provider_open,
                }
            }
            None => HealthSnapshot {
                score: if provider_open { 0 } else { 80 },
                rtt_ms: None,
                loss_pct: None,
                jitter_ms: None,
                stall_events: 0,
                transport_alive: !provider_open,
            },
        }
    }

    fn stats(&self) -> TransportStats {
        let sessions = self.state.sessions.lock().unwrap();
        let mut s = TransportStats::default();
        for p in sessions.values() {
            s.tx_packets += p.tx_packets.load(Ordering::Relaxed);
            s.rx_packets += p.rx_packets.load(Ordering::Relaxed);
            s.tx_bytes += p.tx_bytes.load(Ordering::Relaxed);
            s.rx_bytes += p.rx_bytes.load(Ordering::Relaxed);
        }
        s.peer_count = sessions.len() as u32;
        s
    }

    async fn probe(&self, _peer: PeerId) -> ProbeResult {
        ProbeResult { ok: true, rtt_ms: None }
    }

    fn path_info(&self, peer: PeerId) -> Option<PathInfo> {
        let sn = self.state.current_sn.lock().unwrap().clone()?;
        if !self.connected(&peer) {
            return None;
        }
        Some(PathInfo {
            kind: PathKind::N2nRelay(SupernodeId(sn.id.clone())),
            rtt_ms: None,
            stable_for: Duration::ZERO,
            detail: format!("n2n via {}:{}", sn.host, sn.port),
        })
    }

    async fn subscribe_events(&self, _tx: tokio::sync::mpsc::Sender<TransportEvent>) {
        // M1-2 事件回流走 mesh-ipc Event；Path Manager（M1-3）再接入。
    }
}

/// 简易 hex 编码（避免引入 hex crate 依赖）。
pub fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0xF) as usize] as char);
    }
    out
}
