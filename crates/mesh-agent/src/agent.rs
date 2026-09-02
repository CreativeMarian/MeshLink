//! MeshAgent 编排核心（用户规格三/六/七/八/九/十二/十三）。
//!
//! - 状态机唯一权威（规格九）；
//! - create/join 全流程后台执行：Controller 身份 → 候选交换 → DirectLink 打洞 →
//!   Noise IK（双向公钥校验）→ Overlay（Wintun/Mock）→ 对端 /32 路由 → 加密冒烟；
//! - Connected 事件只在规格十二 8 条件全部满足后发出；
//! - 数据泵：Overlay RX → Noise encrypt → DirectLink / DirectLink → Noise decrypt
//!   → Overlay TX（规格七）。

use crate::overlay::{MockOverlay, OverlayBackend, OverlayConfig, WintunOverlay};
use crate::runtime::RuntimeState;
use crate::state::{ActiveSession, AgentState, PeerView, SessionSnapshot, StatusSnapshot};
use controller_client::{ApiError, ApiResult, Candidate, Client, InviteTtl, PeerCandidates, SessionView};
use directlink::crypto::StaticIdentity;
use directlink::transport::DirectLinkTransport;
use mesh_ipc::{Command, Event, Request, Response};
use serde::{Deserialize, Serialize};
use secure_store::DeviceIdentityStore;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use transport_api::{Endpoint, Ipv4Packet, PeerHints, PeerId, TransportConfig, TransportProvider};
use transport_n2n::{N2NParams, N2NTransport, SupernodeEndpoint};
use mesh_common::error::MeshError;

/// Overlay 后端选择（生产 Wintun / 自动化测试 Mock）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayKind {
    Wintun,
    Mock,
}

/// Agent 启动配置。
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Controller 基址（DEV: http://127.0.0.1:*；PROD: https://…，scheme 白名单
    /// 由 controller-client 强制，Agent 不做降级——规格一）。
    pub controller_url: String,
    /// 设备身份持久化目录（DPAPI + ACL；规格五）。
    pub data_dir: PathBuf,
    /// M1-1.5：runtime 临时目录（active_session/quick_code 等；空 = 未启用）。
    /// 生产由 MeshLink 以 `MESHLINK_RUNTIME_DIR` 注入，正常退出删除、异常退出
    /// 由 supervisor 下次启动自动清理。永久身份仍只存 data_dir，本目录不含密钥。
    pub runtime_dir: PathBuf,
    pub network_id: String,
    pub device_name: Option<String>,
    pub adapter_name: String,
    pub overlay: OverlayKind,
    /// STUN 列表（同机回环 E2E 留空；实网公网验证时填公网 STUN）。
    pub stun_servers: Vec<String>,
    /// joiner 打洞超时（DIRECTLINK_FAILED 判定）。
    pub punch_timeout: Duration,
    /// Noise 握手等待超时。
    pub handshake_timeout: Duration,
    /// 加密 overlay 冒烟超时（规格十二条件 8）。
    pub smoke_timeout: Duration,
    /// creator 等待 joiner 加入的超时（对齐会话有效期 10min）。
    pub wait_peer_timeout: Duration,
    /// M1-2：N2N Supernode 池（Controller Supernode Registry 下发后可动态更新）。
    pub n2n_supernodes: Vec<SupernodeEndpoint>,
    /// M1-2：N2N community（默认 = network_id）。
    pub n2n_community: Option<String>,
    /// M1-2 测试/诊断注入：`MESHLINK_FORCE_DIRECTLINK_FAIL=1` 时 DirectLink
    /// 建链立即失败（触发 Auto 路径自动回退 N2N），用于自动集成测试确定性覆盖。
    pub force_directlink_fail: bool,
}

impl Default for AgentConfig {
    fn default() -> Self {
        let data_dir = std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|p| p.join("MeshLink").join("agent"))
            .unwrap_or_else(|| PathBuf::from("agent-data"));
        Self {
            controller_url: mesh_ipc::DEFAULT_CONTROLLER_URL.into(),
            data_dir,
            runtime_dir: PathBuf::new(),
            network_id: "meshlink".into(),
            device_name: None,
            adapter_name: "MeshLink".into(),
            overlay: OverlayKind::Wintun,
            stun_servers: Vec::new(),
            punch_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(30),
            smoke_timeout: Duration::from_secs(15),
            wait_peer_timeout: Duration::from_secs(600),
            n2n_supernodes: Vec::new(),
            n2n_community: None,
            force_directlink_fail: false,
        }
    }
}

// ---------------------------------------------------------------------------
// 命令通道
// ---------------------------------------------------------------------------

/// Agent 内部命令（IPC 线程 → Agent runtime；reply 为一次性回执通道）。
pub(crate) struct AgentCommand {
    pub id: u64,
    pub kind: CommandKind,
    pub reply: std::sync::mpsc::Sender<Response>,
}

pub(crate) enum CommandKind {
    CreateQuickSession,
    JoinQuickSession { code: String },
    CancelSession,
    DisconnectPeer { peer: String },
    CreateFriendInvite { ttl: String, max_uses: i64 },
    RedeemFriendInvite { invite_id: String, token: String },
    ListFriends,
    ListDevices,
    ListInvites,
    RevokeInvite { invite_id: String },
    AcceptFriendship { friendship_id: String },
    RejectFriendship { friendship_id: String },
    ConnectFriend { device_id: String },
    AcceptConnectionRequest { session_id: String },
    RejectConnectionRequest { session_id: String },
    SetControllerUrl { url: String },
    GetControllerStatus,
    Heartbeat,
    SetPath { path: String },
    GetN2NStatus,
    /// M1-1.5：最近连接历史。
    ListRecentConnections,
    DeleteRecentConnection { remote_device_id: String },
    Shutdown,
    /// M1-2：注册本机（监督者拉起的）DEV/自托管 Supernode 到 Controller Registry，
    /// 随后刷新本机 N2N 池（credential 由 Agent 持有）。
    RegisterLocalSupernode { sn_id: String, host: String, port: u16, priority: u32 },
}

/// M1-2 强制传输路径（Force DirectLink / Force N2N；Auto = 默认 DirectLink，
/// 完整自动 Path Manager 留给 M1-3）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathChoice {
    Auto,
    DirectLink,
    N2N,
}

impl PathChoice {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "directlink" => Some(Self::DirectLink),
            "n2n" => Some(Self::N2N),
            _ => None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::DirectLink => "directlink",
            Self::N2N => "n2n",
        }
    }
}

/// 会话数据面的最小传输接口（DirectLink 与 N2N 共用 overlay 泵/冒烟）。
/// 命名加 io_ 前缀避免与各 Transport 固有方法同名歧义。
#[async_trait::async_trait]
pub(crate) trait SessionPacketIo: Send + Sync {
    fn io_packet_rx(&self, peer: &PeerId) -> Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>>;
    async fn io_send_packet(&self, peer: PeerId, pkt: Ipv4Packet) -> Result<(), MeshError>;
}

#[async_trait::async_trait]
impl SessionPacketIo for DirectLinkTransport {
    fn io_packet_rx(&self, peer: &PeerId) -> Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        DirectLinkTransport::packet_rx(self, peer)
    }
    async fn io_send_packet(&self, peer: PeerId, pkt: Ipv4Packet) -> Result<(), MeshError> {
        // 仅固有方法名为 send_packet，无歧义。
        self.send_packet(peer, pkt).await
    }
}

#[async_trait::async_trait]
impl SessionPacketIo for N2NTransport {
    fn io_packet_rx(&self, peer: &PeerId) -> Option<tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>> {
        N2NTransport::packet_rx(self, peer)
    }
    async fn io_send_packet(&self, peer: PeerId, pkt: Ipv4Packet) -> Result<(), MeshError> {
        self.send_packet(peer, pkt).await
    }
}

// ---------------------------------------------------------------------------
// 会话运行时
// ---------------------------------------------------------------------------

pub(crate) struct PeerState {
    pub device_id: String,
    /// 传输层会话键：session 作用域（双端各自本地一致 = session_id 字符串）。
    pub peer_id: PeerId,
    pub overlay_ip: Option<Ipv4Addr>,
    pub local_overlay_ip: Option<Ipv4Addr>,
    pub connected: bool,
    pub smoke_passed: bool,
}

pub(crate) struct SessionState {
    pub session_id: String,
    /// creator | joiner
    pub role: String,
    pub network_id: String,
    pub code: Option<String>,
    pub expires_at: Option<String>,
    pub overlay_subnet: Option<String>,
    pub peer: PeerState,
    pub stop: Arc<AtomicBool>,
    pub overlay: Arc<Mutex<Box<dyn OverlayBackend>>>,
    /// 好友直连会话（FriendConnected/FriendDisconnected 事件判定）。
    pub friend_session: bool,
}

// ---------------------------------------------------------------------------
// AgentCore
// ---------------------------------------------------------------------------

pub(crate) struct AgentCore {
    pub cfg: AgentConfig,
    pub store: DeviceIdentityStore,
    /// Controller 客户端（M1-1 可重配：SetControllerUrl 重建后替换；Clone 为快照）。
    pub client: Mutex<Client>,
    /// 当前生效的 Controller 地址（SetControllerUrl 后更新；status/cfg 据此读取）。
    pub controller_url: Mutex<String>,
    pub transport: Arc<DirectLinkTransport>,
    /// M1-2：N2N 第二 TransportProvider（Supernode 池由 Controller Registry 下发）。
    pub n2n: Arc<N2NTransport>,
    /// M1-2：强制传输路径（Auto / DirectLink / N2N）。
    pub path: Mutex<PathChoice>,
    pub identity: Arc<StaticIdentity>,
    pub device_id: String,
    credential: Mutex<String>,
    status: Arc<Mutex<StatusSnapshot>>,
    pub session: Arc<Mutex<Option<SessionState>>>,
    pub event_tx: std::sync::mpsc::Sender<Event>,
    /// Mock 后端共享句柄（自动化测试驱动；生产 = None）。
    pub mock: Option<MockOverlay>,
    /// 日志标识（device_name；区分同机多 Agent 的交织日志）。
    pub tag: String,
    ready: AtomicBool,
    /// 事件轮询游标（events/poll 权威通道；WSS 仅为加速）。
    pub poll_seq: Mutex<i64>,
    /// 好友在线缓存（device_id → device_name），在线状态刷新基准。
    pub friend_online: Mutex<std::collections::HashMap<String, String>>,
    /// M1-1.5：runtime 临时目录（active_session/quick_code 等；空 = 未启用）。
    pub runtime: RuntimeState,
    /// M1-2：当前连接实际路径（"" / "directlink" / "n2n"）；由建链流程在 CONNECTED
    /// 时写入，UI 经 GetStatus.current_path 展示 DirectLink / N2N Relay。
    pub current_path: Mutex<String>,
    /// M1-1.5+（P1-1）：软件重启后恢复的活动会话（data_dir/session_persist.json
    /// 持久化 + Controller 验证）。仅承载 6 位码展示（等待态），不含传输层资源。
    pub recovered_session: Mutex<Option<ActiveSession>>,
    /// 最近一次流程/启动失败（code, message）。诊断中心与依赖 Controller 的命令
    /// 据此快速返回明确原因（如 CONTROLLER_UNREACHABLE），避免阻塞/笼统"连接失败"。
    pub last_error: Mutex<Option<(String, String)>>,
    /// P1-4：进入 Failed 的时刻（自动回 READY 的时间基准；None = 非失败态）。
    pub failed_at: Mutex<Option<Instant>>,
}

impl AgentCore {
    fn credential(&self) -> String {
        self.credential.lock().unwrap().clone()
    }

    /// 当前 Controller 客户端快照（Clone 后用于异步流程，避免跨 await 持锁）。
    fn controller(&self) -> Client {
        self.client.lock().unwrap().clone()
    }

    /// 当前生效 Controller 地址。
    fn controller_url(&self) -> String {
        self.controller_url.lock().unwrap().clone()
    }

    pub fn set_state(&self, state: AgentState) {
        let mut s = self.status.lock().unwrap();
        s.state = state;
        s.user_facing = state.user_facing().into();
        // 成功恢复到 Ready：清空上次失败记录（诊断不再显示过期错误）。
        if state == AgentState::Ready {
            *self.last_error.lock().unwrap() = None;
            *self.failed_at.lock().unwrap() = None;
        }
        tracing::info!(target: "agent", state = ?state, "状态切换");
    }

    /// M1-2：记录当前连接实际路径（directlink | n2n），并同步进状态快照。
    pub fn set_current_path(&self, path: &str) {
        *self.current_path.lock().unwrap() = path.to_string();
        // status 顶层 current_path 由 snapshot() 实时读取，无需额外写回。
    }

    pub fn snapshot(&self) -> StatusSnapshot {
        let mut snap = self.status.lock().unwrap().clone();
        let state = snap.state;
        let session = self.session.lock().unwrap().as_ref().map(session_snapshot);
        snap.session = session;
        // 顶层 active_session：即使 UI 页面切换/重绘，6 位码也能恢复（用户规格四）。
        // P1-1：软件重启后无活动 session（内存空）时，用 Controller 验证过的恢复会话。
        snap.active_session = match self.session.lock().unwrap().as_ref() {
            Some(s) => Some(ActiveSession {
                session_id: s.session_id.clone(),
                code: s.code.clone(),
                status: state.wire(),
                expires_at: s.expires_at.clone(),
            }),
            None => self.recovered_session.lock().unwrap().clone(),
        };
        // M1-2：当前连接实际路径（directlink | n2n；未连接 = ""）。
        snap.current_path = self.current_path.lock().unwrap().clone();
        // 最近一次失败（诊断中心展示明确原因；Ready 后已清空）。
        let (ec, em) = self.last_error.lock().unwrap().clone().unwrap_or_default();
        snap.last_error_code = if ec.is_empty() { None } else { Some(ec) };
        snap.last_error_message = if em.is_empty() { None } else { Some(em) };
        snap
    }

    /// P1-1：活动会话持久化（data_dir/session_persist.json——非 runtime，退出不清除，
    /// 供软件重启后恢复 6 位码）。仅存展示字段，不含密钥/传输层资源。
    fn persist_session(&self, session_id: &str, code: &str, expires_at: Option<&str>, status: &str) {
        let path = self.cfg.data_dir.join("session_persist.json");
        let v = serde_json::json!({
            "session_id": session_id,
            "code": code,
            "expires_at": expires_at,
            "status": status,
        });
        if let Err(e) = std::fs::create_dir_all(&self.cfg.data_dir)
            .and_then(|_| std::fs::write(&path, serde_json::to_vec(&v).unwrap_or_default()))
        {
            tracing::warn!(target: "agent", error = %e, "活动会话持久化失败");
        }
    }

    /// P1-1：清除持久化会话与内存恢复态（会话结束/取消）。
    fn clear_persisted_session(&self) {
        *self.recovered_session.lock().unwrap() = None;
        let _ = std::fs::remove_file(self.cfg.data_dir.join("session_persist.json"));
    }

    /// P1-1：软件重启后尝试恢复等待中的 6 位码会话。
    /// 读取 data_dir/session_persist.json → 向 Controller `get_session` 验证仍在等待 →
    /// 写入 recovered_session（GetStatus.active_session 即可恢复展示）。验证失败/过期
    /// → 删除本地文件（不残留脏状态）。
    async fn restore_session(core: Arc<Self>) {
        let path = core.cfg.data_dir.join("session_persist.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else {
            let _ = std::fs::remove_file(&path);
            return;
        };
        let session_id = v.get("session_id").and_then(|x| x.as_str()).unwrap_or("").to_string();
        let code = v.get("code").and_then(|x| x.as_str()).map(String::from);
        let expires_at = v.get("expires_at").and_then(|x| x.as_str()).map(String::from);
        let valid_code = code.as_deref().map(valid_code).unwrap_or(false);
        if session_id.is_empty() || !valid_code {
            let _ = std::fs::remove_file(&path);
            return;
        }
        // 向 Controller 验证会话仍存在（等待 joiner 阶段才恢复）。
        let client = core.controller();
        let cred = core.credential();
        let sid = session_id.clone();
        match AgentCore::controller_call(move || client.get_session(&cred, &sid)).await {
            Ok(view) if view.status == "WAITING" || view.status == "waiting" => {
                *core.recovered_session.lock().unwrap() = Some(ActiveSession {
                    session_id: session_id.clone(),
                    code,
                    status: "WAITING_FOR_PEER".into(),
                    expires_at,
                });
                tracing::info!(target: "agent", session_id, "活动会话已从上次运行恢复（等待好友加入）");
            }
            _ => {
                // 会话已过期/不存在/已进入连接 → 本地不再恢复。
                let _ = std::fs::remove_file(&path);
            }
        }
    }

    fn new_overlay(&self) -> Arc<Mutex<Box<dyn OverlayBackend>>> {
        match self.cfg.overlay {
            OverlayKind::Wintun => {
                Arc::new(Mutex::new(Box::new(WintunOverlay::default())))
            }
            OverlayKind::Mock => {
                let m = self.mock.clone().expect("Mock 后端句柄必须存在");
                Arc::new(Mutex::new(Box::new(m)))
            }
        }
    }

    /// 流程失败：FAILED 状态 + Error 事件 + 会话资源回收。
    /// P1-4：失败后短暂保持 Failed（UI 展示真实原因），随后若仍无活动会话则自动回
    /// READY（可再次创建/加入，无需手动重启）。启动阶段失败（Controller 不可达等，
    /// agent 未 ready）不回 READY，保持 Failed 由上层重试（ensure_agent_running）。
    fn fail(&self, code: &str, err: impl std::fmt::Display) {
        let err_str = err.to_string();
        // 日志优化：故障现场快照（event=FAIL_SNAPSHOT）。一次输出状态/会话/对端/路径/错误码
        // 全字段，诊断中心「错误」分类可按 FAIL_SNAPSHOT 直接抓到失败现场，一眼定位"故障
        // 在哪里"（无需再翻几十行前文拼上下文）。字段按固定顺序各自短持锁，无嵌套。
        let snap = self.snapshot();
        let (sess_id, sess_role, sess_code, peer_dev) = match self.session.lock().unwrap().as_ref() {
            Some(s) => (
                s.session_id.clone(),
                s.role.clone(),
                s.code.clone().unwrap_or_default(),
                s.peer.device_id.clone(),
            ),
            None => (String::new(), String::new(), String::new(), String::new()),
        };
        tracing::error!(
            target: "agent",
            event = "FAIL_SNAPSHOT",
            state = ?snap.state,
            code,
            error = %err_str,
            controller = %self.controller_url.lock().unwrap(),
            device_id = %self.device_id,
            session_id = %sess_id,
            role = %sess_role,
            code6 = %sess_code,
            peer_device = %peer_dev,
            path = %self.current_path.lock().unwrap(),
            "会话流程失败（故障现场）"
        );
        *self.last_error.lock().unwrap() = Some((code.to_string(), err_str.clone()));
        self.abort_session_resources();
        self.set_state(AgentState::Failed);
        let _ = self.event_tx.send(Event::Error { code: code.into(), message: err_str });
        // P1-4：记录失败时刻，background_loop 短暂停留后自动回 READY（仅已就绪的会话失败）。
        *self.failed_at.lock().unwrap() = Some(Instant::now());
    }

    /// Controller 已就绪（Ready/Connected 等）？依赖 Controller 的命令据此快速失败，
    /// 避免在 Controller 不可达时阻塞到 HTTP 超时才返回（虚拟机 EF0001 超时根因之一）。
    fn controller_ready(&self) -> bool {
        matches!(
            self.snapshot().state,
            AgentState::Ready
                | AgentState::SessionCreating
                | AgentState::WaitingForPeer
                | AgentState::PeerDiscovered
                | AgentState::Gathering
                | AgentState::Punching
                | AgentState::NoiseHandshake
                | AgentState::ConfiguringOverlay
                | AgentState::Connected
                | AgentState::Reconnecting
        )
    }

    /// 依赖 Controller 的命令在未就绪时的快速失败错误（带最近一次失败原因）。
    /// ControllerConnecting 表示仍在启动握手，提示稍候；否则透出 last_error。
    fn controller_unready_error(&self, id: u64) -> Response {
        let state = self.snapshot().state;
        let (code, msg) = if state == AgentState::ControllerConnecting {
            ("CONTROLLER_CONNECTING".into(), "正在连接网络服务，请稍候".into())
        } else {
            self.last_error
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| ("CONTROLLER_UNREACHABLE".into(), "无法连接到网络服务".into()))
        };
        error_response(id, &code, msg)
    }

    fn fail_timeout(&self, code: &str, what: &str) {
        self.fail(code, format!("{what} 超时"));
    }

    fn aborted(&self) {
        tracing::info!(target: "agent", "会话流程被取消");
    }

    /// 在 blocking 线程池执行同步 Controller 调用（P0-1 根治）。
    ///
    /// controller-client 是同步裸 TCP（IO_TIMEOUT=8s），在 2-worker Tokio runtime 里
    /// 直接调用会占用 worker 线程；Controller 慢/挂起时一次最多阻塞 8s，且 startup /
    /// background_loop / 会话流程都在争用这 2 个 worker，容易让其它 async 任务饿死
    /// （卡顿、心跳延迟、事件不推送）。`spawn_blocking` 走独立线程池，不占 worker。
    async fn controller_call<T: Send + 'static>(
        f: impl FnOnce() -> ApiResult<T> + Send + 'static,
    ) -> ApiResult<T> {
        tokio::task::spawn_blocking(f).await.unwrap_or_else(|e| {
            Err(ApiError {
                status: 0,
                code: "INTERNAL".into(),
                message: format!("blocking 任务失败: {e}"),
            })
        })
    }

    /// 停泵 + 拆 Overlay + 停 peer keepalive（会话状态本身由调用方处理）。
    fn abort_session_resources(&self) {
        let mut guard = self.session.lock().unwrap();
        if let Some(s) = guard.take() {
            s.stop.store(true, Ordering::Release);
            // P1-3：停掉该 peer 的 keepalive 线程（Keepalive::Drop 置 stop + join），
            // 避免会话结束后 keepalive 继续刷新 NAT 映射/发包（线程残留、日志刷屏）。
            if !s.peer.peer_id.0.is_empty() {
                self.transport.stop_keepalive(&s.peer.peer_id);
                self.n2n.stop_keepalive(&s.peer.peer_id);
            }
            if let Err(e) = s.overlay.lock().unwrap().teardown() {
                tracing::warn!(target: "agent", "Overlay 拆除失败: {e}");
            }
        }
    }

    /// 会话正常结束/取消：回 READY + Disconnected 事件（好友会话附带 FriendDisconnected）。
    fn teardown_session(&self, reason: &str) -> bool {
        let (had, friend, peer_id, session_id) = {
            let g = self.session.lock().unwrap();
            (
                g.is_some(),
                g.as_ref().map(|s| s.friend_session).unwrap_or(false),
                g.as_ref().map(|s| s.peer.device_id.clone()),
                g.as_ref().map(|s| s.session_id.clone()).unwrap_or_default(),
            )
        };
        self.abort_session_resources();
        // M1-1.5：会话结束/取消即清 session 类 runtime 临时文件。
        self.runtime.clear_session();
        // P1-1：清除 data_dir 持久化会话与内存恢复态（不再恢复展示）。
        self.clear_persisted_session();
        // M1-2：会话结束/取消 → 当前路径复位（UI 不再显示 DirectLink / N2N Relay）。
        *self.current_path.lock().unwrap() = String::new();
        if had {
            tracing::info!(
                target: "agent",
                session_id = %session_id,
                reason = %reason,
                "[SESSION CLOSE]"
            );
            self.set_state(AgentState::Ready);
            let _ = self.event_tx.send(Event::Disconnected { reason: reason.into() });
            if friend {
                if let Some(pid) = peer_id {
                    if !pid.is_empty() {
                        let _ = self.event_tx.send(Event::FriendDisconnected { device_id: pid });
                    }
                }
            }
        }
        had
    }

    fn ensure_can_start_session(&self) -> Result<(), (String, String)> {
        if !self.ready.load(Ordering::Acquire) {
            return Err(("AGENT_NOT_READY".into(), "Agent 尚未完成启动（Controller 连接中）".into()));
        }
        if self.session.lock().unwrap().is_some() {
            return Err(("AGENT_BUSY".into(), "已有进行中的会话，请先取消".into()));
        }
        Ok(())
    }

    async fn handle_command(self: Arc<Self>, cmd: AgentCommand) {
        let AgentCommand { id, kind, reply } = cmd;
        let ok = |data: serde_json::Value| Response { id, ok: true, data: Some(data), error: None };
        match kind {
            CommandKind::CreateQuickSession => {
                if let Err((code, msg)) = self.ensure_can_start_session() {
                    let _ = reply.send(error_response(id, &code, msg));
                    return;
                }
                let core = self.clone();
                let is_n2n = core.path.lock().unwrap().clone() == PathChoice::N2N;
                // 同步创建会话：响应本身必须携带 6 位码（用户规格三：UI 显示
                // 不依赖后续 WaitingForPeer 事件）。code 全程 string，固定宽度。
                let client = core.controller();
                let cred = core.credential();
                let net = core.cfg.network_id.clone();
                let view = match AgentCore::controller_call(move || client.create_session(&cred, &net)).await {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = reply.send(error_response(id, "SESSION_CREATE_FAILED", format!("{e}")));
                        return;
                    }
                };
                let Some(code) = view.code.clone().filter(|c| valid_code(c)) else {
                    let _ = reply.send(error_response(
                        id,
                        "QUICK_CODE_INVALID_RESPONSE",
                        "Controller 未返回有效 6 位码",
                    ));
                    return;
                };
                // M1-2.x：Session 生命周期日志——创建即落盘，code 唯一来源是
                // Controller 的 POST /v1/sessions 响应（前端/Agent 均不自行生成）。
                tracing::info!(
                    target: "agent",
                    session_id = %view.session_id,
                    code = %code,
                    device_id = %core.device_id,
                    expires_at = %view.expires_at.as_deref().unwrap_or(""),
                    "[SESSION CREATE]"
                );
                let _ = reply.send(ok(serde_json::json!({
                    "session_id": view.session_id,
                    "code": code,
                    "expires_at": view.expires_at,
                    "status": "WAITING",
                })));
                // M1-1.5：runtime 临时快照（快速会话创建即落盘，供残留检测/崩溃恢复）。
                self.runtime.on_session_created(
                    &view.session_id,
                    &code,
                    view.expires_at.as_deref(),
                    "WAITING_FOR_PEER",
                );
                // P1-1：活动会话持久化到 data_dir（软件重启后经 Controller 验证恢复 6 位码）。
                self.persist_session(
                    &view.session_id,
                    &code,
                    view.expires_at.as_deref(),
                    "WAITING_FOR_PEER",
                );
                tokio::spawn(async move {
                    if is_n2n {
                        creator_flow_n2n_with_view(core, view, false).await;
                    } else {
                        creator_flow_with_view(core, view, false).await;
                    }
                });
            }
            CommandKind::JoinQuickSession { code } => {
                if let Err((code, msg)) = self.ensure_can_start_session() {
                    let _ = reply.send(error_response(id, &code, msg));
                    return;
                }
                let _ = reply.send(ok(serde_json::json!({ "status": "accepted" })));
                let core = self.clone();
                tokio::spawn(async move {
                    let client = core.controller();
                    let cred = core.credential();
                    let code2 = code.clone();
                    let view = match AgentCore::controller_call(move || client.join_session(&cred, &code2)).await {
                        Ok(v) => {
                            // M1-2.x：Session 生命周期日志——加入成功（Controller 已核验 6 位码）。
                            tracing::info!(
                                target: "agent",
                                input_code = %code,
                                found_session = true,
                                session_id = %v.session_id,
                                "[SESSION JOIN]"
                            );
                            v
                        }
                        Err(e) => {
                            // M1-2.x：按 6 位码查询会话失败——透传 Controller 真实业务码
                            // （SESSION_CODE_INVALID 等），不再硬编码 SESSION_NOT_FOUND。
                            let reason = e.to_string();
                            let err_code = if e.code.is_empty() {
                                "SESSION_NOT_FOUND".to_string()
                            } else {
                                e.code.clone()
                            };
                            tracing::warn!(
                                target: "agent",
                                input_code = %code,
                                found_session = false,
                                reason = %reason,
                                "[SESSION NOT FOUND]"
                            );
                            return core.fail(&err_code, reason);
                        }
                    };
                    if core.path.lock().unwrap().clone() == PathChoice::N2N {
                        joiner_flow_n2n(core, view, false).await;
                    } else {
                        joiner_flow_with_view(core, view, false).await;
                    }
                });
            }
            CommandKind::CancelSession => {
                let had = self.teardown_session("cancelled");
                let _ = reply.send(ok(serde_json::json!({ "cancelled": had })));
            }
            CommandKind::DisconnectPeer { peer } => {
                let current = self.session.lock().unwrap().as_ref().map(|s| s.peer.device_id.clone());
                match current {
                    Some(p) if p == peer => {
                        self.teardown_session("disconnected");
                        let _ = reply.send(ok(serde_json::json!({ "disconnected": peer })));
                    }
                    _ => {
                        let _ = reply.send(error_response(id, "PEER_NOT_FOUND", format!("无此已连接 peer: {peer}")));
                    }
                }
            }
            CommandKind::CreateFriendInvite { ttl, max_uses } => {
                let ttl = match parse_invite_ttl(&ttl) {
                    Some(t) => t,
                    None => {
                        let _ = reply.send(error_response(id, "INVITE_TTL_INVALID", "有效期必须是 permanent / 24h / 7d"));
                        return;
                    }
                };
                let client = self.controller();
                match client.create_invite(&self.credential(), &self.cfg.network_id, ttl, max_uses) {
                    Ok(inv) => {
                        let data = serde_json::json!({
                            "invite_id": inv.invite_id,
                            "invite_token": inv.invite_token,
                            "ttl": ttl_label(ttl),
                            "max_uses": max_uses,
                            "expires_at": inv.expires_at,
                            "created_at": inv.created_at,
                            "status": inv.status,
                        });
                        let _ = reply.send(ok(data));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "INVITE_CREATE_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::RedeemFriendInvite { invite_id, token } => {
                // M1-1：兑换建立 PENDING 好友关系（不再创建连接会话）。
                let client = self.controller();
                match client.redeem_invite(&self.credential(), &invite_id, &token) {
                    Ok(view) => {
                        let data = serde_json::json!({
                            "friendship_id": view.friendship_id,
                            "status": view.status,
                            "creator_device_id": view.creator.device.device_id,
                            "creator_name": view.creator.device.device_name,
                        });
                        let _ = reply.send(ok(data));
                        let _ = self.event_tx.send(Event::FriendPending {
                            friendship_id: view.friendship_id.clone(),
                            peer_device_id: view.creator.device.device_id.clone(),
                            peer_name: view.creator.device.device_name.clone().unwrap_or_default(),
                        });
                        let _ = self.event_tx.send(Event::FriendsChanged);
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "INVITE_REDEEM_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::ListFriends => {
                // Controller 未就绪（启动握手/不可达）时快速失败，避免阻塞到 HTTP 超时
                // （虚拟机 EF0001「等待响应超时」根因之一：依赖 Controller 命令串行阻塞）。
                if !self.controller_ready() {
                    let _ = reply.send(self.controller_unready_error(id));
                    return;
                }
                let client = self.controller();
                let cred = self.credential();
                match AgentCore::controller_call(move || client.list_friendships(&cred)).await {
                    Ok(friends) => {
                        let list: Vec<serde_json::Value> = friends
                            .iter()
                            .map(|f| {
                                serde_json::json!({
                                    "friendship_id": f.friendship_id,
                                    "status": f.status,
                                    "peer_device_id": f.peer.device.device_id,
                                    "peer_name": f.peer.device.device_name,
                                    "peer_online": f.peer.online,
                                    "noise_public_key": f.peer.device.noise_public_key,
                                })
                            })
                            .collect();
                        let _ = reply.send(ok(serde_json::json!({ "friendships": list })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "LIST_FRIENDS_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::ListDevices => {
                // M1-1：设备身份模型下"我的设备"= 本机设备（模型预留多设备用户）。
                if !self.controller_ready() {
                    let _ = reply.send(self.controller_unready_error(id));
                    return;
                }
                let client = self.controller();
                let self_dev = client.get_device(&self.credential(), &self.device_id);
                let session_ip = self
                    .session
                    .lock()
                    .unwrap()
                    .as_ref()
                    .and_then(|s| s.peer.local_overlay_ip)
                    .map(|i| i.to_string());
                match self_dev {
                    Ok(dp) => {
                        let last_seen = dp.device.last_seen_at.clone();
                        let device_name = dp.device.device_name.clone().unwrap_or_else(|| self.device_id.clone());
                        let _ = reply.send(ok(serde_json::json!({
                            "devices": [{
                                "device_id": dp.device.device_id,
                                "device_name": device_name,
                                "online": dp.online,
                                "overlay_ip": session_ip,
                                "last_seen": last_seen,
                            }]
                        })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "LIST_DEVICES_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::ListInvites => {
                if !self.controller_ready() {
                    let _ = reply.send(self.controller_unready_error(id));
                    return;
                }
                let client = self.controller();
                match client.list_invites(&self.credential()) {
                    Ok(invites) => {
                        let list: Vec<serde_json::Value> = invites
                            .iter()
                            .map(|i| {
                                serde_json::json!({
                                    "invite_id": i.invite_id,
                                    "network_id": i.network_id,
                                    "expires_at": i.expires_at,
                                    "max_uses": i.max_uses,
                                    "used_count": i.used_count,
                                    "status": i.status,
                                    "created_at": i.created_at,
                                })
                            })
                            .collect();
                        let _ = reply.send(ok(serde_json::json!({ "invites": list })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "LIST_INVITES_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::RevokeInvite { invite_id } => {
                let client = self.controller();
                match client.revoke_invite(&self.credential(), &invite_id) {
                    Ok(()) => {
                        let _ = reply.send(ok(serde_json::json!({ "revoked": true })));
                        let _ = self.event_tx.send(Event::FriendsChanged);
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "INVITE_REVOKE_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::AcceptFriendship { friendship_id } => {
                let client = self.controller();
                match client.accept_friendship(&self.credential(), &friendship_id) {
                    Ok(v) => {
                        let _ = reply.send(ok(serde_json::json!({
                            "friendship_id": v.friendship_id,
                            "status": v.status,
                        })));
                        let _ = self.event_tx.send(Event::FriendAccepted {
                            friendship_id: v.friendship_id.clone(),
                            peer_device_id: v.peer.device.device_id.clone(),
                            peer_name: v.peer.device.device_name.clone().unwrap_or_default(),
                        });
                        let _ = self.event_tx.send(Event::FriendsChanged);
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "FRIEND_ACCEPT_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::RejectFriendship { friendship_id } => {
                let client = self.controller();
                // 拒绝/删除好友 = 撤销授权（REMOVED）。
                match client.reject_friendship(&self.credential(), &friendship_id) {
                    Ok(()) => {
                        let _ = reply.send(ok(serde_json::json!({ "removed": true })));
                        let _ = self.event_tx.send(Event::FriendRemoved {
                            friendship_id,
                            peer_device_id: String::new(),
                        });
                        let _ = self.event_tx.send(Event::FriendsChanged);
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "FRIEND_REMOVE_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::ConnectFriend { device_id } => {
                if let Err((code, msg)) = self.ensure_can_start_session() {
                    let _ = reply.send(error_response(id, &code, msg));
                    return;
                }
                let client = self.controller();
                match client.friend_connect(&self.credential(), &device_id, &self.cfg.network_id) {
                    Ok(view) => {
                        let _ = reply.send(ok(serde_json::json!({ "status": "accepted" })));
                        let core = self.clone();
                        tokio::spawn(async move { creator_flow_with_view(core, view, true).await });
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "FRIEND_CONNECT_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::AcceptConnectionRequest { session_id } => {
                if let Err((code, msg)) = self.ensure_can_start_session() {
                    let _ = reply.send(error_response(id, &code, msg));
                    return;
                }
                let client = self.controller();
                match client.accept_connection_request(&self.credential(), &session_id) {
                    Ok(view) => {
                        let _ = reply.send(ok(serde_json::json!({ "status": "accepted" })));
                        let core = self.clone();
                        let peer_id = view.peer_member(&core.device_id).map(|m| m.device_id.clone()).unwrap_or_default();
                        tokio::spawn(async move {
                            joiner_flow_with_view(core.clone(), view, true).await;
                            if !peer_id.is_empty() {
                                let _ = core.event_tx.send(Event::FriendConnected { device_id: peer_id });
                            }
                        });
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "ACCEPT_REQUEST_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::RejectConnectionRequest { session_id } => {
                let client = self.controller();
                let cred = self.credential();
                let sid = session_id.clone();
                match AgentCore::controller_call(move || client.reject_connection_request(&cred, &sid)).await {
                    Ok(()) => {
                        let _ = reply.send(ok(serde_json::json!({ "rejected": true })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "REJECT_REQUEST_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::SetControllerUrl { url } => {
                // 校验（生产强制 HTTPS / DEV 仅 localhost；公网明文拒绝）。
                let new_client = match Client::new(&url) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = reply.send(error_response(id, "CONTROLLER_URL_INVALID", format!("生产 Controller 必须使用 HTTPS（或开发机 localhost）。{e}")));
                        return;
                    }
                };
                // 取消进行中会话（数据面随断开回收）。
                self.teardown_session("controller url changed");
                *self.client.lock().unwrap() = new_client;
                *self.controller_url.lock().unwrap() = url.clone();
                {
                    let mut st = self.status.lock().unwrap();
                    st.controller = url.clone();
                }
                // 异步重连。
                let core = self.clone();
                tokio::spawn(async move { reconnect_controller(core).await });
                let _ = reply.send(ok(serde_json::json!({ "reconnecting": true, "url": url })));
            }
            CommandKind::GetControllerStatus => {
                let client = self.controller();
                let url = self.controller_url();
                let device_id = self.device_id.clone();
                let started = Instant::now();
                let (connected, latency_ms) = match AgentCore::controller_call(move || client.healthz()).await {
                    Ok(_) => (true, started.elapsed().as_millis() as u64),
                    Err(_) => (false, 0u64),
                };
                let _ = reply.send(ok(serde_json::json!({
                    "url": url,
                    "device_id": device_id,
                    "connected": connected,
                    "latency_ms": latency_ms,
                })));
            }
            CommandKind::Heartbeat => {
                let client = self.controller();
                let cred = self.credential();
                match AgentCore::controller_call(move || client.presence_heartbeat(&cred)).await {
                    Ok(()) => {
                        let _ = reply.send(ok(serde_json::json!({ "ok": true })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "HEARTBEAT_FAILED", e.to_string()));
                    }
                }
            }
            CommandKind::SetPath { path } => {
                match PathChoice::parse(&path) {
                    Some(p) => {
                        *self.path.lock().unwrap() = p.clone();
                        let _ = reply.send(ok(serde_json::json!({ "path": p.as_str() })));
                        let _ = self.event_tx.send(Event::PathChanged {
                            detail: format!("forced_path={}", p.as_str()),
                        });
                    }
                    None => {
                        let _ = reply.send(error_response(id, "PATH_INVALID", "path 必须是 auto / directlink / n2n"));
                    }
                }
            }
            CommandKind::GetN2NStatus => {
                let _ = reply.send(ok(n2n_status_json(&self)));
            }
            CommandKind::RegisterLocalSupernode { sn_id, host, port, priority } => {
                let client = self.controller();
                let credential = self.credential();
                let sn = sn_id.clone();
                let h = host.clone();
                // 注册本机（监督者拉起的）Supernode 到 Controller Registry。
                match AgentCore::controller_call(move || client.register_supernode(&credential, &sn, &h, port, priority)).await {
                    Ok(()) => {
                        // 注册成功后刷新本机 N2N Supernode 池（含新登记节点）。
                        let client2 = self.controller();
                        let cred2 = self.credential();
                        match AgentCore::controller_call(move || client2.list_supernodes(&cred2)).await {
                            Ok(sns) if !sns.is_empty() => {
                                let eps: Vec<SupernodeEndpoint> = sns
                                    .iter()
                                    .map(|s| SupernodeEndpoint {
                                        id: s.id.clone(),
                                        host: s.host.clone(),
                                        port: s.port,
                                        priority: s.priority.min(u8::MAX as u32) as u8,
                                    })
                                    .collect();
                                self.n2n.set_supernodes(eps);
                            }
                            _ => {}
                        }
                        let _ = reply.send(ok(serde_json::json!({ "registered": true, "id": sn_id, "host": host, "port": port })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "SUPERNODE_REGISTER_FAILED", format!("{e}")));
                    }
                }
            }
            CommandKind::Shutdown => {
                self.teardown_session("shutdown");
                self.set_state(AgentState::Stopped);
                // M1-1.5：优雅退出清理全部 runtime 临时文件（supervisor 随后删整个目录）。
                self.runtime.clear_all();
                let _ = reply.send(ok(serde_json::json!({ "stopped": true })));
            }
            CommandKind::ListRecentConnections => {
                let client = self.controller();
                match client.list_recent_connections(&self.credential()) {
                    Ok(list) => {
                        let _ = reply.send(ok(serde_json::json!({ "recent_connections": list })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "LIST_RECENT_FAILED", format!("{e}")));
                    }
                }
            }
            CommandKind::DeleteRecentConnection { remote_device_id } => {
                let client = self.controller();
                match client.delete_recent_connection(&self.credential(), &remote_device_id) {
                    Ok(()) => {
                        let _ = self.event_tx.send(Event::RecentConnectionsChanged);
                        let _ = reply.send(ok(serde_json::json!({ "deleted": true })));
                    }
                    Err(e) => {
                        let _ = reply.send(error_response(id, "DELETE_RECENT_FAILED", format!("{e}")));
                    }
                }
            }
        }
    }
}

fn session_snapshot(s: &SessionState) -> SessionSnapshot {
    SessionSnapshot {
        session_id: s.session_id.clone(),
        role: s.role.clone(),
        code: s.code.clone(),
        expires_at: s.expires_at.clone(),
        network_id: s.network_id.clone(),
        overlay_subnet: s.overlay_subnet.clone(),
        peers: vec![PeerView {
            device_id: s.peer.device_id.clone(),
            connected: s.peer.connected,
            local_overlay_ip: s.peer.local_overlay_ip.map(|i| i.to_string()),
            peer_overlay_ip: s.peer.overlay_ip.map(|i| i.to_string()),
        }],
    }
}

fn error_response(id: u64, code: &str, message: impl Into<String>) -> Response {
    Response {
        id,
        ok: false,
        data: None,
        error: Some(mesh_ipc::IpcError::new(code, message)),
    }
}

fn parse_invite_ttl(s: &str) -> Option<InviteTtl> {
    match s {
        "permanent" => Some(InviteTtl::Permanent),
        "24h" => Some(InviteTtl::Hours24),
        "7d" => Some(InviteTtl::Days7),
        _ => None,
    }
}

fn ttl_label(t: InviteTtl) -> &'static str {
    match t {
        InviteTtl::Permanent => "permanent",
        InviteTtl::Hours24 => "24h",
        InviteTtl::Days7 => "7d",
    }
}

/// 6 位码严格校验（SESSION_CODE_INVALID 语义，绝不 panic）。
fn valid_code(code: &str) -> bool {
    code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit())
}

fn wire_candidates(t: &DirectLinkTransport) -> Vec<Candidate> {
    t.local_candidates()
        .iter()
        .map(|c| Candidate { ip: c.addr.ip().to_string(), port: c.addr.port(), kind: "host".into() })
        .collect()
}

fn endpoints(peers: &[PeerCandidates]) -> Vec<Endpoint> {
    peers
        .iter()
        .flat_map(|p| p.candidates.iter())
        .map(|c| Endpoint { ip: c.ip.clone(), port: c.port, kind: c.kind.clone() })
        .collect()
}

fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (net, mask) = cidr.split_once('/')?;
    let net: Ipv4Addr = net.parse().ok()?;
    let prefix: u8 = mask.parse().ok()?;
    if prefix > 32 { None } else { Some((net, prefix)) }
}

fn my_member<'a>(view: &'a SessionView, device_id: &str) -> Option<&'a controller_client::SessionMember> {
    view.members.iter().find(|m| m.device_id == device_id)
}

fn other_member<'a>(view: &'a SessionView, device_id: &str) -> Option<&'a controller_client::SessionMember> {
    view.members.iter().find(|m| m.device_id != device_id)
}

// ---------------------------------------------------------------------------
// MeshAgent 门面
// ---------------------------------------------------------------------------

pub struct MeshAgent;

impl MeshAgent {
    /// 启动 Agent（后台 runtime）。返回句柄 + 事件流（事件流交给 mesh-ipc
    /// 广播线程或测试直接消费）。
    pub fn spawn(cfg: AgentConfig) -> Result<(AgentHandle, std::sync::mpsc::Receiver<Event>), mesh_common::MeshError> {
        // 同步初始化：身份（DPAPI 持久化）+ Controller 客户端 + 传输层对象。
        std::fs::create_dir_all(&cfg.data_dir).map_err(|e| {
            mesh_common::MeshError::new(
                mesh_common::ErrorCode::ConfigInvalid,
                format!("数据目录不可创建: {}: {e}", cfg.data_dir.display()),
            )
        })?;
        let store = DeviceIdentityStore::open(cfg.data_dir.clone());
        let (id, _first) = store.create_or_load()?;
        let identity = Arc::new(StaticIdentity::from_parts(&id.device_id, *id.private_key, id.public_key)?);
        let client = Client::new(&cfg.controller_url)?;
        let transport = Arc::new(DirectLinkTransport::new());
        // M1-2：N2N 第二传输（Supernode 池可为空，启动后由 Controller Registry 下发）。
        let n2n = Arc::new(N2NTransport::new(N2NParams {
            supernodes: cfg.n2n_supernodes.clone(),
            community: cfg.n2n_community.clone().unwrap_or_else(|| cfg.network_id.clone()),
            network_id: cfg.network_id.clone(),
            ..Default::default()
        })?);

        let (event_tx, event_rx) = std::sync::mpsc::channel::<Event>();
        let (cmd_tx, cmd_rx) = std::sync::mpsc::channel::<AgentCommand>();
        let status = Arc::new(Mutex::new(StatusSnapshot::new(
            AgentState::Starting,
            id.device_id.clone(),
            cfg.controller_url.clone(),
        )));
        let mock = match cfg.overlay {
            OverlayKind::Mock => Some(MockOverlay::default()),
            OverlayKind::Wintun => None,
        };

        let core = Arc::new(AgentCore {
            cfg: cfg.clone(),
            store,
            client: Mutex::new(client),
            controller_url: Mutex::new(cfg.controller_url.clone()),
            transport: transport.clone(),
            n2n: n2n.clone(),
            path: Mutex::new(PathChoice::Auto),
            identity: identity.clone(),
            device_id: id.device_id.clone(),
            credential: Mutex::new(String::new()),
            status: status.clone(),
            session: Arc::new(Mutex::new(None)),
            event_tx: event_tx.clone(),
            mock: mock.clone(),
            tag: cfg.device_name.clone().unwrap_or_else(|| "agent".into()),
            ready: AtomicBool::new(false),
            poll_seq: Mutex::new(0),
            friend_online: Mutex::new(std::collections::HashMap::new()),
            runtime: RuntimeState::new(cfg.runtime_dir.clone()),
            current_path: Mutex::new(String::new()),
            recovered_session: Mutex::new(None),
            last_error: Mutex::new(None),
            failed_at: Mutex::new(None),
        });

        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .map_err(|e| {
                    mesh_common::MeshError::new(mesh_common::ErrorCode::Internal, format!("tokio runtime: {e}"))
                })?,
        );

        // 启动任务：Controller 连接 + 注册 + 传输层 start + READY。
        {
            let core = core.clone();
            runtime.spawn(async move { startup(core).await });
        }

        // 后台循环：事件轮询（权威通道）+ 心跳 + 好友/设备在线刷新（M1-1）。
        {
            let core = core.clone();
            runtime.spawn(async move { background_loop(core).await });
        }

        // 命令桥接线程：std mpsc（IPC 线程）→ tokio runtime。
        {
            let core = core.clone();
            let rt = runtime.handle().clone();
            std::thread::Builder::new()
                .name("agent-cmd-bridge".into())
                .spawn(move || {
                    while let Ok(cmd) = cmd_rx.recv() {
                        if matches!(cmd.kind, CommandKind::Shutdown) {
                            let core = core.clone();
                            rt.spawn(async move { core.handle_command(cmd).await });
                            break;
                        }
                        let core = core.clone();
                        rt.spawn(async move { core.handle_command(cmd).await });
                    }
                })
                .map_err(|e| {
                    mesh_common::MeshError::new(mesh_common::ErrorCode::Internal, format!("命令桥接线程: {e}"))
                })?;
        }

        Ok((
            AgentHandle {
                _runtime: runtime,
                cmd_tx: Mutex::new(cmd_tx),
                core,
            },
            event_rx,
        ))
    }
}

/// UI/测试侧句柄（命令分发 + 状态读取 + Mock 驱动）。
pub struct AgentHandle {
    /// tokio runtime 持有句柄：仅以字段存在维持 runtime 存活（不读取）；
    /// drop AgentHandle 即回收 runtime 与全部后台任务。
    _runtime: Arc<tokio::runtime::Runtime>,
    cmd_tx: Mutex<std::sync::mpsc::Sender<AgentCommand>>,
    core: Arc<AgentCore>,
}

impl AgentHandle {
    /// 处理一条 IPC 请求（同步：查询直读共享状态，动作经命令通道）。
    pub fn request(&self, req: Request) -> Response {
        let Request { id, command } = req;
        match command {
            Command::GetStatus => Response { id, ok: true, data: Some(serde_json::to_value(self.core.snapshot()).unwrap()), error: None },
            Command::ListPeers => {
                let peers = self.core.snapshot().session.map(|s| s.peers).unwrap_or_default();
                Response { id, ok: true, data: Some(serde_json::json!({ "peers": peers })), error: None }
            }
            Command::GetDiagnostics => Response { id, ok: true, data: Some(self.build_diagnostics()), error: None },
            Command::JoinQuickSession { code } => {
                if !valid_code(&code) {
                    return error_response(id, "SESSION_CODE_INVALID", "连接码必须是 6 位数字");
                }
                self.dispatch(id, CommandKind::JoinQuickSession { code })
            }
            Command::CreateQuickSession => self.dispatch(id, CommandKind::CreateQuickSession),
            Command::CancelSession => self.dispatch(id, CommandKind::CancelSession),
            Command::DisconnectPeer { peer } => self.dispatch(id, CommandKind::DisconnectPeer { peer }),
            Command::CreateFriendInvite { ttl, max_uses } => {
                if parse_invite_ttl(&ttl).is_none() {
                    return error_response(id, "INVITE_TTL_INVALID", "有效期必须是 permanent / 24h / 7d");
                }
                self.dispatch(id, CommandKind::CreateFriendInvite { ttl, max_uses })
            }
            Command::RedeemFriendInvite { invite_id, token } => {
                self.dispatch(id, CommandKind::RedeemFriendInvite { invite_id, token })
            }
            Command::ListFriends => self.dispatch(id, CommandKind::ListFriends),
            Command::ListDevices => self.dispatch(id, CommandKind::ListDevices),
            Command::ListInvites => self.dispatch(id, CommandKind::ListInvites),
            Command::RevokeInvite { invite_id } => self.dispatch(id, CommandKind::RevokeInvite { invite_id }),
            Command::AcceptFriendship { friendship_id } => self.dispatch(id, CommandKind::AcceptFriendship { friendship_id }),
            Command::RejectFriendship { friendship_id } => self.dispatch(id, CommandKind::RejectFriendship { friendship_id }),
            Command::ConnectFriend { device_id } => self.dispatch(id, CommandKind::ConnectFriend { device_id }),
            Command::AcceptConnectionRequest { session_id } => {
                self.dispatch(id, CommandKind::AcceptConnectionRequest { session_id })
            }
            Command::RejectConnectionRequest { session_id } => {
                self.dispatch(id, CommandKind::RejectConnectionRequest { session_id })
            }
            Command::SetControllerUrl { url } => self.dispatch(id, CommandKind::SetControllerUrl { url }),
            Command::GetControllerStatus => self.dispatch(id, CommandKind::GetControllerStatus),
            Command::Heartbeat => self.dispatch(id, CommandKind::Heartbeat),
            Command::SetPath { path } => self.dispatch(id, CommandKind::SetPath { path }),
            Command::GetN2NStatus => self.dispatch(id, CommandKind::GetN2NStatus),
            Command::RegisterLocalSupernode { sn_id, host, port, priority } => self.dispatch(
                id,
                CommandKind::RegisterLocalSupernode { sn_id, host, port, priority },
            ),
            Command::ListRecentConnections => self.dispatch(id, CommandKind::ListRecentConnections),
            Command::DeleteRecentConnection { remote_device_id } => {
                self.dispatch(id, CommandKind::DeleteRecentConnection { remote_device_id })
            }
            Command::Shutdown => {
                // 协议硬化：id=0 为 RESERVED/INVALID，不进入正常响应关联；
                // Shutdown 属关键命令，同样拒绝非法 id。
                if id == 0 {
                    return error_response(id, "IPC_INVALID_REQUEST_ID", "Request id 必须为非零递增");
                }
                self.dispatch(id, CommandKind::Shutdown)
            }
        }
    }

    fn dispatch(&self, id: u64, kind: CommandKind) -> Response {
        let (tx, rx) = std::sync::mpsc::channel();
        {
            let guard = self.cmd_tx.lock().unwrap();
            if guard.send(AgentCommand { id, kind, reply: tx }).is_err() {
                return error_response(id, "AGENT_STOPPED", "Agent 命令通道已关闭");
            }
        }
        match rx.recv_timeout(Duration::from_secs(15)) {
            Ok(resp) => resp,
            Err(_) => error_response(id, "AGENT_TIMEOUT", "Agent 响应超时"),
        }
    }

    /// 当前状态快照。
    pub fn status(&self) -> StatusSnapshot {
        self.core.snapshot()
    }

    /// 服务是否已停止（Shutdown 命令处理后 = true；main 循环据此退出）。
    pub fn is_stopped(&self) -> bool {
        self.core.snapshot().state == AgentState::Stopped
    }

    /// Mock Overlay 句柄（自动化测试驱动；生产 = None）。
    pub fn mock_overlay(&self) -> Option<MockOverlay> {
        self.core.mock.clone()
    }

    /// 高级诊断（规格十一：仅诊断页展示；Path/RTT/Overlay/Noise epoch 等）。
    pub fn build_diagnostics(&self) -> serde_json::Value {
        let core = &self.core;
        let snap = core.snapshot();
        let (noise, punch, selected, stun, overlay_json) = {
            let guard = core.session.lock().unwrap();
            match guard.as_ref() {
                Some(s) => (
                    core.transport.crypto_report(&s.peer.peer_id),
                    core.transport.punch_evidence(),
                    core.transport.session_info(&s.peer.peer_id).map(|(l, r, kind)| {
                        serde_json::json!({ "local": l.to_string(), "remote": r.to_string(), "remote_kind": format!("{kind:?}") })
                    }),
                    core.transport.first_stun_server(),
                    {
                        let ov = s.overlay.lock().unwrap();
                        serde_json::json!({
                            "kind": ov.kind(),
                            "local_ip": ov.local_ip().map(|i| i.to_string()),
                            "peer_routes": ov.routes_installed().iter().map(|i| i.to_string()).collect::<Vec<_>>(),
                        })
                    },
                ),
                None => (
                    serde_json::Value::Null,
                    serde_json::Value::Null,
                    None,
                    core.transport.first_stun_server(),
                    serde_json::json!({ "kind": match core.cfg.overlay { OverlayKind::Wintun => "wintun", OverlayKind::Mock => "mock" } }),
                ),
            }
        };
        serde_json::json!({
            "state": snap.state,
            "state_user_facing": snap.user_facing,
            "device_id": snap.device_id,
            "controller": snap.controller,
            "session": snap.session,
            "noise": noise,
            "punch_evidence": punch,
            "selected_pair": selected,
            "stun": stun,
            "overlay": overlay_json,
            // M1-2：当前连接实际路径（directlink | n2n | ""）与 N2N 状态。
            "current_path": snap.current_path,
            "last_error_code": snap.last_error_code,
            "last_error_message": snap.last_error_message,
            "n2n": n2n_status_json(core),
        })
    }

    /// N2N 运行状态（M1-2 诊断；Supernode 池 / 熔断 / 会话）。
    pub fn n2n_status_json(&self) -> serde_json::Value {
        n2n_status_json(&self.core)
    }

    /// 停止 Agent（停泵 + 拆 Overlay + runtime 收尾）。
    pub fn shutdown(&self) {
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = self.cmd_tx.lock().unwrap().send(AgentCommand {
            id: 0,
            kind: CommandKind::Shutdown,
            reply: tx,
        });
        let _ = rx.recv_timeout(Duration::from_secs(5));
        self.core.abort_session_resources();
    }
}

/// Agent + IPC 管道服务一并启动（main / MVP Gate E2E 共用）。
pub fn spawn_service(
    cfg: AgentConfig,
    pipe_name: &str,
) -> Result<(Arc<AgentHandle>, Arc<mesh_ipc::PipeServerHandle>), mesh_common::MeshError> {
    let (handle, events_rx) = MeshAgent::spawn(cfg)?;
    let handle = Arc::new(handle);
    let h = handle.clone();
    let handler: mesh_ipc::RequestHandler = Arc::new(move |req| h.request(req));
    let server = mesh_ipc::spawn_server(pipe_name, handler, events_rx)?;
    Ok((handle, server))
}

// ---------------------------------------------------------------------------
// 启动流程
// ---------------------------------------------------------------------------

async fn startup(core: Arc<AgentCore>) {
    core.set_state(AgentState::ControllerConnecting);
    // healthz 重试（Controller 可能晚于 Agent 启动）。
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let client = core.controller();
        match AgentCore::controller_call(move || client.healthz()).await {
            Ok(_) => break,
            Err(e) => {
                // 每次失败记录原因（agent.log 可见），便于定位是 DNS / 连接 / TLS 问题。
                tracing::warn!(target: "agent", controller = %core.controller_url(), error = %e, "healthz 重试中");
                if Instant::now() > deadline {
                    return core.fail("CONTROLLER_UNREACHABLE", format!("healthz 30s 未就绪: {e}"));
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    // 设备注册（幂等；公钥绑定信任根）。首次 → 新 credential 并 DPAPI 持久化。
    let fingerprint = core.identity.fingerprint();
    let device_id = core.device_id.clone();
    let name = core.cfg.device_name.clone().or_else(device_hostname);
    let client = core.controller();
    match AgentCore::controller_call(move || client.register_device(&device_id, &fingerprint, name.as_deref())).await {
        Ok(resp) if resp.status == "registered" => {
            let cred = resp.credential.unwrap_or_default();
            if cred.is_empty() {
                return core.fail("CONTROLLER_AUTH_FAILED", "注册未下发 credential");
            }
            // create_or_load 已在 spawn 持久化身份；此处仅回填 credential。
            match core.store.load() {
                Ok(Some(rec)) => {
                    if let Err(e) = core
                        .store
                        .update_credential(&rec.device_id, &rec.public_key, &rec.private_key, &cred)
                    {
                        return core.fail("IDENTITY_PERSIST_FAILED", e);
                    }
                }
                _ => {
                    return core.fail(
                        "IDENTITY_PERSIST_FAILED",
                        "身份存储缺失（create_or_load 之后不应发生）",
                    )
                }
            }
            *core.credential.lock().unwrap() = cred;
        }
        Ok(_) => {
            // existing：credential 必须已在身份存储（重启路径）。
            let cred = core
                .store
                .load()
                .ok()
                .flatten()
                .and_then(|r| r.controller_credential);
            match cred {
                Some(c) if !c.is_empty() => *core.credential.lock().unwrap() = c,
                _ => {
                    return core.fail(
                        "CONTROLLER_AUTH_FAILED",
                        "设备已注册但本地 credential 缺失（身份存储损坏？）",
                    )
                }
            }
        }
        Err(e) => return core.fail("DEVICE_REGISTER_FAILED", e),
    }

    // 传输层（DirectLink UDP socket 由本服务独占持有——规格三）。
    let params = serde_json::json!({
        "listen_port": 0,
        "stun_servers": core.cfg.stun_servers,
    });
    if let Err(e) = core
        .transport
        .start(TransportConfig { name: "mesh-agent".into(), params })
        .await
    {
        return core.fail("TRANSPORT_START_FAILED", e);
    }
    core.transport.configure_noise(core.identity.clone(), core.cfg.network_id.clone());

    core.ready.store(true, Ordering::Release);
    core.set_state(AgentState::Ready);
    // P1-1：软件重启后恢复等待中的 6 位码会话（Controller 验证；未过期则 GetStatus 可恢复展示）。
    AgentCore::restore_session(core.clone()).await;
    // M1-2：拉取 Controller Supernode Registry → 下发 N2N Supernode 池（非阻塞）。
    {
        let client = core.controller();
        let cred = core.credential();
        match AgentCore::controller_call(move || client.list_supernodes(&cred)).await {
            Ok(sns) if !sns.is_empty() => {
                let eps: Vec<SupernodeEndpoint> = sns
                    .iter()
                    .map(|s| SupernodeEndpoint {
                        id: s.id.clone(),
                        host: s.host.clone(),
                        port: s.port,
                        priority: s.priority.min(u8::MAX as u32) as u8,
                    })
                    .collect();
                core.n2n.set_supernodes(eps);
                tracing::info!(target: "agent", n = core.n2n.supernodes().len(), "N2N Supernode 池已从 Controller Registry 下发");
            }
            _ => {}
        }
    }
    let _ = core
        .event_tx
        .send(Event::ControllerConnected { controller: core.controller_url(), device_id: core.device_id.clone() });
    // M1-1.5：身份初始化完成标记（runtime_token.json，仅供残留检测）。
    core.runtime.write_token(&core.device_id);
    tracing::info!(target: "agent", device_id = %core.device_id, "Agent READY（Controller 已连接，身份已注册）");
}

/// 重新连接 Controller（SetControllerUrl 后调用）：重建客户端 + healthz +
/// 幂等注册刷新 credential，然后 READY。传输层已启动，不重复 start。
async fn reconnect_controller(core: Arc<AgentCore>) -> bool {
    core.set_state(AgentState::ControllerConnecting);
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let client = core.controller();
        match AgentCore::controller_call(move || client.healthz()).await {
            Ok(_) => break,
            Err(e) => {
                if Instant::now() > deadline {
                    core.set_state(AgentState::Failed);
                    let _ = core.event_tx.send(Event::Error {
                        code: "CONTROLLER_UNREACHABLE".into(),
                        message: format!("新 Controller 不可达: {e}"),
                    });
                    return false;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    let fingerprint = core.identity.fingerprint();
    let device_id = core.device_id.clone();
    let name = core.cfg.device_name.clone().or_else(device_hostname);
    let client = core.controller();
    match AgentCore::controller_call(move || client.register_device(&device_id, &fingerprint, name.as_deref())).await {
        Ok(resp) if resp.status == "registered" => {
            let cred = resp.credential.unwrap_or_default();
            if cred.is_empty() {
                core.set_state(AgentState::Failed);
                return false;
            }
            if let Ok(Some(rec)) = core.store.load() {
                let _ = core
                    .store
                    .update_credential(&rec.device_id, &rec.public_key, &rec.private_key, &cred);
            }
            *core.credential.lock().unwrap() = cred;
        }
        Ok(_) => {
            if let Ok(Some(rec)) = core.store.load() {
                if let Some(c) = rec.controller_credential {
                    if !c.is_empty() {
                        *core.credential.lock().unwrap() = c;
                    }
                }
            }
        }
        Err(e) => {
            core.set_state(AgentState::Failed);
            let _ = core.event_tx.send(Event::Error {
                code: "DEVICE_REGISTER_FAILED".into(),
                message: e.to_string(),
            });
            return false;
        }
    }
    core.ready.store(true, Ordering::Release);
    core.set_state(AgentState::Ready);
    let _ = core.event_tx.send(Event::ControllerConnected {
        controller: core.controller_url(),
        device_id: core.device_id.clone(),
    });
    true
}

/// 后台循环（M1-1）：事件轮询（权威通道）+ 心跳 + 好友在线状态刷新。
/// 仅 ready 后工作；失败静默（Controller 重启后 startup 会重连）。
async fn background_loop(core: Arc<AgentCore>) {
    let mut heartbeat_tick: u32 = 0;
    let mut presence_tick: u32 = 0;
    // P2-2：事件轮询动态背压——空轮询退避（2s→4s→8s→10s，上限 5 tick），有事件
    // 或失败恢复 1 tick。减少空闲期对 Controller 的无意义轮询频率（省流量/负载）。
    let mut poll_tick: u32 = 0;
    let mut poll_interval: u32 = 1;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if !core.ready.load(Ordering::Acquire) {
            continue;
        }
        // P1-4：Failed 自动恢复——失败已通过 Error 事件展示给 UI，停留 3s 后若仍
        // Failed 且无活动会话，自动回 READY（可再次创建/加入，无需手动重启）。
        if let Some(t) = *core.failed_at.lock().unwrap() {
            if t.elapsed() >= Duration::from_secs(3) {
                *core.failed_at.lock().unwrap() = None;
                if core.snapshot().state == AgentState::Failed && core.session.lock().unwrap().is_none() {
                    core.set_state(AgentState::Ready);
                    let _ = core.event_tx.send(Event::Disconnected {
                        reason: "连接失败，已自动恢复就绪".into(),
                    });
                }
            }
        }
        heartbeat_tick += 1;
        presence_tick += 1;

        // 心跳：维持 last_seen（auth 中间件也 touch，这里是空闲保活）。
        if heartbeat_tick >= 15 {
            heartbeat_tick = 0;
            let client = core.controller();
            let cred = core.credential();
            let _ = AgentCore::controller_call(move || client.presence_heartbeat(&cred)).await;
        }

        // 事件轮询（friends/connection_request 等），按动态间隔执行。
        poll_tick += 1;
        if poll_tick >= poll_interval {
            poll_tick = 0;
            let client = core.controller();
            let cred = core.credential();
            let since = *core.poll_seq.lock().unwrap();
            match AgentCore::controller_call(move || client.poll_events(&cred, since)).await {
                Ok(poll) => {
                    *core.poll_seq.lock().unwrap() = poll.seq;
                    if poll.events.is_empty() {
                        // P2-2：空轮询 → 指数退避（1→2→4→5 tick 封顶）。
                        poll_interval = (poll_interval * 2).min(5);
                    } else {
                        poll_interval = 1;
                        for ev in poll.events {
                            forward_controller_event(&core, &ev);
                        }
                    }
                }
                Err(e) => {
                    // P2-2：失败恢复积极轮询（可能丢事件，缩短间隔尽快追上）。
                    poll_interval = 1;
                    tracing::warn!(target: "agent", error = %e, "事件轮询失败");
                }
            }
        }

        // 好友/设备在线状态刷新（约每 30s）。
        if presence_tick >= 15 {
            presence_tick = 0;
            refresh_presence(&core).await;
        }
    }
}

/// 将 Controller 事件转发为 UI 事件（M1-1：好友/直连/在线）。
fn forward_controller_event(core: &Arc<AgentCore>, ev: &controller_client::ControllerEvent) {
    let payload = &ev.payload;
    let str_p = |k: &str| payload.get(k).and_then(|v| v.as_str()).unwrap_or("").to_string();
    match ev.event_type.as_str() {
        controller_client::event_types::CONNECTION_REQUEST => {
            let _ = core.event_tx.send(Event::IncomingConnectionRequest {
                session_id: ev.session_id.clone().unwrap_or_default(),
                from_device_id: ev.device_id.clone().unwrap_or_default(),
                from_name: str_p("from_name"),
            });
        }
        controller_client::event_types::REQUEST_REJECTED => {
            // 对方拒绝：若正等待该会话则终止 creator 流程。
            let sid = ev.session_id.clone().unwrap_or_default();
            let is_current = core
                .session
                .lock()
                .unwrap()
                .as_ref()
                .map(|s| s.session_id == sid)
                .unwrap_or(false);
            if is_current {
                core.teardown_session("对方拒绝了连接请求");
                let _ = core.event_tx.send(Event::Error {
                    code: "REQUEST_REJECTED".into(),
                    message: "对方拒绝了连接请求".into(),
                });
            }
        }
        controller_client::event_types::FRIEND_PENDING => {
            let _ = core.event_tx.send(Event::FriendPending {
                friendship_id: str_p("friendship_id"),
                peer_device_id: str_p("peer_device_id"),
                peer_name: str_p("peer_name"),
            });
            let _ = core.event_tx.send(Event::FriendsChanged);
        }
        controller_client::event_types::FRIEND_ACCEPTED => {
            let _ = core.event_tx.send(Event::FriendAccepted {
                friendship_id: str_p("friendship_id"),
                peer_device_id: str_p("peer_device_id"),
                peer_name: str_p("peer_name"),
            });
            let _ = core.event_tx.send(Event::FriendsChanged);
        }
        controller_client::event_types::FRIEND_REMOVED => {
            let _ = core.event_tx.send(Event::FriendRemoved {
                friendship_id: str_p("friendship_id"),
                peer_device_id: str_p("peer_device_id"),
            });
            let _ = core.event_tx.send(Event::FriendsChanged);
        }
        _ => {}
    }
}

/// 好友/设备在线状态刷新：拉取好友列表，对比缓存并发送 FriendOnline/Offline。
async fn refresh_presence(core: &Arc<AgentCore>) {
    let client = core.controller();
    let cred = core.credential();
    let Ok(friends) = AgentCore::controller_call(move || client.list_friendships(&cred)).await else {
        return;
    };
    let mut online_now: Vec<(String, String)> = Vec::new(); // (device_id, name)
    for f in &friends {
        if f.status == "ACCEPTED" {
            online_now.push((f.peer.device.device_id.clone(), f.peer.device.device_name.clone().unwrap_or_default()));
        }
    }
    // 与缓存比对（核心字段以 Mutex 保存最近一次在线快照）。
    let mut cached = core.friend_online.lock().unwrap();
    for (id, name) in &online_now {
        if !cached.contains_key(id) {
            let _ = core.event_tx.send(Event::FriendOnline { device_id: id.clone(), device_name: name.clone() });
            let _ = core.event_tx.send(Event::FriendsChanged);
        }
    }
    let gone: Vec<String> = cached.keys().filter(|k| !online_now.iter().any(|(id, _)| id == *k)).cloned().collect();
    for id in &gone {
        let _ = core.event_tx.send(Event::FriendOffline { device_id: id.clone() });
        let _ = core.event_tx.send(Event::FriendsChanged);
    }
    cached.clear();
    for (id, name) in &online_now {
        cached.insert(id.clone(), name.clone());
    }
}

fn device_hostname() -> Option<String> {
    std::env::var("COMPUTERNAME").ok()
}

/// N2N 运行状态 JSON（AgentCore 与 AgentHandle 共用）。
fn n2n_status_json(core: &Arc<AgentCore>) -> serde_json::Value {
    let path = core.path.lock().unwrap().clone();
    let n2n = core.n2n.clone();
    let supernodes: Vec<serde_json::Value> = n2n
        .supernodes()
        .into_iter()
        .map(|s| {
            let breaker = n2n.breaker_state(&s.id);
            serde_json::json!({
                "id": s.id,
                "host": s.host,
                "port": s.port,
                "priority": s.priority,
                "breaker": breaker,
            })
        })
        .collect();
    serde_json::json!({
        "forced_path": path.as_str(),
        "supernode_pool": supernodes,
        "sessions": n2n.session_info_all(),
        "provider_open": n2n.provider_open(),
        "last_health_ok": n2n.last_health_ok(),
    })
}

// ---------------------------------------------------------------------------
// M1-2：DirectLink 建链失败 → Auto 路径自动回退 N2N Supernode Relay
// ---------------------------------------------------------------------------

impl AgentCore {
    /// Auto 路径 + N2N 池可用时允许 DirectLink → N2N 自动回退。
    fn auto_fallback_ready(&self) -> bool {
        *self.path.lock().unwrap() == PathChoice::Auto && !self.n2n.supernodes().is_empty()
    }
}

/// creator：DirectLink 建链失败（Auto）→ 清理 DirectLink 会话资源后转 N2N creator。
async fn creator_fallback_to_n2n(core: Arc<AgentCore>, view: SessionView, friend: bool, code: &str, msg: String) {
    if !core.auto_fallback_ready() {
        core.fail(code, msg);
        return;
    }
    tracing::warn!(target: "agent", from = code, "DirectLink 建链失败 → 自动回退 N2N Supernode（creator）");
    core.abort_session_resources();
    let _ = core.event_tx.send(Event::PathChanged { detail: "n2n-fallback".into() });
    creator_flow_n2n_with_view(core, view, friend).await;
}

/// joiner：DirectLink 建链失败（Auto）→ 清理 DirectLink 会话资源后转 N2N joiner。
async fn joiner_fallback_to_n2n(core: Arc<AgentCore>, view: SessionView, friend: bool, code: &str, msg: String) {
    if !core.auto_fallback_ready() {
        core.fail(code, msg);
        return;
    }
    tracing::warn!(target: "agent", from = code, "DirectLink 建链失败 → 自动回退 N2N Supernode（joiner）");
    core.abort_session_resources();
    let _ = core.event_tx.send(Event::PathChanged { detail: "n2n-fallback".into() });
    joiner_flow_n2n(core, view, friend).await;
}

// ---------------------------------------------------------------------------
// Creator 流程（创建 6 位码 → 等待 joiner → responder Noise → Overlay）
// ---------------------------------------------------------------------------

async fn creator_flow_with_view(core: Arc<AgentCore>, view: SessionView, friend: bool) {
    let cred = core.credential();
    let client = core.controller();
    let session_id = view.session_id.clone();
    let peer_id = PeerId(session_id.clone());
    let stop = Arc::new(AtomicBool::new(false));
    let overlay = core.new_overlay();
    {
        let mut s = core.session.lock().unwrap();
        *s = Some(SessionState {
            session_id: session_id.clone(),
            role: "creator".into(),
            network_id: view.network_id.clone(),
            code: view.code.clone(),
            expires_at: view.expires_at.clone(),
            overlay_subnet: view.overlay_subnet.clone(),
            peer: PeerState {
                device_id: String::new(),
                peer_id: peer_id.clone(),
                overlay_ip: None,
                local_overlay_ip: None,
                connected: false,
                smoke_passed: false,
            },
            stop: stop.clone(),
            overlay: overlay.clone(),
            friend_session: friend,
        });
    }

    // responder 待命（punch tag = Controller session_id，双端均知）。
    core.transport.start_accepting(peer_id.clone(), session_id.clone());

    // 候选收集 + 上传。
    let cands = wire_candidates(&core.transport);
    if cands.is_empty() {
        return core.fail("CANDIDATE_GATHER_FAILED", "本机无可用 host candidate");
    }
    let _ = core.event_tx.send(Event::GatheringCandidates { count: cands.len() });
    {
        let c = client.clone();
        let cr = cred.clone();
        let sid = session_id.clone();
        if let Err(e) = AgentCore::controller_call(move || c.put_candidates(&cr, &sid, &cands)).await {
            return core.fail("CANDIDATE_UPLOAD_FAILED", e);
        }
    }

    core.set_state(AgentState::WaitingForPeer);
    let _ = core.event_tx.send(Event::WaitingForPeer {
        code: view.code.clone().unwrap_or_default(),
        session_id: session_id.clone(),
        expires_at: view.expires_at.clone(),
    });

    // 等待 joiner 加入（Controller 视图轮询）。
    let deadline = Instant::now() + core.cfg.wait_peer_timeout;
    let (peer_device, peer_key, peer_ip, local_ip) = loop {
        if stop.load(Ordering::Acquire) {
            return core.aborted();
        }
        if Instant::now() > deadline {
            return core.fail_timeout("WAIT_PEER_TIMEOUT", "等待好友加入");
        }
        match AgentCore::controller_call({
            let c = client.clone();
            let cr = cred.clone();
            let sid = session_id.clone();
            move || c.get_session(&cr, &sid)
        }).await {
            Ok(v) => {
                if let (Some(me), Some(other)) =
                    (my_member(&v, &core.device_id), other_member(&v, &core.device_id))
                {
                    if me.overlay_ip.is_some() && other.overlay_ip.is_some() {
                        break (
                            other.device_id.clone(),
                            other.public_key(),
                            other.overlay_ip.clone(),
                            me.overlay_ip.clone(),
                        );
                    }
                }
            }
            Err(e) => {
                // M1-2.x：会话轮询查询失败（会话被删/过期等）——debug 级，避免刷屏。
                tracing::debug!(
                    target: "agent",
                    session_id = %session_id,
                    reason = %e.to_string(),
                    "[SESSION NOT FOUND] poll"
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };

    // 双向验证（规格二）：creator 登记 joiner 公钥——唯一来源 Controller Registry。
    let Some(peer_key) = peer_key else {
        return core.fail("DEVICE_KEY_UNAVAILABLE", "Controller 未分发 joiner 公钥");
    };
    core.transport.set_expected_initiator(&peer_id, peer_key);
    core.transport.require_initiator_identity(&peer_id);

    {
        let mut s = core.session.lock().unwrap();
        if let Some(s) = s.as_mut() {
            s.peer.device_id = peer_device.clone();
            s.peer.overlay_ip = peer_ip.and_then(|p| p.parse().ok());
            s.peer.local_overlay_ip = local_ip.and_then(|p| p.parse().ok());
        }
    }

    let _ = core.event_tx.send(Event::PeerFound { peer_device_id: peer_device.clone() });
    // creator 不主动打洞（对端 joiner 发起）；UX 侧同样进入「建立直连」阶段。
    core.set_state(AgentState::Punching);
    let _ = core.event_tx.send(Event::Punching { track: "A".into() });

    // 等 Noise established（joiner 主动握手；严格模式下 msg1 未登记前被拒并重试）。
    // M1-2：DirectLink 建链超时（Auto）→ 自动回退 N2N；强制 DirectLink 则直接失败。
    let deadline = Instant::now() + core.cfg.handshake_timeout;
    let mut announced = false;
    loop {
        if stop.load(Ordering::Acquire) {
            return core.aborted();
        }
        if core.cfg.force_directlink_fail {
            // 测试/诊断注入：模拟 DirectLink 握手不可达 → 触发 Auto 回退。
            tokio::time::sleep(Duration::from_millis(300)).await;
            return creator_fallback_to_n2n(
                core.clone(),
                view,
                friend,
                "NOISE_HANDSHAKE_TIMEOUT",
                "Noise IK 握手（MESHLINK_FORCE_DIRECTLINK_FAIL 注入）".into(),
            )
            .await;
        }
        let report = core.transport.crypto_report(&peer_id);
        if !announced && !report.is_null() {
            announced = true;
            core.set_state(AgentState::NoiseHandshake);
            let _ = core.event_tx.send(Event::NoiseHandshaking { role: "responder".into() });
        }
        if report.get("established").and_then(|v| v.as_bool()).unwrap_or(false) {
            break;
        }
        if Instant::now() > deadline {
            return creator_fallback_to_n2n(
                core.clone(),
                view,
                friend,
                "NOISE_HANDSHAKE_TIMEOUT",
                "Noise IK 握手超时（DirectLink 路径）".into(),
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    finish_connected(core.clone(), peer_id, stop, overlay, core.transport.clone(), "directlink").await;
}

// ---------------------------------------------------------------------------
// Joiner 流程（凭 6 位码 / 邀请加入 → punch → initiator Noise → Overlay）
// ---------------------------------------------------------------------------

async fn joiner_flow_with_view(core: Arc<AgentCore>, view: SessionView, friend: bool) {
    let cred = core.credential();
    let client = core.controller();
    let session_id = view.session_id.clone();
    let peer_id = PeerId(session_id.clone());

    let Some(me) = my_member(&view, &core.device_id) else {
        return core.fail("SESSION_MEMBER_MISSING", "会话成员视图缺少本机");
    };
    let Some(other) = other_member(&view, &core.device_id) else {
        return core.fail("WAIT_PEER_TIMEOUT", "对端尚未加入会话");
    };
    let Some(peer_key) = other.public_key() else {
        return core.fail("DEVICE_KEY_UNAVAILABLE", "Controller 未分发 creator 公钥");
    };
    let peer_device = other.device_id.clone();
    let peer_ip: Option<Ipv4Addr> = other.overlay_ip.as_deref().and_then(|p| p.parse().ok());
    let local_ip: Option<Ipv4Addr> = me.overlay_ip.as_deref().and_then(|p| p.parse().ok());

    let stop = Arc::new(AtomicBool::new(false));
    let overlay = core.new_overlay();
    {
        let mut s = core.session.lock().unwrap();
        *s = Some(SessionState {
            session_id: session_id.clone(),
            role: "joiner".into(),
            network_id: view.network_id.clone(),
            code: None,
            expires_at: view.expires_at.clone(),
            overlay_subnet: view.overlay_subnet.clone(),
            peer: PeerState {
                device_id: peer_device.clone(),
                peer_id: peer_id.clone(),
                overlay_ip: peer_ip,
                local_overlay_ip: local_ip,
                connected: false,
                smoke_passed: false,
            },
            stop: stop.clone(),
            overlay: overlay.clone(),
            friend_session: friend,
        });
    }

    // punch 准备 + 候选上传。
    core.transport.set_punch_session(session_id.clone(), core.transport.punch_candidates_wire());
    let cands = wire_candidates(&core.transport);
    if cands.is_empty() {
        return core.fail("CANDIDATE_GATHER_FAILED", "本机无可用 host candidate");
    }
    let _ = core.event_tx.send(Event::GatheringCandidates { count: cands.len() });
    {
        let c = client.clone();
        let cr = cred.clone();
        let sid = session_id.clone();
        if let Err(e) = AgentCore::controller_call(move || c.put_candidates(&cr, &sid, &cands)).await {
            return core.fail("CANDIDATE_UPLOAD_FAILED", e);
        }
    }

    // 拉取 creator 候选。
    let peers = match AgentCore::controller_call({
        let c = client.clone();
        let cr = cred.clone();
        let sid = session_id.clone();
        move || c.get_candidates(&cr, &sid)
    }).await {
        Ok(p) => p,
        Err(e) => return core.fail("CANDIDATE_FETCH_FAILED", e),
    };
    let eps = endpoints(&peers);
    if eps.is_empty() {
        // M1-2：DirectLink 不可用（无对端候选）→ Auto 自动回退 N2N。
        return joiner_fallback_to_n2n(
            core.clone(),
            view,
            friend,
            "DIRECTLINK_FAILED",
            "对端候选为空（creator 未上线或未上传）".into(),
        )
        .await;
    }
    core.set_state(AgentState::PeerDiscovered);
    let _ = core.event_tx.send(Event::PeerFound { peer_device_id: peer_device.clone() });

    // UDP 打洞（joiner 主动；失败 = DIRECTLINK_FAILED——产品要求）。
    core.set_state(AgentState::Punching);
    let _ = core.event_tx.send(Event::Punching { track: "B".into() });
    if core.cfg.force_directlink_fail {
        // 测试/诊断注入：模拟打洞不可达 → 触发 Auto 回退。
        tokio::time::sleep(Duration::from_millis(300)).await;
        return joiner_fallback_to_n2n(
            core.clone(),
            view,
            friend,
            "DIRECTLINK_FAILED",
            "UDP 打洞（MESHLINK_FORCE_DIRECTLINK_FAIL 注入）".into(),
        )
        .await;
    }
    let hints = PeerHints { endpoints: eps, static_key_fingerprint: None, overlay_mac: None };
    match tokio::time::timeout(core.cfg.punch_timeout, core.transport.connect_peer(peer_id.clone(), hints)).await {
        Err(_) => {
            return joiner_fallback_to_n2n(
                core.clone(),
                view,
                friend,
                "DIRECTLINK_FAILED",
                "UDP 打洞超时".into(),
            )
            .await
        }
        Ok(Err(e)) => {
            return joiner_fallback_to_n2n(core.clone(), view, friend, "DIRECTLINK_FAILED", e.to_string()).await
        }
        Ok(Ok(_)) => {}
    }

    // Noise IK initiator（expected key = Controller 分发的 creator 注册公钥）。
    core.set_state(AgentState::NoiseHandshake);
    let _ = core.event_tx.send(Event::NoiseHandshaking { role: "initiator".into() });
    if let Err(e) = core
        .transport
        .start_noise_initiator(&peer_id, core.identity.clone(), &view.network_id, &peer_device, &peer_key)
        .await
    {
        return joiner_fallback_to_n2n(core.clone(), view, friend, "NOISE_HANDSHAKE_FAILED", e.to_string()).await;
    }

    finish_connected(core.clone(), peer_id, stop, overlay, core.transport.clone(), "directlink").await;
}

// ---------------------------------------------------------------------------
// M1-2：N2N Creator 流程（Force N2N：Supernode 中继路径，无打洞/候选交换）
// ---------------------------------------------------------------------------

/// N2N Creator：Controller 会话 + N2N responder（等 joiner 经 SN 中继发 msg1）。
/// `friend`：好友会话标记（DirectLink 建链失败自动回退时透传，保留好友事件语义）。
async fn creator_flow_n2n_with_view(core: Arc<AgentCore>, view: SessionView, friend: bool) {
    // 前置：N2N Supernode 池必须可用。
    if core.n2n.supernodes().is_empty() {
        return core.fail("N2N_SUPERNODE_UNAVAILABLE", "未配置 N2N Supernode（Controller Registry 未下发）");
    }
    let cred = core.credential();
    let client = core.controller();
    let session_id = view.session_id.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let overlay = core.new_overlay();
    {
        let mut s = core.session.lock().unwrap();
        *s = Some(SessionState {
            session_id: session_id.clone(),
            role: "creator".into(),
            network_id: view.network_id.clone(),
            code: view.code.clone(),
            expires_at: view.expires_at.clone(),
            overlay_subnet: view.overlay_subnet.clone(),
            peer: PeerState {
                device_id: String::new(),
                peer_id: PeerId(session_id.clone()),
                overlay_ip: None,
                local_overlay_ip: None,
                connected: false,
                smoke_passed: false,
            },
            stop: stop.clone(),
            overlay: overlay.clone(),
            friend_session: friend,
        });
    }

    // N2N：本机设备名（transport device_id）即 SN 成员名；joiner 按它发现。
    core.n2n.configure_noise(core.identity.clone(), core.cfg.network_id.clone());

    core.set_state(AgentState::WaitingForPeer);
    let _ = core.event_tx.send(Event::WaitingForPeer {
        code: view.code.clone().unwrap_or_default(),
        session_id: session_id.clone(),
        expires_at: view.expires_at.clone(),
    });

    // 等待 joiner 加入（Controller 视图轮询，与 DirectLink creator 一致）。
    let deadline = Instant::now() + core.cfg.wait_peer_timeout;
    let (peer_device, peer_key, peer_ip, local_ip) = loop {
        if stop.load(Ordering::Acquire) {
            return core.aborted();
        }
        if Instant::now() > deadline {
            return core.fail_timeout("WAIT_PEER_TIMEOUT", "等待好友加入");
        }
        match AgentCore::controller_call({
            let c = client.clone();
            let cr = cred.clone();
            let sid = session_id.clone();
            move || c.get_session(&cr, &sid)
        }).await {
            Ok(v) => {
                if let (Some(me), Some(other)) =
                    (my_member(&v, &core.device_id), other_member(&v, &core.device_id))
                {
                    if me.overlay_ip.is_some() && other.overlay_ip.is_some() {
                        break (
                            other.device_id.clone(),
                            other.public_key(),
                            other.overlay_ip.clone(),
                            me.overlay_ip.clone(),
                        );
                    }
                }
            }
            Err(e) => {
                // M1-2.x：会话轮询查询失败（会话被删/过期等）——debug 级，避免刷屏。
                tracing::debug!(
                    target: "agent",
                    session_id = %session_id,
                    reason = %e.to_string(),
                    "[SESSION NOT FOUND] poll"
                );
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    };

    // 双向验证（规格二）：creator 登记 joiner 公钥——唯一来源 Controller Registry。
    let Some(peer_key) = peer_key else {
        return core.fail("DEVICE_KEY_UNAVAILABLE", "Controller 未分发 joiner 公钥");
    };

    // N2N channel 以对端 device_id 为名（SN 成员名）。禁止用 session_id：
    // 双端用同一 session_id 会在 SN 成员表冲突（互相覆盖 → 路由失效）。
    let n2n_peer = PeerId(peer_device.clone());
    {
        let mut s = core.session.lock().unwrap();
        if let Some(s) = s.as_mut() {
            s.peer.device_id = peer_device.clone();
            s.peer.peer_id = n2n_peer.clone();
            s.peer.overlay_ip = peer_ip.and_then(|p| p.parse().ok());
            s.peer.local_overlay_ip = local_ip.and_then(|p| p.parse().ok());
        }
    }

    // responder 待命：向 SN 登记本机（joiner 可发现）+ 建立对端 channel。
    core.n2n.start_accepting(n2n_peer.clone(), session_id.clone());
    core.n2n.set_expected_initiator(&n2n_peer, peer_key);
    core.n2n.require_initiator_identity(&n2n_peer);

    let _ = core.event_tx.send(Event::PeerFound { peer_device_id: peer_device.clone() });
    core.set_state(AgentState::NoiseHandshake);
    let _ = core.event_tx.send(Event::NoiseHandshaking { role: "responder".into() });

    // 等 Noise established（joiner 经 SN 中继发起 msg1；responder 线程自动应答）。
    let deadline = Instant::now() + core.cfg.handshake_timeout;
    loop {
        if stop.load(Ordering::Acquire) {
            return core.aborted();
        }
        if core.n2n.connected(&n2n_peer) {
            break;
        }
        if Instant::now() > deadline {
            return core.fail_timeout("NOISE_HANDSHAKE_TIMEOUT", "Noise IK 握手（N2N 路径）");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    finish_connected(core.clone(), n2n_peer, stop, overlay, core.n2n.clone(), "n2n").await;
}

// ---------------------------------------------------------------------------
// M1-2：N2N Joiner 流程（Force N2N / Auto 回退）
// ---------------------------------------------------------------------------

/// N2N Joiner：Supernode 中继路径（Force N2N 直入 / Auto 模式下 DirectLink 失败回退）。
/// `friend`：好友会话标记（保留好友事件语义；FriendConnected 由 AcceptConnectionRequest 调用方发送）。
async fn joiner_flow_n2n(core: Arc<AgentCore>, view: SessionView, friend: bool) {
    if core.n2n.supernodes().is_empty() {
        return core.fail("N2N_SUPERNODE_UNAVAILABLE", "未配置 N2N Supernode（Controller Registry 未下发）");
    }
    let session_id = view.session_id.clone();

    let Some(me) = my_member(&view, &core.device_id) else {
        return core.fail("SESSION_MEMBER_MISSING", "会话成员视图缺少本机");
    };
    let Some(other) = other_member(&view, &core.device_id) else {
        return core.fail("WAIT_PEER_TIMEOUT", "对端尚未加入会话");
    };
    let Some(peer_key) = other.public_key() else {
        return core.fail("DEVICE_KEY_UNAVAILABLE", "Controller 未分发 creator 公钥");
    };
    let peer_device = other.device_id.clone();
    let peer_ip: Option<Ipv4Addr> = other.overlay_ip.as_deref().and_then(|p| p.parse().ok());
    let local_ip: Option<Ipv4Addr> = me.overlay_ip.as_deref().and_then(|p| p.parse().ok());

    // N2N channel 以对端 device_id（creator）为名 = SN 成员名。
    let n2n_peer = PeerId(peer_device.clone());

    let stop = Arc::new(AtomicBool::new(false));
    let overlay = core.new_overlay();
    {
        let mut s = core.session.lock().unwrap();
        *s = Some(SessionState {
            session_id: session_id.clone(),
            role: "joiner".into(),
            network_id: view.network_id.clone(),
            code: None,
            expires_at: view.expires_at.clone(),
            overlay_subnet: view.overlay_subnet.clone(),
            peer: PeerState {
                device_id: peer_device.clone(),
                peer_id: n2n_peer.clone(),
                overlay_ip: peer_ip,
                local_overlay_ip: local_ip,
                connected: false,
                smoke_passed: false,
            },
            stop: stop.clone(),
            overlay: overlay.clone(),
            friend_session: friend,
        });
    }

    // N2N initiator：配置 Noise → 连接 Supernode → 发起 msg1 中继握手。
    core.n2n.configure_noise(core.identity.clone(), core.cfg.network_id.clone());

    let _ = core.event_tx.send(Event::PeerFound { peer_device_id: peer_device.clone() });
    core.set_state(AgentState::NoiseHandshake);
    let _ = core.event_tx.send(Event::NoiseHandshaking { role: "initiator".into() });

    // 先解析 creator 在 SN 的成员（creator 需先登记 → 注册竞态用重试吸收）。
    let conn_deadline = Instant::now() + core.cfg.handshake_timeout;
    loop {
        if stop.load(Ordering::Acquire) {
            return core.aborted();
        }
        if Instant::now() > conn_deadline {
            return core.fail_timeout("N2N_PEER_CONNECT_FAILED", "等待 creator 在 Supernode 上线");
        }
        match core.n2n.connect_peer(n2n_peer.clone(), PeerHints::default()) {
            Ok(_) => break,
            Err(e) => {
                tracing::debug!(target: "agent", err = %e, "connect_peer 未命中 creator，重试");
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }
    }

    if let Err(e) = core
        .n2n
        .start_noise_initiator(&n2n_peer, core.identity.clone(), &core.cfg.network_id, &peer_device, &peer_key)
        .await
    {
        return core.fail("NOISE_HANDSHAKE_FAILED", e);
    }

    // 等 Noise established。
    let deadline = Instant::now() + core.cfg.handshake_timeout;
    loop {
        if stop.load(Ordering::Acquire) {
            return core.aborted();
        }
        if core.n2n.connected(&n2n_peer) {
            break;
        }
        if Instant::now() > deadline {
            return core.fail_timeout("NOISE_HANDSHAKE_TIMEOUT", "Noise IK 握手（N2N 路径）");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    finish_connected(core.clone(), n2n_peer, stop, overlay, core.n2n.clone(), "n2n").await;
}

// ---------------------------------------------------------------------------
// 共同收尾：Overlay + /32 路由 + 数据泵 + 加密冒烟（规格十二 8 条件）
// ---------------------------------------------------------------------------

async fn finish_connected(
    core: Arc<AgentCore>,
    peer_id: PeerId,
    stop: Arc<AtomicBool>,
    overlay: Arc<Mutex<Box<dyn OverlayBackend>>>,
    io: Arc<dyn SessionPacketIo>,
    path_label: &'static str,
) {
    let (local_ip, peer_ip, subnet, prefix, adapter) = {
        let s = core.session.lock().unwrap();
        let s = s.as_ref().expect("finish_connected 必须有会话");
        (
            s.peer.local_overlay_ip,
            s.peer.overlay_ip,
            s.overlay_subnet.clone(),
            24,
            core.cfg.adapter_name.clone(),
        )
    };
    let Some(local_ip) = local_ip else {
        return core.fail("OVERLAY_IP_MISSING", "Controller 未分配本机 Overlay IP");
    };
    let Some(peer_ip) = peer_ip else {
        return core.fail("OVERLAY_IP_MISSING", "Controller 未分配对端 Overlay IP");
    };
    let (subnet, prefix) = subnet
        .as_deref()
        .and_then(parse_cidr)
        .unwrap_or((overlay_default_subnet(local_ip, prefix), prefix));

    // 条件 5/6：Overlay 接口 + 本机 Overlay IP（Controller IPAM，规格六）。
    core.set_state(AgentState::ConfiguringOverlay);
    tracing::info!(target: "gatedbg", agent = %core.tag, local = %local_ip, peer = %peer_ip, "finish_connected: 开始配置 Overlay");
    {
        let mut ov = overlay.lock().unwrap();
        if let Err(e) = ov.bring_up(OverlayConfig {
            adapter_name: adapter,
            tunnel_type: "MeshLink".into(),
            local_ip,
            subnet,
            prefix,
        }) {
            return core.fail("OVERLAY_SETUP_FAILED", e);
        }
        // 条件 7：对端 /32 主机路由（规格八：仅此一条，无默认路由/DNS）。
        if let Err(e) = ov.add_peer_route(peer_ip) {
            return core.fail("ROUTE_SETUP_FAILED", e);
        }
    }
    tracing::info!(target: "gatedbg", agent = %core.tag, "finish_connected: Overlay up + /32 路由完成");

    // 条件 4：Noise transport ready → 解密数据流。
    let Some(rx) = io.io_packet_rx(&peer_id) else {
        return core.fail("INTERNAL", "packet_rx 通道不可用（会话未建立）");
    };
    tracing::info!(target: "gatedbg", agent = %core.tag, "finish_connected: packet_rx 已取得");

    let smoke_ok = Arc::new(AtomicBool::new(false));
    {
        let transport = io.clone();
        let stop = stop.clone();
        let overlay = overlay.clone();
        let smoke_ok = smoke_ok.clone();
        let pump_peer = peer_id.clone();
        let tag = core.tag.clone();
        tokio::spawn(async move {
            pump(transport, pump_peer, rx, overlay, stop, smoke_ok, tag).await;
        });
    }
    tracing::info!(target: "gatedbg", agent = %core.tag, "finish_connected: pump 已 spawn");

    // 诊断 watchdog：验证 runtime 调度是否仍在推进（区分“任务冻结”与“runtime 卡死”）。
    {
        let smoke_ok = smoke_ok.clone();
        let stop = stop.clone();
        let tag = core.tag.clone();
        tokio::spawn(async move {
            let mut n = 0u32;
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                if stop.load(Ordering::Acquire) {
                    break; // P1-2：会话已结束，watchdog 退出，不泄漏空转任务。
                }
                n += 1;
                if n <= 4 || n % 4 == 0 {
                    tracing::info!(
                        target: "gatedbg",
                        agent = %tag,
                        n,
                        smoke = smoke_ok.load(Ordering::Acquire),
                        thread = ?std::thread::current().id(),
                        "watchdog: runtime 调度心跳"
                    );
                }
            }
        });
    }

    // 条件 8：加密 overlay 冒烟（ICMP Echo 经 Noise 往返）。
    // 冒烟请求周期性重发（对端 pump/RX 就绪存在启动时序竞争；单次发包可能
    // 落在对端尚未建立解密流时被丢弃——重发直到应答或超时，与真实 Overlay
    // 的数据面行为一致）。
    let req = crate::icmp::echo_request(local_ip, peer_ip);
    tracing::info!(target: "gatedbg", agent = %core.tag, len = req.len(), "finish_connected: 发送冒烟请求");
    let deadline = Instant::now() + core.cfg.smoke_timeout;
    let mut next_send = Instant::now();
    let mut wait_logged = 0u32;
    while !smoke_ok.load(Ordering::Acquire) {
        if stop.load(Ordering::Acquire) {
            return core.aborted();
        }
        if Instant::now() > deadline {
            return core.fail_timeout("OVERLAY_SMOKE_TIMEOUT", "加密 overlay 冒烟");
        }
        if Instant::now() >= next_send {
            if let Err(e) = io.io_send_packet(peer_id.clone(), Ipv4Packet { bytes: req.clone() }).await {
                tracing::warn!(target: "agent", "冒烟请求发送失败（继续重试）: {e}");
            }
            next_send = Instant::now() + Duration::from_millis(500);
        }
        wait_logged += 1;
        if wait_logged <= 3 || wait_logged % 10 == 0 {
            tracing::info!(target: "gatedbg", agent = %core.tag, iter = wait_logged, smoke = smoke_ok.load(Ordering::Acquire), thread = ?std::thread::current().id(), "finish_connected: 冒烟等待迭代");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 规格十二 8 条件全部满足（1 Controller peer verified / 2 path established /
    // 3 Noise mutual identity / 4 Noise transport / 5 Overlay ready /
    // 6 Overlay IP / 7 Route / 8 smoke passed）→ CONNECTED。
    core.set_current_path(path_label);
    {
        let mut s = core.session.lock().unwrap();
        if let Some(s) = s.as_mut() {
            s.peer.connected = true;
            s.peer.smoke_passed = true;
        }
    }
    core.set_state(AgentState::Connected);
    let _ = core.event_tx.send(Event::Connected {
        peer_device_id: {
            let s = core.session.lock().unwrap();
            s.as_ref().map(|s| s.peer.device_id.clone()).unwrap_or_default()
        },
        local_overlay_ip: local_ip.to_string(),
        peer_overlay_ip: peer_ip.to_string(),
        path: path_label.into(),
    });
    tracing::info!(
        target: "agent",
        local = %local_ip,
        peer = %peer_ip,
        path = path_label,
        "CONNECTED：规格十二 8 条件全部满足"
    );

    // M1-1.5：CONNECTED 后记录 recent_connection（异步，不阻塞数据面）。
    // 对端名称/指纹由 Controller 从 Registry 读取（本端只传 device_id + overlay_ip + path）。
    {
        let peer_id = core.session.lock().unwrap().as_ref().map(|s| s.peer.device_id.clone()).unwrap_or_default();
        if !peer_id.is_empty() {
            let core = core.clone();
            let client = core.controller();
            let cred = core.credential();
            let pid = peer_id.clone();
            let lip = local_ip.to_string();
            tokio::spawn(async move {
                match AgentCore::controller_call(move || client.upsert_recent_connection(&cred, &pid, &lip, path_label)).await {
                    Ok(_) => {
                        let _ = core.event_tx.send(Event::RecentConnectionsChanged);
                    }
                    Err(e) => {
                        tracing::warn!(target: "agent", peer = %peer_id, error = %e, "recent_connection 记录失败（不影响已建立连接）");
                    }
                }
            });
        }
    }
}

/// /24 对端网段兜底（Controller 正常会下发 overlay_subnet；缺失时保守推导）。
fn overlay_default_subnet(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) };
    Ipv4Addr::from(u32::from(ip) & mask)
}

// ---------------------------------------------------------------------------
// 数据泵（规格七）
// ---------------------------------------------------------------------------

async fn pump(
    transport: Arc<dyn SessionPacketIo>,
    peer_id: PeerId,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    overlay: Arc<Mutex<Box<dyn OverlayBackend>>>,
    stop: Arc<AtomicBool>,
    smoke_ok: Arc<AtomicBool>,
    tag: String,
) {
    let mut replies_sent: u64 = 0;
    let mut pump_iters: u64 = 0;
    while !stop.load(Ordering::Acquire) {
        pump_iters += 1;
        if pump_iters == 1 || pump_iters % 100 == 0 {
            tracing::info!(target: "gatedbg", agent = %tag, iter = pump_iters, replies = replies_sent, thread = ?std::thread::current().id(), "pump: 迭代心跳");
        }
        // 下行：DirectLink（Noise 解密）→ Overlay 注入本机协议栈。
        loop {
            match rx.try_recv() {
                Ok(bytes) => {
                    tracing::info!(
                        target: "gatedbg",
                        agent = %tag,
                        len = bytes.len(),
                        icmp_type = bytes.get(20).copied().map(|b| format!("type={b}")).unwrap_or_default(),
                        icmp_id = bytes.get(24..26).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0),
                        "pump: 收到解密包"
                    );
                    // 冒烟应答匹配（规格十二条件 8 的发起端判定）。
                    if crate::icmp::is_smoke_reply(&bytes) {
                        tracing::info!(target: "gatedbg", agent = %tag, "pump: 冒烟应答命中 smoke_ok");
                        smoke_ok.store(true, Ordering::Release);
                    }
                    // Agent 内置 ICMP 应答（Mock 与真实内核双保险；重复应答无害）。
                    if let Some(reply) = crate::icmp::smoke_reply_for(&bytes) {
                        replies_sent += 1;
                        if let Err(e) = transport.io_send_packet(peer_id.clone(), Ipv4Packet { bytes: reply }).await {
                            tracing::warn!(target: "agent", "内置 ICMP 应答发送失败: {e}");
                        }
                    }
                    if let Err(e) = overlay.lock().unwrap().send_packet(&bytes) {
                        tracing::warn!(target: "agent", "Overlay 注入失败: {e}");
                    }
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    tracing::info!(target: "gatedbg", agent = %tag, "pump: 解密数据流关闭，pump 退出");
                    return;
                }
            }
        }
        // 上行：Overlay RX（本机协议栈要发出的包）→ Noise encrypt → DirectLink。
        // 注意：MutexGuard 绝不跨 await 持有（Future Send 约束）——先取包再发送。
        let rx_pkt = {
            match overlay.lock().unwrap().recv_timeout(Duration::from_millis(10)) {
                Ok(p) => p,
                Err(e) => {
                    tracing::info!(target: "gatedbg", agent = %tag, error = %e, "pump: Overlay RX 错误，pump 退出");
                    return;
                }
            }
        };
        if let Some(pkt) = rx_pkt {
            tracing::info!(
                target: "gatedbg",
                agent = %tag,
                len = pkt.len(),
                icmp_type = pkt.get(20).copied().map(|b| format!("type={b}")).unwrap_or_default(),
                icmp_id = pkt.get(24..26).map(|b| u16::from_be_bytes([b[0], b[1]])).unwrap_or(0),
                "pump: 上行取出包并发送"
            );
            if let Err(e) = transport.io_send_packet(peer_id.clone(), Ipv4Packet { bytes: pkt }).await {
                tracing::warn!(target: "agent", "上行加密发送失败: {e}");
            }
        }
    }
    tracing::debug!(target: "agent", replies_sent, "pump 已退出（stop）");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn code_validation_strict() {
        assert!(valid_code("482731"));
        assert!(valid_code("000000"));
        assert!(!valid_code("48273"));
        assert!(!valid_code("4827311"));
        assert!(!valid_code("48273a"));
        assert!(!valid_code(""));
        assert!(!valid_code("48 731"));
    }

    #[test]
    fn invite_ttl_mapping() {
        assert!(matches!(parse_invite_ttl("permanent"), Some(InviteTtl::Permanent)));
        assert!(matches!(parse_invite_ttl("24h"), Some(InviteTtl::Hours24)));
        assert!(matches!(parse_invite_ttl("7d"), Some(InviteTtl::Days7)));
        assert!(parse_invite_ttl("1h").is_none());
        assert!(parse_invite_ttl("").is_none());
        assert_eq!(ttl_label(InviteTtl::Hours24), "24h");
    }

    #[test]
    fn cidr_parsing_and_default_subnet() {
        assert_eq!(parse_cidr("10.88.7.0/24"), Some((Ipv4Addr::new(10, 88, 7, 0), 24)));
        assert_eq!(parse_cidr("10.88.7.0/33"), None);
        assert_eq!(parse_cidr("10.88.7.0"), None);
        assert_eq!(
            overlay_default_subnet(Ipv4Addr::new(10, 88, 7, 5), 24),
            Ipv4Addr::new(10, 88, 7, 0)
        );
    }
}
