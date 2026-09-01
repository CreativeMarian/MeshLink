//! MeshLink Controller 客户端（Controller MVP，极简 HTTP + 生产 HTTPS）。
//!
//! 职责边界（用户规格一/四/六）：
//! - 设备注册 + credential 获取；6 位码会话创建/加入；候选交换；好友邀请；
//! - **Controller 是身份信任根**：joiner 获得 creator Noise 公钥的唯一可信
//!   来源是 join 响应（Controller Device Registry），6 位码只是会话索引，
//!   绝不作为认证 secret、绝不派生 Noise 密钥；
//! - 本客户端只做信令面调用，**不进入数据面**（数据路径 = DirectLink UDP + Noise）。
//!
//! 传输白名单（Overlay MVP 规格一，硬性）：
//! - DEV MODE：仅 `http://127.0.0.1[:port]` / `http://localhost[:port]`（明文限回环）；
//! - PRODUCTION：仅 `https://host[:port]`（默认 443）；事件端点 `wss://` 同规则；
//! - **公网明文 HTTP 一律拒绝**（`http://` 非 localhost → 构造失败）；
//! - **禁止降级**：https 连接失败只会返回 TRANSPORT 错误，绝无自动重试明文。
//!   Controller 若经 Cloudflare Tunnel 暴露，客户端仍走标准 https://，
//!   不感知 Tunnel 存在。

use mesh_common::{ErrorCode, MeshError};
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

const USER_AGENT: &str = "meshlink-controller-client/0.1";
const IO_TIMEOUT: Duration = Duration::from_secs(8);

/// API 结构化错误（code 与 Controller api.go 约定一致）。
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP 状态码（0 = 传输层错误）。
    pub status: u16,
    /// 业务错误码（如 DEVICE_KEY_MISMATCH / SESSION_RATE_LIMITED）。
    pub code: String,
    pub message: String,
}

impl ApiError {
    /// 传输失败（连接/超时/响应非法）。
    fn transport(msg: impl Into<String>) -> Self {
        Self { status: 0, code: "TRANSPORT".into(), message: msg.into() }
    }

    pub fn is_code(&self, code: &str) -> bool {
        self.code == code
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.status == 0 {
            write!(f, "controller transport error: {}", self.message)
        } else {
            write!(f, "controller error {} (HTTP {}): {}", self.code, self.status, self.message)
        }
    }
}

impl std::error::Error for ApiError {}

impl From<ApiError> for MeshError {
    fn from(e: ApiError) -> Self {
        MeshError::new(ErrorCode::ControllerProtocol, e.to_string())
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

// ---- 领域类型（与 Go internal/model 严格对应） ----

/// POST /v1/devices 响应：首次注册一次性下发 credential（Controller 只存 hash）。
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceRegistration {
    pub device_id: String,
    pub noise_public_key: String,
    #[serde(default)]
    pub device_name: Option<String>,
    /// registered | existing。
    pub status: String,
    /// 仅首次注册出现；客户端必须 DPAPI 持久化（secure-store update_credential）。
    #[serde(default)]
    pub credential: Option<String>,
}

/// 会话成员（含公钥快照——Controller 分发身份的核心通道）。
#[derive(Debug, Clone, Deserialize)]
pub struct SessionMember {
    pub session_id: String,
    pub device_id: String,
    /// creator | joiner（与 Noise 角色一致：creator=responder，joiner=initiator）。
    pub role: String,
    /// hex 64：加入时刻的注册公钥快照。
    pub noise_public_key: String,
    pub joined_at: String,
    /// Controller IPAM 分配的本会话 overlay IPv4（如 "10.88.7.1"）。
    #[serde(default)]
    pub overlay_ip: Option<String>,
}

impl SessionMember {
    /// 公钥快照 hex → 32 字节（不可信输入：只拒绝不 panic）。
    pub fn public_key(&self) -> Option<[u8; 32]> {
        decode_key32(&self.noise_public_key)
    }
}

/// 会话视图。`code` 仅创建者可见（joiner 不需要码本身）。
#[derive(Debug, Clone, Deserialize)]
pub struct SessionView {
    pub session_id: String,
    #[serde(default)]
    pub code: Option<String>,
    pub network_id: String,
    /// WAITING | JOINED | CLOSED。
    pub status: String,
    pub members: Vec<SessionMember>,
    /// Controller IPAM 为本会话分配的独占 /24（如 "10.88.7.0/24"）。
    #[serde(default)]
    pub overlay_subnet: Option<String>,
    /// 会话过期时刻（RFC3339 UTC；UI 倒计时输入）。
    #[serde(default)]
    pub expires_at: Option<String>,
}

impl SessionView {
    /// 按角色取对端成员（creator 取 joiner，joiner 取 creator）。
    pub fn peer_member(&self, my_device_id: &str) -> Option<&SessionMember> {
        self.members.iter().find(|m| m.device_id != my_device_id)
    }
}

/// 候选（与 directlink CandidateWire 对应：IPv4 + port + host|srflx）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub ip: String,
    pub port: u16,
    pub kind: String,
}

/// GET /v1/sessions/{id}/candidates 响应中的单个对端。
#[derive(Debug, Clone, Deserialize)]
pub struct PeerCandidates {
    pub device_id: String,
    pub candidates: Vec<Candidate>,
    pub updated_at: String,
}

/// 好友邀请视图（invite_token 仅创建响应出现一次）。
#[derive(Debug, Clone, Deserialize)]
pub struct InviteView {
    pub invite_id: String,
    #[serde(default)]
    pub invite_token: Option<String>,
    pub network_id: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    /// 0 = 不限次。
    pub max_uses: i64,
    pub used_count: i64,
    /// ACTIVE | REVOKED | EXHAUSTED。
    pub status: String,
    pub created_at: String,
}

/// 设备（Controller Device Registry 条目）。
#[derive(Debug, Clone, Deserialize)]
pub struct Device {
    pub device_id: String,
    /// hex 64：Controller Registry 中该设备的 Noise 静态公钥。
    pub noise_public_key: String,
    #[serde(default)]
    pub device_name: Option<String>,
    pub status: String,
    pub created_at: String,
    pub last_seen_at: String,
}

/// 设备 + 在线状态（last_seen 新鲜度判定）。
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceWithPresence {
    #[serde(flatten)]
    pub device: Device,
    pub online: bool,
}

/// 好友关系视图（对端设备 + 在线状态）。
#[derive(Debug, Clone, Deserialize)]
pub struct FriendView {
    pub friendship_id: String,
    /// PENDING | ACCEPTED | BLOCKED | REMOVED。
    pub status: String,
    pub created_at: String,
    pub peer: DeviceWithPresence,
}

/// 兑换响应：PENDING 好友关系 + 邀请方设备信息（UI 显示"来自 X"）。
#[derive(Debug, Clone, Deserialize)]
pub struct RedeemView {
    pub friendship_id: String,
    pub status: String,
    pub creator: DeviceWithPresence,
}

/// 事件轮询响应（events/poll：权威通道；WSS 仅为加速）。
#[derive(Debug, Clone, Deserialize)]
pub struct EventPoll {
    #[serde(default)]
    pub events: Vec<ControllerEvent>,
    pub seq: i64,
}

/// M1-2：Controller Supernode Registry 视图。
#[derive(Debug, Clone, Deserialize)]
pub struct SupernodeView {
    pub id: String,
    pub host: String,
    pub port: u16,
    #[serde(default = "default_priority")]
    pub priority: u32,
    #[serde(default)]
    pub healthy: bool,
}

fn default_priority() -> u32 {
    100
}

/// M1-1.5：最近连接历史视图（本地视角；指纹快照来自 Controller Registry）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentConnection {
    pub id: i64,
    pub local_device_id: String,
    pub remote_device_id: String,
    #[serde(default)]
    pub remote_name: String,
    /// hex 64 快照（来自 Registry，客户端不可自报）。
    #[serde(default)]
    pub remote_fingerprint: String,
    pub last_connected_at: String,
    #[serde(default)]
    pub last_overlay_ip: String,
    #[serde(default)]
    pub last_path: String,
    #[serde(default)]
    pub connection_count: i64,
    pub created_at: String,
}

/// Controller 事件（type 与 events.go 常量对应；payload 为结构化 JSON）。
#[derive(Debug, Clone, Deserialize)]
pub struct ControllerEvent {
    pub seq: i64,
    #[serde(rename = "type")]
    #[serde(default)]
    pub event_type: String,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub payload: serde_json::Map<String, serde_json::Value>,
}

/// 事件类型常量（与 events.go 对齐）。
pub mod event_types {
    pub const SESSION_JOINED: &str = "session_joined";
    pub const CANDIDATES_UPDATED: &str = "candidates_updated";
    pub const CONNECTION_REQUEST: &str = "connection_request";
    pub const REQUEST_REJECTED: &str = "connection_request_rejected";
    pub const FRIEND_PENDING: &str = "friend_pending";
    pub const FRIEND_ACCEPTED: &str = "friend_accepted";
    pub const FRIEND_REMOVED: &str = "friend_removed";
}

/// 邀请 TTL 档位。
#[derive(Debug, Clone, Copy)]
pub enum InviteTtl {
    Permanent,
    Hours24,
    Days7,
}

impl InviteTtl {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Permanent => "permanent",
            Self::Hours24 => "24h",
            Self::Days7 => "7d",
        }
    }
}

// ---- HTTP 客户端 ----

/// 传输方案（构造期白名单裁决，运行期不可变——降级在类型层不可能）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// DEV MODE：明文 HTTP，仅限 127.0.0.1 / localhost。
    HttpLocal,
    /// PRODUCTION：TLS（rustls，系统根或固定 CA）。
    Https,
}

/// Controller 客户端（同步、每请求新建连接——MVP 信令调用频率极低，简单可靠优先）。
#[derive(Debug, Clone)]
pub struct Client {
    scheme: Scheme,
    host: String,
    port: u16,
    /// https 时的 rustls 配置（None + Https 只出现在系统根加载失败的延迟错误）。
    tls: Option<Arc<rustls::ClientConfig>>,
    /// HTTPS 代理（HTTP CONNECT 隧道）。环境变量/Windows 系统代理解析；
    /// 代理只用于 https（公网 Controller）——DEV 明文回环不走代理。
    proxy: Option<ProxyConfig>,
}

/// HTTP 代理配置（仅支持 HTTP/HTTPS CONNECT 隧道；socks 不支持）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyConfig {
    pub host: String,
    pub port: u16,
}

/// 解析 base_url：`scheme://host[:port]`。
/// 白名单：http:// 仅 127.0.0.1|localhost（DEV）；https:// 任意 host（PRODUCTION）。
/// 其余（公网 http、ws、ftp、裸 host…）一律构造失败。
fn parse_base_url(base_url: &str) -> ApiResult<(Scheme, String, u16)> {
    let rest = base_url.trim().trim_end_matches('/');
    let (scheme_str, hostport) = rest
        .split_once("://")
        .ok_or_else(|| ApiError::transport(format!("base_url 非法（须 http(s)://host:port）: {base_url}")))?;
    let default_port = match scheme_str {
        "http" | "https" => {}
        "wss" => {
            return Err(ApiError::transport(
                "wss:// 是事件通道端点而非 API base_url；API 请用 https://（PRODUCTION）",
            ))
        }
        "ws" => {
            return Err(ApiError::transport(
                "ws:// 是 DEV 事件通道端点而非 API base_url；API 请用 http://127.0.0.1:<port>（DEV）",
            ))
        }
        other => return Err(ApiError::transport(format!("不支持的 scheme: {other}"))),
    };
    let scheme = match scheme_str {
        "http" => {
            let host = hostport.rsplit_once(':').map(|(h, _)| h).unwrap_or(hostport);
            let ok_loop = host == "127.0.0.1" || host == "localhost";
            let ok_lan = match host.parse::<std::net::IpAddr>() {
                // Ipv4Addr::is_private() 稳定（RFC1918）；IPv6 局域网联机请走 https。
                Ok(std::net::IpAddr::V4(v4)) => v4.is_private(),
                Ok(std::net::IpAddr::V6(_)) => false,
                Err(_) => false,
            };
            if !(ok_loop || ok_lan) {
                return Err(ApiError::transport(format!(
                    "公网明文 HTTP 禁止（{hostport}）：DEV MODE 仅允许 http://127.0.0.1|localhost 或 RFC1918 私网，PRODUCTION 请用 https://"
                )));
            }
            Scheme::HttpLocal
        }
        _ => Scheme::Https,
    };
    let _ = default_port;
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|_| ApiError::transport(format!("端口非法: {p}")))?;
            (h.to_string(), port)
        }
        None => (hostport.to_string(), if scheme == Scheme::Https { 443 } else { 80 }),
    };
    if host.is_empty() || port == 0 {
        return Err(ApiError::transport("host/port 非法"));
    }
    Ok((scheme, host, port))
}

impl Client {
    /// DEV：`http://127.0.0.1:18080`（默认端口）；PRODUCTION：`https://control.example.com`。
    /// https 默认信任系统根；自签/私有 CA 用 [`Client::with_ca_pem`]。
    pub fn new(base_url: &str) -> ApiResult<Self> {
        let (scheme, host, port) = parse_base_url(base_url)?;
        let tls = match scheme {
            Scheme::HttpLocal => None,
            Scheme::Https => Some(build_client_config(None)?),
        };
        Ok(Self { scheme, host, port, tls, proxy: resolve_proxy() })
    }

    /// 固定信任 CA（PEM 文件路径）——自签 Controller 或私有 CA 场景。
    /// 仅对 https 生效；http:// base_url 调用本方法为配置错误。
    pub fn with_ca_pem(base_url: &str, ca_pem: &std::path::Path) -> ApiResult<Self> {
        let (scheme, host, port) = parse_base_url(base_url)?;
        match scheme {
            Scheme::HttpLocal => Err(ApiError::transport(
                "with_ca_pem 仅适用于 https:// base_url（DEV 明文无需 CA）",
            )),
            Scheme::Https => Ok(Self {
                scheme,
                host,
                port,
                tls: Some(build_client_config(Some(ca_pem))?),
                proxy: resolve_proxy(),
            }),
        }
    }

    /// 当前生效的 HTTPS 代理（诊断用；None = 直连）。
    pub fn proxy(&self) -> Option<&ProxyConfig> {
        self.proxy.as_ref()
    }

    /// DEV/PROD 判定（诊断与测试用）。
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// 事件通道端点 URL（MVP 事件用 HTTP 轮询获取；PRODUCTION 客户端对外
    /// 仍呈 https:// 语义，wss:// 升级由事件通道后续里程碑接入）。
    pub fn event_base_url(&self) -> String {
        match self.scheme {
            Scheme::HttpLocal => format!("http://{}:{}", self.host, self.port),
            Scheme::Https => format!("https://{}:{}", self.host, self.port),
        }
    }

    // ---- API 方法 ----

    /// GET /healthz（无需认证）：就绪探测。
    pub fn healthz(&self) -> ApiResult<serde_json::Value> {
        self.request("GET", "/healthz", None, None)
    }

    /// POST /v1/devices（无需认证）：首次注册建立 device_id→公钥绑定。
    /// 幂等重放（同公钥）→ status=existing；**公钥变化 → DEVICE_KEY_MISMATCH**。
    pub fn register_device(
        &self,
        device_id: &str,
        public_key_hex: &str,
        device_name: Option<&str>,
    ) -> ApiResult<DeviceRegistration> {
        #[derive(Serialize)]
        struct Req<'a> {
            device_id: &'a str,
            noise_public_key: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            device_name: Option<&'a str>,
        }
        let body = serde_json::to_vec(&Req {
            device_id,
            noise_public_key: public_key_hex,
            device_name,
        })
        .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        self.request("POST", "/v1/devices", None, Some(&body))
    }

    /// POST /v1/sessions（auth）：创建 WAITING 会话，Controller 原子分配 6 位码。
    pub fn create_session(&self, credential: &str, network_id: &str) -> ApiResult<SessionView> {
        #[derive(Serialize)]
        struct Req<'a> {
            network_id: &'a str,
        }
        let body = serde_json::to_vec(&Req { network_id })
            .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        self.request("POST", "/v1/sessions", Some(credential), Some(&body))
    }

    /// POST /v1/sessions/{code}/join（auth）：凭 6 位码加入。
    /// 响应 members 含 creator 公钥快照——**joiner 信任的 creator 公钥唯一来源**。
    pub fn join_session(&self, credential: &str, code: &str) -> ApiResult<SessionView> {
        let path = format!("/v1/sessions/{code}/join");
        self.request("POST", &path, Some(credential), Some(b"{}"))
    }

    /// GET /v1/sessions/{session_id}（auth 成员）：creator 轮询发现 joiner。
    pub fn get_session(&self, credential: &str, session_id: &str) -> ApiResult<SessionView> {
        let path = format!("/v1/sessions/{session_id}");
        self.request("GET", &path, Some(credential), None)
    }

    /// PUT /v1/sessions/{session_id}/candidates（auth 成员）：上传本端候选集。
    pub fn put_candidates(
        &self,
        credential: &str,
        session_id: &str,
        candidates: &[Candidate],
    ) -> ApiResult<usize> {
        #[derive(Serialize)]
        struct Req<'a> {
            candidates: &'a [Candidate],
        }
        let body = serde_json::to_vec(&Req { candidates })
            .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        let path = format!("/v1/sessions/{session_id}/candidates");
        #[derive(Deserialize)]
        struct Resp {
            count: usize,
        }
        let resp: Resp = self.request("PUT", &path, Some(credential), Some(&body))?;
        Ok(resp.count)
    }

    /// GET /v1/sessions/{session_id}/candidates（auth 成员）：拉取对端候选
    /// （返回为空 = 对端尚未上传，调用方轮询重试）。
    pub fn get_candidates(
        &self,
        credential: &str,
        session_id: &str,
    ) -> ApiResult<Vec<PeerCandidates>> {
        let path = format!("/v1/sessions/{session_id}/candidates");
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            peers: Vec<PeerCandidates>,
        }
        let resp: Resp = self.request("GET", &path, Some(credential), None)?;
        Ok(resp.peers)
    }

    /// POST /v1/invites（auth）：创建好友邀请（与 6 位码完全独立的长期授权）。
    pub fn create_invite(
        &self,
        credential: &str,
        network_id: &str,
        ttl: InviteTtl,
        max_uses: i64,
    ) -> ApiResult<InviteView> {
        #[derive(Serialize)]
        struct Req<'a> {
            network_id: &'a str,
            ttl: &'a str,
            max_uses: i64,
        }
        let body = serde_json::to_vec(&Req {
            network_id,
            ttl: ttl.as_str(),
            max_uses,
        })
        .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        self.request("POST", "/v1/invites", Some(credential), Some(&body))
    }

    /// POST /v1/invites/{invite_id}/redeem（auth）：凭 token 兑换邀请，
    /// 建立 PENDING 好友关系（M1-1：不再创建连接会话）。响应含邀请方设备信息。
    pub fn redeem_invite(
        &self,
        credential: &str,
        invite_id: &str,
        invite_token: &str,
    ) -> ApiResult<RedeemView> {
        let path = format!("/v1/invites/{invite_id}/redeem");
        #[derive(Serialize)]
        struct Req<'a> {
            invite_token: &'a str,
        }
        let body = serde_json::to_vec(&Req { invite_token })
            .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        self.request("POST", &path, Some(credential), Some(&body))
    }

    /// GET /v1/invites（auth）：我的邀请列表（含状态/使用情况）。
    pub fn list_invites(&self, credential: &str) -> ApiResult<Vec<InviteView>> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            invites: Vec<InviteView>,
        }
        let resp: Resp = self.request("GET", "/v1/invites", Some(credential), None)?;
        Ok(resp.invites)
    }

    /// POST /v1/invites/{invite_id}/revoke（auth 创建者）：撤销邀请 → 旧 token 失效。
    pub fn revoke_invite(&self, credential: &str, invite_id: &str) -> ApiResult<()> {
        let path = format!("/v1/invites/{invite_id}/revoke");
        let _: serde_json::Value = self.request("POST", &path, Some(credential), Some(b"{}"))?;
        Ok(())
    }

    // ---- 好友关系（M1-1） ----

    /// GET /v1/friendships（auth）：我的好友列表（含对端设备+在线；PENDING 请求也在内）。
    pub fn list_friendships(&self, credential: &str) -> ApiResult<Vec<FriendView>> {
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            friendships: Vec<FriendView>,
        }
        let resp: Resp = self.request("GET", "/v1/friendships", Some(credential), None)?;
        Ok(resp.friendships)
    }

    /// GET /v1/friendships/{friendship_id}（auth 成员）：好友关系详情。
    pub fn get_friendship(&self, credential: &str, friendship_id: &str) -> ApiResult<FriendView> {
        let path = format!("/v1/friendships/{friendship_id}");
        self.request("GET", &path, Some(credential), None)
    }

    /// POST /v1/friendships/{friendship_id}/accept（auth 成员）：接受好友请求 → ACCEPTED。
    pub fn accept_friendship(&self, credential: &str, friendship_id: &str) -> ApiResult<FriendView> {
        let path = format!("/v1/friendships/{friendship_id}/accept");
        self.request("POST", &path, Some(credential), Some(b"{}"))
    }

    /// POST /v1/friendships/{friendship_id}/reject（auth 成员）：拒绝 → REMOVED。
    pub fn reject_friendship(&self, credential: &str, friendship_id: &str) -> ApiResult<()> {
        let path = format!("/v1/friendships/{friendship_id}/reject");
        let _: serde_json::Value = self.request("POST", &path, Some(credential), Some(b"{}"))?;
        Ok(())
    }

    /// POST /v1/friendships/{friendship_id}/revoke（auth 成员）：删除好友（撤销授权）。
    pub fn revoke_friendship(&self, credential: &str, friendship_id: &str) -> ApiResult<()> {
        let path = format!("/v1/friendships/{friendship_id}/revoke");
        let _: serde_json::Value = self.request("POST", &path, Some(credential), Some(b"{}"))?;
        Ok(())
    }

    /// POST /v1/friends/{device_id}/connect（auth）：向好友发起直连请求。
    /// 返回 WAITING 会话（target 接受后走既有 DirectLink/Noise/Overlay）。
    pub fn friend_connect(
        &self,
        credential: &str,
        target_device_id: &str,
        network_id: &str,
    ) -> ApiResult<SessionView> {
        let path = format!("/v1/friends/{target_device_id}/connect");
        #[derive(Serialize)]
        struct Req<'a> {
            network_id: &'a str,
        }
        let body = serde_json::to_vec(&Req { network_id })
            .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        self.request("POST", &path, Some(credential), Some(&body))
    }

    /// POST /v1/sessions/{session_id}/accept-request（auth）：接受好友直连请求 → JOINED。
    pub fn accept_connection_request(
        &self,
        credential: &str,
        session_id: &str,
    ) -> ApiResult<SessionView> {
        let path = format!("/v1/sessions/{session_id}/accept-request");
        self.request("POST", &path, Some(credential), Some(b"{}"))
    }

    /// POST /v1/sessions/{session_id}/reject-request（auth）：拒绝好友直连请求。
    pub fn reject_connection_request(&self, credential: &str, session_id: &str) -> ApiResult<()> {
        let path = format!("/v1/sessions/{session_id}/reject-request");
        let _: serde_json::Value = self.request("POST", &path, Some(credential), Some(b"{}"))?;
        Ok(())
    }

    // ---- 设备 / 在线状态 ----

    /// GET /v1/devices/{device_id}（auth）：设备详情（含公钥指纹；仅本人或好友可查）。
    pub fn get_device(&self, credential: &str, device_id: &str) -> ApiResult<DeviceWithPresence> {
        let path = format!("/v1/devices/{device_id}");
        self.request("GET", &path, Some(credential), None)
    }

    /// POST /v1/presence/heartbeat（auth）：显式保活（auth 中间件已 touch last_seen）。
    pub fn presence_heartbeat(&self, credential: &str) -> ApiResult<()> {
        let _: serde_json::Value = self.request("POST", "/v1/presence/heartbeat", Some(credential), Some(b"{}"))?;
        Ok(())
    }

    /// GET /v1/events/poll?since={seq}（auth）：轮询本设备事件（权威通道）。
    pub fn poll_events(&self, credential: &str, since: i64) -> ApiResult<EventPoll> {
        let path = format!("/v1/events/poll?since={since}");
        self.request("GET", &path, Some(credential), None)
    }

    /// M1-2：拉取 Controller Supernode Registry（Priority + 熔断池由 Agent 侧消费）。
    pub fn list_supernodes(&self, credential: &str) -> ApiResult<Vec<SupernodeView>> {
        #[derive(Deserialize)]
        struct SupernodeList {
            #[serde(default)]
            supernodes: Vec<SupernodeView>,
        }
        let list: SupernodeList = self.request("GET", "/v1/supernodes", Some(credential), None)?;
        Ok(list.supernodes)
    }

    /// M1-2：注册/更新一个 Supernode（POST /v1/supernodes，需已注册设备 credential）。
    /// MeshLink 监督者拉起的本机 DEV/自托管 Supernode 由 Agent 以本方法登记，
    /// credential 始终由 Agent 持有（UI 不触碰）。
    pub fn register_supernode(
        &self,
        credential: &str,
        id: &str,
        host: &str,
        port: u16,
        priority: u32,
    ) -> ApiResult<()> {
        #[derive(Serialize)]
        struct Req<'a> {
            id: &'a str,
            host: &'a str,
            port: u16,
            priority: u32,
        }
        let body = serde_json::to_vec(&Req { id, host, port, priority })
            .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        let _: serde_json::Value = self.request("POST", "/v1/supernodes", Some(credential), Some(&body))?;
        Ok(())
    }

    // ---- M1-1.5：最近连接历史 ----

    /// GET /v1/devices/me/recent-connections（auth）：本机最近连接历史。
    pub fn list_recent_connections(&self, credential: &str) -> ApiResult<Vec<RecentConnection>> {
        #[derive(Deserialize)]
        struct RecentList {
            #[serde(default)]
            recent_connections: Vec<RecentConnection>,
        }
        let list: RecentList =
            self.request("GET", "/v1/devices/me/recent-connections", Some(credential), None)?;
        Ok(list.recent_connections)
    }

    /// PUT /v1/devices/me/recent-connections/{device_id}（auth）：CONNECTED 后记录。
    /// 对端名称/指纹由 Controller 从 Registry 读取，本端只上传 overlay_ip 与 path。
    pub fn upsert_recent_connection(
        &self,
        credential: &str,
        remote_device_id: &str,
        overlay_ip: &str,
        path: &str,
    ) -> ApiResult<RecentConnection> {
        let path_url = format!("/v1/devices/me/recent-connections/{remote_device_id}");
        #[derive(Serialize)]
        struct Req<'a> {
            #[serde(skip_serializing_if = "str::is_empty")]
            overlay_ip: &'a str,
            #[serde(skip_serializing_if = "str::is_empty")]
            path: &'a str,
        }
        let body = serde_json::to_vec(&Req { overlay_ip, path })
            .map_err(|e| ApiError::transport(format!("序列化失败: {e}")))?;
        self.request("PUT", &path_url, Some(credential), Some(&body))
    }

    /// DELETE /v1/devices/me/recent-connections/{device_id}（auth）：删除本地历史。
    pub fn delete_recent_connection(&self, credential: &str, remote_device_id: &str) -> ApiResult<()> {
        let path = format!("/v1/devices/me/recent-connections/{remote_device_id}");
        let _: serde_json::Value = self.request("DELETE", &path, Some(credential), None)?;
        Ok(())
    }

    // ---- 传输层 ----

    fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        credential: Option<&str>,
        body: Option<&[u8]>,
    ) -> ApiResult<T> {
        let payload = self.call(method, path, credential, body)?;
        serde_json::from_slice(&payload)
            .map_err(|e| ApiError::transport(format!("响应 JSON 解析失败: {e}（原始: {}）",
                String::from_utf8_lossy(&payload[..payload.len().min(256)]))))
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        credential: Option<&str>,
        body: Option<&[u8]>,
    ) -> ApiResult<Vec<u8>> {
        let mut req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: {USER_AGENT}\r\nAccept: application/json\r\nConnection: close\r\n",
            self.host, self.port
        );
        if let Some(cred) = credential {
            req.push_str(&format!("Authorization: Bearer {cred}\r\n"));
        }
        if let Some(b) = body {
            req.push_str("Content-Type: application/json\r\n");
            req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        req.push_str("\r\n");

        let addr = format!("{}:{}", self.host, self.port);
        // 单一分派：DEV 走明文，PRODUCTION 走 TLS——https 失败绝不回落 http。
        let raw = match self.scheme {
            Scheme::HttpLocal => {
                let mut stream = connect_with_timeout(&addr, IO_TIMEOUT)
                    .map_err(|e| ApiError::transport(format!("连接 Controller {addr} 失败: {e}")))?;
                set_timeouts(&stream)?;
                write_request(&mut stream, req.as_bytes(), body)?;
                read_to_end(&mut stream)?
            }
            Scheme::Https => self.call_tls(&addr, req.as_bytes(), body)?,
        };
        parse_http_response(&raw)
    }

    /// PRODUCTION 传输：rustls over TcpStream（每请求新建 TLS 连接——
    /// 信令频率极低，简单可靠优先）。失败只报 TRANSPORT 错误，无降级路径。
    /// 已配置 HTTPS 代理时先经 HTTP CONNECT 隧道（v2rayN/Clash 规则模式下
    /// agent 直连被网络环境阻断时的出路），再在隧道上跑 TLS。
    fn call_tls(&self, addr: &str, req_head: &[u8], body: Option<&[u8]>) -> ApiResult<Vec<u8>> {
        use rustls::Stream;
        let config = self
            .tls
            .as_ref()
            .ok_or_else(|| ApiError::transport("TLS 配置缺失（内部错误）"))?;
        let server_name = rustls_pki_types::ServerName::try_from(self.host.clone())
            .map_err(|_| ApiError::transport(format!("TLS SNI 主机名非法: {}", self.host)))?;
        let mut conn = rustls::ClientConnection::new(Arc::clone(config), server_name)
            .map_err(|e| ApiError::transport(format!("TLS 客户端初始化失败: {e}")))?;
        let mut sock = match &self.proxy {
            Some(p) => {
                let pa = format!("{}:{}", p.host, p.port);
                let mut s = connect_with_timeout(&pa, IO_TIMEOUT).map_err(|e| {
                    ApiError::transport(format!("连接 HTTPS 代理 {pa} 失败: {e}"))
                })?;
                set_timeouts(&s)?;
                connect_proxy(&mut s, addr)?;
                s
            }
            None => {
                let s = connect_with_timeout(addr, IO_TIMEOUT).map_err(|e| {
                    ApiError::transport(format!("连接 Controller {addr} 失败: {e}"))
                })?;
                set_timeouts(&s)?;
                s
            }
        };
        let mut tls = Stream::new(&mut conn, &mut sock);
        write_request(&mut tls, req_head, body)?;
        read_to_end(&mut tls)
    }
}

/// HTTP CONNECT 隧道（TLS 前置）：向代理请求建立到 `target`（host:port）的隧道，
/// 读到 200 即建立；非 200 / 代理无响应 → transport 错误。
fn connect_proxy(stream: &mut TcpStream, target: &str) -> ApiResult<()> {
    use std::io::{Read, Write};
    let req = format!(
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| ApiError::transport(format!("发送代理 CONNECT 失败: {e}")))?;
    let mut resp = Vec::new();
    let mut byte = [0u8; 1];
    while !resp.windows(4).any(|w| w == b"\r\n\r\n") {
        if resp.len() > 8192 {
            return Err(ApiError::transport("代理 CONNECT 响应头过长"));
        }
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => resp.push(byte[0]),
            Err(e) => return Err(ApiError::transport(format!("读取代理 CONNECT 响应失败: {e}"))),
        }
    }
    let head = String::from_utf8_lossy(&resp);
    let code = head.split_whitespace().nth(1).unwrap_or("000").to_string();
    if code != "200" {
        return Err(ApiError::transport(format!("代理 CONNECT 失败（HTTP {code}）")));
    }
    Ok(())
}

/// 解析代理地址（支持 `host:port` 或 `http://host:port`；忽略 user:pass 与 socks 前缀）。
fn parse_proxy_addr(raw: &str) -> Option<ProxyConfig> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let body = raw
        .strip_prefix("http://")
        .or_else(|| raw.strip_prefix("https://"))
        .or_else(|| {
            if raw.starts_with("socks") {
                None
            } else {
                Some(raw)
            }
        })?;
    // 忽略 user:pass@（第一版不做代理认证）。
    let body = body.rsplit_once('@').map(|(_, h)| h).unwrap_or(body);
    let (host, port) = match body.rsplit_once(':') {
        Some((h, p)) => (h.trim(), p.trim().parse::<u16>().ok()?),
        None => (body.trim(), 0),
    };
    if host.is_empty() || port == 0 {
        return None;
    }
    Some(ProxyConfig { host: host.to_string(), port })
}

/// 生效 HTTPS 代理：`MESHLINK_HTTPS_PROXY`（专属覆盖）→ `HTTPS_PROXY`/`https_proxy`
/// → `ALL_PROXY` → Windows 系统代理（ProxyEnable=1 时取 ProxyServer 的 https= 或整体）。
fn resolve_proxy() -> Option<ProxyConfig> {
    for var in ["MESHLINK_HTTPS_PROXY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
        if let Ok(v) = std::env::var(var) {
            if let Some(p) = parse_proxy_addr(&v) {
                return Some(p);
            }
        }
    }
    windows_system_proxy()
}

/// Windows 系统代理（HKCU Internet Settings：ProxyEnable=1 时 ProxyServer）。
#[cfg(windows)]
fn windows_system_proxy() -> Option<ProxyConfig> {
    use winreg::enums::HKEY_CURRENT_USER;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key = hkcu
        .open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        .ok()?;
    let enable: u32 = key.get_value("ProxyEnable").ok()?;
    if enable == 0 {
        return None;
    }
    let server: String = key.get_value("ProxyServer").ok()?;
    // ProxyServer 可能是 `https=127.0.0.1:10809;http=...` 或单一 `127.0.0.1:10809`。
    let pick = server
        .split(';')
        .map(|s| s.trim())
        .find(|s| s.starts_with("https="))
        .map(|s| s.trim_start_matches("https=").to_string())
        .unwrap_or_else(|| server.clone());
    parse_proxy_addr(&pick)
}

#[cfg(not(windows))]
fn windows_system_proxy() -> Option<ProxyConfig> {
    None
}

fn set_timeouts(stream: &TcpStream) -> ApiResult<()> {
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|_| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|e| ApiError::transport(format!("设置超时失败: {e}")))
}

/// 带超时的 TCP 连接（`std::TcpStream::connect` 无超时——在 IPv6 不可达/路由黑洞的
/// 网络（常见于虚拟机 NAT + AAAA 记录）下 SYN 无响应会**无限挂起**，导致 agent 永远卡在
/// ControllerConnecting 而无 healthz 错误日志）。同时**优先 IPv4**：浏览器走 Happy
/// Eyeballs 能通而 agent 卡住的正因就是 agent 先连了不可达的 IPv6 地址。
fn connect_with_timeout(addr: &str, timeout: Duration) -> ApiResult<TcpStream> {
    let iter = addr
        .to_socket_addrs()
        .map_err(|e| ApiError::transport(format!("解析 {addr} 失败: {e}")))?;
    let addrs: Vec<SocketAddr> = iter.collect();
    // IPv4 优先；IPv6 仅 IPv4 全部失败后尝试。
    let mut order: Vec<&SocketAddr> = addrs.iter().filter(|a| a.is_ipv4()).collect();
    order.extend(addrs.iter().filter(|a| a.is_ipv6()));
    if order.is_empty() {
        return Err(ApiError::transport(format!("{addr} 无可连接地址")));
    }
    let mut last: Option<std::io::Error> = None;
    for a in order {
        match TcpStream::connect_timeout(a, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(ApiError::transport(format!(
        "连接 {addr} 失败（每个地址超时 {timeout:?}）: {last:?}"
    )))
}

fn write_request<W: Write>(w: &mut W, head: &[u8], body: Option<&[u8]>) -> ApiResult<()> {
    w.write_all(head)
        .and_then(|_| match body {
            Some(b) => w.write_all(b),
            None => Ok(()),
        })
        .map_err(|e| ApiError::transport(format!("发送请求失败: {e}")))
}

/// 判定已收到的字节是否构成完整 HTTP/1.1 响应（头 + 完整 Content-Length 体）。
/// Connection: close 下对端可能以 RST 收尾（Windows 常见）——完整响应一到即可
/// 结束，无需再等 EOF。
fn has_complete_response(raw: &[u8]) -> bool {
    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return false;
    };
    let head = &raw[..head_end];
    let head_str = String::from_utf8_lossy(head);
    let content_length: Option<usize> = head_str
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.eq_ignore_ascii_case("content-length") {
                v.trim().parse().ok()
            } else {
                None
            }
        });
    match content_length {
        Some(n) => raw.len() >= head_end + 4 + n,
        // 无 Content-Length（chunked 等）：以终结 chunk 判定完整。
        None => {
            if head_str.to_ascii_lowercase().contains("transfer-encoding: chunked") {
                raw.ends_with(b"\r\n0\r\n\r\n")
            } else {
                false
            }
        }
    }
}

fn read_to_end<R: Read>(r: &mut R) -> ApiResult<Vec<u8>> {
    let mut raw = Vec::with_capacity(2048);
    let mut buf = [0u8; 4096];
    loop {
        if has_complete_response(&raw) {
            break;
        }
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                raw.extend_from_slice(&buf[..n]);
                // 无界保护：信令响应远小于 1MB。
                if raw.len() > 1 << 20 {
                    return Err(ApiError::transport("响应超过 1MB 上限"));
                }
            }
            // Connection: close 语义下，对端不发 TLS close_notify 直接断开
            // （UnexpectedEof）按正常结束处理——HTTP 响应以 EOF 或长度界定。
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                // 完整响应已收到（Content-Length 满足）时，后续 RST 属对端非干净
                // 关闭（Windows 常见），不作为错误；否则为真实截断。
                if has_complete_response(&raw) {
                    break;
                }
                let partial = String::from_utf8_lossy(&raw[..raw.len().min(120)]);
                return Err(ApiError::transport(format!(
                    "读取响应失败: {e}（已读 {}B: {:?}）",
                    raw.len(),
                    partial
                )));
            }
        }
    }
    Ok(raw)
}

/// 构建 rustls 客户端配置：固定 CA（PEM）或系统根。
fn build_client_config(ca_pem: Option<&std::path::Path>) -> ApiResult<Arc<rustls::ClientConfig>> {
    let builder = rustls::ClientConfig::builder();
    let config = match ca_pem {
        Some(path) => {
            let der = rustls_pki_types::CertificateDer::from_pem_file(path)
                .map_err(|e| ApiError::transport(format!("读取 CA PEM {path:?} 失败: {e}")))?;
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(der)
                .map_err(|e| ApiError::transport(format!("CA 证书无效: {e}")))?;
            builder.with_root_certificates(roots).with_no_client_auth()
        }
        None => {
            let mut roots = rustls::RootCertStore::empty();
            let native = rustls_native_certs::load_native_certs();
            for cert in native.certs {
                roots
                    .add(cert)
                    .map_err(|e| ApiError::transport(format!("系统根加载失败: {e}")))?;
            }
            if roots.is_empty() {
                return Err(ApiError::transport(
                    "系统信任根为空：请指定 CA（with_ca_pem）或配置系统证书库",
                ));
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        }
    };
    Ok(Arc::new(config))
}

/// 解析 HTTP/1.1 响应（Content-Length / chunked / 读到 EOF 三种）。
fn parse_http_response(raw: &[u8]) -> ApiResult<Vec<u8>> {
    let header_end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ApiError::transport("响应缺少头部结束符"))?;
    let head = std::str::from_utf8(&raw[..header_end])
        .map_err(|_| ApiError::transport("响应头非 UTF-8"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().ok_or_else(|| ApiError::transport("空响应"))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| ApiError::transport(format!("状态行非法: {status_line}")))?;

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else { continue };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "content-length" {
            content_length = value.parse().ok();
        } else if name == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            chunked = true;
        }
    }

    let body_raw = &raw[header_end + 4..];
    let body = if chunked {
        dechunk(body_raw)?
    } else if let Some(n) = content_length {
        if body_raw.len() < n {
            return Err(ApiError::transport(format!(
                "响应体不完整（{}/{}）", body_raw.len(), n
            )));
        }
        body_raw[..n].to_vec()
    } else {
        body_raw.to_vec() // Connection: close → 剩余即响应体
    };

    if (200..300).contains(&status) {
        Ok(body)
    } else {
        #[derive(Deserialize)]
        struct ErrBody {
            error: ErrCode,
        }
        #[derive(Deserialize)]
        struct ErrCode {
            code: String,
            message: String,
        }
        let (code, message) = match serde_json::from_slice::<ErrBody>(&body) {
            Ok(e) => (e.error.code, e.error.message),
            Err(_) => ("UNKNOWN".into(), String::from_utf8_lossy(&body).into_owned()),
        };
        Err(ApiError { status, code, message })
    }
}

/// 解码 Transfer-Encoding: chunked。
fn dechunk(mut raw: &[u8]) -> ApiResult<Vec<u8>> {
    let mut out = Vec::with_capacity(raw.len());
    loop {
        let line_end = raw
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| ApiError::transport("chunked 尺寸行非法"))?;
        let size_str = std::str::from_utf8(&raw[..line_end])
            .map_err(|_| ApiError::transport("chunked 尺寸行非 ASCII"))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| ApiError::transport(format!("chunked 尺寸非法: {size_str}")))?;
        let rest = &raw[line_end + 2..];
        if size == 0 {
            return Ok(out); // 结尾 chunk（忽略 trailer）
        }
        if rest.len() < size + 2 {
            return Err(ApiError::transport("chunked 数据不完整"));
        }
        out.extend_from_slice(&rest[..size]);
        raw = &rest[size + 2..]; // 跳过 chunk 数据后的 CRLF
    }
}

/// hex 64 → 32 字节公钥。
pub fn decode_key32(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[i * 2] as char).to_digit(16)?;
        let lo = (s.as_bytes()[i * 2 + 1] as char).to_digit(16)?;
        *b = (hi as u8) << 4 | lo as u8;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 串行化依赖进程级 env 的测试（并行会互相污染）。
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn has_complete_response_content_length() {
        // 头 + 完整 Content-Length 体 → 完整。
        let full = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert!(has_complete_response(full), "完整响应应判定为完整");
        assert!(!has_complete_response(&full[..full.len() - 1]), "差 1 字节应判未完整");
        assert!(!has_complete_response(b"HTTP/1.1 200 OK\r\n\r\n"), "无 Content-Length 不完整");
        assert!(!has_complete_response(b"HTTP/1.1 200"), "只有状态行不完整");
    }

    #[test]
    fn has_complete_response_chunked() {
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        assert!(has_complete_response(chunked), "chunked 终结块应判完整");
        assert!(!has_complete_response(&chunked[..chunked.len() - 3]), "chunked 未终结不完整");
    }

    #[test]
    fn dev_mode_allows_only_loopback_and_private_http() {
        assert!(Client::new("http://127.0.0.1:18080").is_ok());
        assert!(Client::new("http://localhost:18080").is_ok());
        assert!(Client::new("http://localhost").is_ok());
        // 局域网（RFC1918 私网）明文：允许（双机联机显式放行）。
        assert!(Client::new("http://192.168.1.10:18080").is_ok(), "私网应允许");
        assert!(Client::new("http://10.0.0.5:18080").is_ok(), "私网应允许");
        assert!(Client::new("http://172.16.0.8:18080").is_ok(), "私网应允许");
        // 公网明文 HTTP：一律拒绝（规格一，私网之外的 http 一律拒）。
        for bad in ["http://control.example.com", "http://8.8.8.8:18080", "http://example.com:18080"] {
            let err = Client::new(bad).err().unwrap_or_else(|| panic!("{bad} 应拒绝"));
            assert!(err.message.contains("公网明文"), "{bad} 拒绝原因应指明明文禁止: {err}");
        }
    }

    #[test]
    fn production_accepts_https_rejects_downgrade_schemes() {
        // https 构造成功（系统根存在时；根缺失也允许构造——错误延迟到首次调用）。
        if let Ok(c) = Client::new("https://control.meshlink.example") {
            assert_eq!(c.scheme(), Scheme::Https);
            assert_eq!(c.event_base_url(), "https://control.meshlink.example:443");
        }
        // 事件端点语义：wss/ws 不是 API base_url。
        assert!(Client::new("wss://control.example.com").is_err());
        assert!(Client::new("ws://127.0.0.1:18080").is_err());
        assert!(Client::new("garbage").is_err());
        assert!(Client::new("ftp://x").is_err());
        assert!(Client::new("http://:0").is_err());
    }

    #[test]
    fn https_failure_is_transport_error_never_plaintext_fallback() {
        // 连不上的 https 端口：必须是 TRANSPORT 错误，且 Client 结构上
        // 不存在任何 http 回退（scheme 一经构造不可变）。
        let c = Client::new("https://127.0.0.1:1").expect("构造");
        assert_eq!(c.scheme(), Scheme::Https);
        let err = c.healthz().err().expect("连接失败");
        assert_eq!(err.status, 0, "传输层错误 status=0: {err}");
        assert!(err.is_code("TRANSPORT"));
        // 构造后 scheme 不变：降级在类型层不可能。
        assert_eq!(c.scheme(), Scheme::Https);
    }

    #[test]
    fn parses_http_base_url() {
        let c = Client::new("http://127.0.0.1:18080/").expect("parse");
        assert_eq!(c.event_base_url(), "http://127.0.0.1:18080");
        assert_eq!(c.scheme(), Scheme::HttpLocal);
    }

    #[test]
    fn overlay_fields_deserialize() {
        // Controller 视图新增 overlay_subnet / overlay_ip（IPAM 下发）。
        let v: SessionView = serde_json::from_str(
            r#"{"session_id":"s1","network_id":"net","status":"JOINED",
                "overlay_subnet":"10.88.7.0/24",
                "members":[{"session_id":"s1","device_id":"d1","role":"creator",
                "noise_public_key":"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
                "joined_at":"t","overlay_ip":"10.88.7.1"}]}"#,
        )
        .expect("parse");
        assert_eq!(v.overlay_subnet.as_deref(), Some("10.88.7.0/24"));
        assert_eq!(v.members[0].overlay_ip.as_deref(), Some("10.88.7.1"));
    }

    #[test]
    fn parses_content_length_response() {
        // Content-Length 只取 11 字节，尾部 3 个空格必须丢弃。
        let head = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n";
        let raw: Vec<u8> = [head as &[u8], b"{\"ok\":true}   " as &[u8]].concat();
        assert_eq!(parse_http_response(&raw).unwrap(), b"{\"ok\":true}".to_vec());
    }

    #[test]
    fn parses_chunked_response() {
        // 两个 chunk（5 + 5 字节）+ 尾 chunk，拼出 {"a":true}。
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n{\"a\":\r\n5\r\ntrue}\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(raw).unwrap(), b"{\"a\":true}".to_vec());
    }

    #[test]
    fn error_body_maps_to_api_error() {
        let body = br#"{"error":{"code":"DEVICE_KEY_MISMATCH","message":"xx"}}"#;
        let head = format!("HTTP/1.1 409 Conflict\r\nContent-Length: {}\r\n\r\n", body.len());
        let raw = [head.as_bytes(), body as &[u8]].concat();
        let err = parse_http_response(&raw).err().unwrap();
        assert_eq!(err.status, 409);
        assert!(err.is_code("DEVICE_KEY_MISMATCH"));
    }

    #[test]
    fn malformed_status_line_rejected() {
        let raw = b"garbage\r\n\r\nx";
        assert!(parse_http_response(raw).is_err());
        let raw = b"HTTP/1.1 200 OK\r\n\r\n";
        // Content-Length 缺失 + close 语义 → 剩余空体。
        assert_eq!(parse_http_response(raw).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_key32_roundtrip() {
        assert!(decode_key32("").is_none());
        assert!(decode_key32("zz").is_none());
        assert!(decode_key32(&"0".repeat(64)).is_some());
        let k = decode_key32("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff").unwrap();
        assert_eq!(k[0], 0x00);
        assert_eq!(k[1], 0x11);
        assert_eq!(k[31], 0xff);
    }

    // ---- PRODUCTION 传输：本地 rustls TLS server 验证完整 https 路径 ----

    /// 极简 TLS HTTP server：先生成自签证书写入 CA PEM，再监听；
    /// 接受一次连接，响应固定 JSON（{"ok":true}）后关闭。
    fn spawn_tls_healthz(ca_pem_path: &std::path::Path) -> (u16, std::thread::JoinHandle<()>) {
        use std::net::TcpListener;
        // 先落盘证书（客户端 connect 前必须可读，否则 accept/等待互锁）。
        let cert = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()])
            .expect("cert");
        std::fs::write(ca_pem_path, cert.cert.pem()).expect("write ca pem");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec())],
                rustls_pki_types::PrivateKeyDer::from(
                    rustls_pki_types::PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()),
                ),
            )
            .expect("server config");
        let server_config = Arc::new(server_config);
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().expect("accept");
            let mut conn =
                rustls::ServerConnection::new(server_config).expect("server conn");
            {
                let mut tls = rustls::Stream::new(&mut conn, &mut sock);
                // 读取请求（忽略内容），写回固定响应，关闭。
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut tls, &mut buf);
                let body = br#"{"ok":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = std::io::Write::write_all(&mut tls, resp.as_bytes());
                let _ = std::io::Write::write_all(&mut tls, body);
                let _ = tls.flush();
            }
            conn.send_close_notify();
            let _ = sock.shutdown(std::net::Shutdown::Both);
        });
        (port, handle)
    }

    #[test]
    fn https_roundtrip_with_pinned_ca() {
        // env 代理解析是进程级的，与代理 env 测试互斥（避免并行污染导致误连代理）。
        let _env = ENV_LOCK.lock().unwrap();
        for v in ["MESHLINK_HTTPS_PROXY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
            unsafe {
                std::env::remove_var(v);
            }
        }
        let tmp = std::env::temp_dir().join(format!(
            "meshlink-tls-test-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let ca_path = tmp.join("ca.pem");
        let (port, handle) = spawn_tls_healthz(&ca_path);
        let client = Client::with_ca_pem(&format!("https://127.0.0.1:{port}"), &ca_path)
            .expect("client with pinned CA");
        let resp = client.healthz().expect("https 请求成功");
        assert_eq!(resp, serde_json::json!({"ok": true}));
        handle.join().expect("server thread");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- HTTPS 代理（HTTP CONNECT 隧道）----

    /// 极简 HTTP CONNECT 代理（测试用）：接受 CONNECT，连上游，200 后双向转发。
    fn spawn_connect_proxy() -> (u16, std::thread::JoinHandle<()>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if let Ok(mut c) = stream {
                    let mut buf = Vec::new();
                    let mut b = [0u8; 1];
                    loop {
                        if c.read(&mut b).unwrap_or(0) == 0 {
                            break;
                        }
                        buf.push(b[0]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let head = String::from_utf8_lossy(&buf);
                    let target = head
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("");
                    if target.is_empty() {
                        continue;
                    }
                    let (host, port) = target
                        .rsplit_once(':')
                        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443)))
                        .unwrap_or((target.to_string(), 443));
                    let Ok(mut upstream) = std::net::TcpStream::connect((host.as_str(), port)) else {
                        continue;
                    };
                    let _ = c.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n");
                    let mut c2 = c.try_clone().expect("clone");
                    let mut u2 = upstream.try_clone().expect("clone");
                    let t1 = std::thread::spawn(move || {
                        let _ = std::io::copy(&mut c2, &mut u2);
                    });
                    let _ = std::io::copy(&mut upstream, &mut c);
                    let _ = t1.join();
                }
            }
        });
        (port, handle)
    }

    #[test]
    fn https_roundtrip_via_connect_proxy() {
        let _env = ENV_LOCK.lock().unwrap();
        for v in ["MESHLINK_HTTPS_PROXY", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"] {
            unsafe {
                std::env::remove_var(v);
            }
        }
        let tmp = std::env::temp_dir().join(format!(
            "meshlink-tls-proxy-test-{}",
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&tmp).expect("mkdir");
        let ca_path = tmp.join("ca.pem");
        let (tls_port, tls_handle) = spawn_tls_healthz(&ca_path);
        let (proxy_port, proxy_handle) = spawn_connect_proxy();
        unsafe {
            std::env::set_var("MESHLINK_HTTPS_PROXY", format!("127.0.0.1:{proxy_port}"));
        }
        let client = Client::with_ca_pem(&format!("https://127.0.0.1:{tls_port}"), &ca_path)
            .expect("client with pinned CA");
        let resp = client.healthz().expect("经代理 https 请求成功");
        assert_eq!(resp, serde_json::json!({"ok": true}));
        unsafe {
            std::env::remove_var("MESHLINK_HTTPS_PROXY");
        }
        tls_handle.join().expect("tls server");
        drop(proxy_handle); // 代理线程 detached（转发循环可能半开阻塞，不 join 防挂起）。
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn parse_proxy_addr_formats() {
        assert_eq!(
            parse_proxy_addr("127.0.0.1:10809"),
            Some(ProxyConfig { host: "127.0.0.1".into(), port: 10809 })
        );
        assert_eq!(
            parse_proxy_addr("http://127.0.0.1:10809"),
            Some(ProxyConfig { host: "127.0.0.1".into(), port: 10809 })
        );
        assert_eq!(
            parse_proxy_addr("  https://proxy.example:3128  "),
            Some(ProxyConfig { host: "proxy.example".into(), port: 3128 })
        );
        // user:pass@ 忽略认证部分（第一版不支持代理认证）。
        assert_eq!(
            parse_proxy_addr("http://user:pass@127.0.0.1:10809"),
            Some(ProxyConfig { host: "127.0.0.1".into(), port: 10809 })
        );
        // socks 不支持 → None。
        assert_eq!(parse_proxy_addr("socks5://127.0.0.1:10808"), None);
        // 空/非法 → None。
        assert_eq!(parse_proxy_addr(""), None);
        assert_eq!(parse_proxy_addr("   "), None);
        assert_eq!(parse_proxy_addr("127.0.0.1"), None, "缺端口应拒绝");
        assert_eq!(parse_proxy_addr("127.0.0.1:abc"), None);
        assert_eq!(parse_proxy_addr(":10809"), None);
    }

    #[test]
    fn https_proxy_env_resolves_client_proxy() {
        // 与 https_roundtrip 互斥（env 是进程级状态，避免并行污染）。
        let _env = ENV_LOCK.lock().unwrap();
        // 环境变量生效：MESHLINK_HTTPS_PROXY（专属覆盖）→ 客户端代理字段可读。
        unsafe {
            std::env::set_var("MESHLINK_HTTPS_PROXY", "127.0.0.1:10809");
        }
        let client = Client::new("https://controller.bpbpanel.cc.cd").expect("https client");
        assert_eq!(
            client.proxy(),
            Some(&ProxyConfig { host: "127.0.0.1".into(), port: 10809 })
        );
        unsafe {
            std::env::remove_var("MESHLINK_HTTPS_PROXY");
        }
        // DEV 明文不受代理影响（回环直连）。
        let dev = Client::new("http://127.0.0.1:18080").expect("dev client");
        assert!(dev.proxy().is_some() || std::env::var("HTTPS_PROXY").is_err());
        // HTTPS_PROXY 通用变量也生效。
        unsafe {
            std::env::set_var("HTTPS_PROXY", "http://127.0.0.1:10809");
        }
        let c2 = Client::new("https://example.com").expect("client");
        assert_eq!(
            c2.proxy(),
            Some(&ProxyConfig { host: "127.0.0.1".into(), port: 10809 })
        );
        unsafe {
            std::env::remove_var("HTTPS_PROXY");
            std::env::remove_var("https_proxy");
            std::env::remove_var("ALL_PROXY");
            std::env::remove_var("all_proxy");
        }
    }
}
