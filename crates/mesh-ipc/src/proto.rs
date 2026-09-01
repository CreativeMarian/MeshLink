//! IPC 协议类型（用户规格四的 9 命令 / 10 事件，serde JSON Lines）。

use serde::{Deserialize, Serialize};

use crate::MAX_LINE_LEN;

/// UI → Agent 命令（M1-1：好友/设备/直连/Controller 配置）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "cmd")]
pub enum Command {
    /// 当前状态 + 会话信息。
    GetStatus,
    /// 创建 6 位码快速连接（creator 侧全流程后台执行）。
    CreateQuickSession,
    /// 凭 6 位码加入（joiner 侧全流程后台执行）。
    JoinQuickSession { code: String },
    /// 取消当前会话（回到 READY）。
    CancelSession,
    /// 断开指定 peer（overlay down + 传输断开）。
    DisconnectPeer { peer: String },
    /// 已连接 peer 列表。
    ListPeers,
    /// 创建好友邀请（永久 / 24h / 7d；0 = 不限次）。
    CreateFriendInvite { ttl: String, max_uses: i64 },
    /// 兑换好友邀请 → 建立 PENDING 好友关系。
    RedeemFriendInvite { invite_id: String, token: String },
    /// 高级诊断（Path/RTT/Loss/Overlay IP/Noise epoch 等）。
    GetDiagnostics,
    /// 好友列表（含在线状态与 PENDING 请求）。
    ListFriends,
    /// 我的设备列表。
    ListDevices,
    /// 我的邀请列表（含状态/使用情况）。
    ListInvites,
    /// 撤销邀请（旧 token 即刻失效）。
    RevokeInvite { invite_id: String },
    /// 接受好友请求 → ACCEPTED。
    AcceptFriendship { friendship_id: String },
    /// 拒绝/删除好友（撤销授权）。
    RejectFriendship { friendship_id: String },
    /// 向好友设备发起直连请求。
    ConnectFriend { device_id: String },
    /// 接受好友直连请求（target 侧）。
    AcceptConnectionRequest { session_id: String },
    /// 拒绝好友直连请求（target 侧）。
    RejectConnectionRequest { session_id: String },
    /// 设置 Controller 地址（校验后重连；生产强制 HTTPS）。
    SetControllerUrl { url: String },
    /// 当前 Controller 连接状态（地址/延迟/服务器）。
    GetControllerStatus,
    /// 发送心跳（在线保活；Agent 亦自动周期发送）。
    Heartbeat,
    /// M1-2：强制传输路径（"auto" | "directlink" | "n2n"）。
    SetPath { path: String },
    /// M1-2：N2N 运行状态（Supernode 池/熔断/当前路径）。
    GetN2NStatus,
    /// M1-1.5：最近连接历史（6 位码临时连接记录，与好友关系分离）。
    ListRecentConnections,
    /// M1-1.5：删除一条本地最近连接记录（不影响好友关系）。
    DeleteRecentConnection { remote_device_id: String },
    /// M1-1.5：优雅关闭（关闭当前会话 → 清理 runtime 临时文件 → 进程退出；
    /// MeshLink 退出时按序调用，正常退出后由 ProcessSupervisor 兜底清理）。
    Shutdown,
    /// M1-2：注册本机（MeshLink 监督者拉起的）DEV/自托管 Supernode 到
    /// Controller Registry（credential 由 Agent 持有，UI 不触碰密钥）。
    RegisterLocalSupernode { sn_id: String, host: String, port: u16, priority: u32 },
}

/// UI → Agent 请求信封。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// id 由调用方生成；`#[serde(default)]` 容忍老桥接/外部构造缺失 id
    /// （GUI 桥接 ipc_request 用 `build_request` 单独反序列化 Command 后补 id）。
    #[serde(default)]
    pub id: u64,
    #[serde(flatten)]
    pub command: Command,
}

/// Agent → UI 响应信封。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    pub id: u64,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

/// 响应错误（code 沿用 mesh-common / Controller 错误码字符串）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpcError {
    pub code: String,
    pub message: String,
}

impl IpcError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into() }
    }
}

/// Agent → UI 事件（用户规格四，共 10 个）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event")]
pub enum Event {
    /// Controller 就绪 + 身份注册完成。
    ControllerConnected { controller: String, device_id: String },
    /// creator：会话已创建，等待 joiner。
    WaitingForPeer { code: String, session_id: String, #[serde(default)] expires_at: Option<String> },
    /// 对端出现（creator 发现 joiner / joiner 从 join 响应得知 creator）。
    PeerFound { peer_device_id: String },
    /// 候选收集/上传中。
    GatheringCandidates { count: usize },
    /// UDP 打洞中。
    Punching { track: String },
    /// Noise IK 握手中（含双向公钥校验）。
    NoiseHandshaking { role: String },
    /// 全部成功（用户规格十二的 8 条件全部满足后才发）。
    /// `path` = 当前连接实际路径：`directlink` | `n2n`（M1-2 UI 展示 DirectLink / N2N Relay）。
    Connected {
        peer_device_id: String,
        local_overlay_ip: String,
        peer_overlay_ip: String,
        #[serde(default)]
        path: String,
    },
    /// 数据路径变化（后续 Path Manager 使用）。
    PathChanged { detail: String },
    /// 会话断开/取消。
    Disconnected { reason: String },
    /// 错误（code + message）。
    Error { code: String, message: String },
    /// 收到好友直连请求（target 侧；UI 弹窗 [接受][拒绝]）。
    IncomingConnectionRequest { session_id: String, from_device_id: String, from_name: String },
    /// 收到好友邀请（redeem 后 PENDING，等待接受）。
    FriendPending { friendship_id: String, peer_device_id: String, peer_name: String },
    /// 好友关系已建立（ACCEPTED）。
    FriendAccepted { friendship_id: String, peer_device_id: String, peer_name: String },
    /// 好友关系被撤销/拒绝（REMOVED）。
    FriendRemoved { friendship_id: String, peer_device_id: String },
    /// 好友设备上线（last_seen 进入在线窗口）。
    FriendOnline { device_id: String, device_name: String },
    /// 好友设备下线。
    FriendOffline { device_id: String },
    /// 我的设备上线。
    DeviceOnline { device_id: String },
    /// 我的设备下线。
    DeviceOffline { device_id: String },
    /// 好友直连成功（数据面 CONNECTED）。
    FriendConnected { device_id: String },
    /// 好友直连断开。
    FriendDisconnected { device_id: String },
    /// 好友/设备/邀请数据发生变化（UI 触发刷新）。
    FriendsChanged,
    /// M1-1.5：最近连接历史发生变化（UI 触发刷新）。
    RecentConnectionsChanged,
}

/// 服务端推给客户端的完整消息（响应或事件）。
#[derive(Debug, Clone, PartialEq)]
pub enum ServerMessage {
    Response(Response),
    Event(Event),
}

/// 一行序列化（JSON + `\n`）。调用方保证 msg 可序列化。
pub fn encode_line<T: Serialize>(msg: &T) -> Result<Vec<u8>, mesh_common::MeshError> {
    let mut line = serde_json::to_vec(msg).map_err(|e| {
        mesh_common::MeshError::new(
            mesh_common::ErrorCode::Internal,
            format!("IPC 序列化失败: {e}"),
        )
    })?;
    line.push(b'\n');
    Ok(line)
}

/// 从缓冲区切出完整行（返回 (完整行, 消费字节数)）；无完整行返回 None。
/// 超长行直接报错（防内存攻击）。
pub fn decode_line(
    buf: &[u8],
) -> Result<Option<(&[u8], usize)>, mesh_common::MeshError> {
    match buf.iter().position(|&b| b == b'\n') {
        Some(i) => {
            if i + 1 > MAX_LINE_LEN {
                return Err(mesh_common::MeshError::new(
                    mesh_common::ErrorCode::Internal,
                    "IPC 行超长",
                ));
            }
            Ok(Some((&buf[..i], i + 1)))
        }
        None => {
            if buf.len() > MAX_LINE_LEN {
                return Err(mesh_common::MeshError::new(
                    mesh_common::ErrorCode::Internal,
                    "IPC 行超长",
                ));
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 防默认值漂移：DEFAULT_CONTROLLER_URL 必须等于规范值
    /// （与 Go controller DefaultAddr=127.0.0.1:18080 对齐）。
    #[test]
    fn default_controller_url_is_canonical() {
        assert_eq!(crate::DEFAULT_CONTROLLER_URL, "http://127.0.0.1:18080");
    }

    #[test]
    fn command_wire_roundtrip() {
        let req = Request { id: 7, command: Command::JoinQuickSession { code: "482731".into() } };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""cmd":"JoinQuickSession""#), "tag 序列化: {json}");
        assert!(json.contains(r#""code":"482731""#), "flatten 字段: {json}");
        let back: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(back, req);

        let simple = Request { id: 1, command: Command::GetStatus };
        assert_eq!(
            serde_json::to_string(&simple).unwrap(),
            r#"{"id":1,"cmd":"GetStatus"}"#
        );
    }

    #[test]
    fn gui_bridge_wire_missing_id_tolerated() {
        // GUI 桥接 `build_request` 用 Command（内部标签 cmd）反序列化；
        // Request.id 需容忍缺省（防 M1-1 Release GUI undefined 回归）。
        let req: Request =
            serde_json::from_str(r#"{"cmd":"ListDevices"}"#).expect("缺失 id 应被容忍");
        assert_eq!(req.id, 0);
        assert_eq!(req.command, Command::ListDevices);

        let cmd: Command = serde_json::from_str(
            r#"{"cmd":"CreateFriendInvite","ttl":"7d","max_uses":0}"#,
        )
        .expect("bridge 的 Command wire 应可反序列化");
        assert_eq!(cmd, Command::CreateFriendInvite { ttl: "7d".into(), max_uses: 0 });
    }

    #[test]
    fn build_request_never_yields_zero_and_is_strictly_increasing() {
        use std::sync::atomic::AtomicU64;

        // 正常初始化（1）：id = 1,2,3...
        let next = AtomicU64::new(1);
        for expect in [1u64, 2, 3, 4] {
            let req = crate::build_request(&next, "GetStatus", None).expect("构造");
            assert_eq!(req.id, expect, "正常初始化应严格递增");
            assert_ne!(req.id, 0, "id 永不为 0");
        }

        // 边角：误初始化为 0 —— 首个请求仍必须返回非零 id，且后续严格递增无碰撞。
        let next0 = AtomicU64::new(0);
        let ids: Vec<u64> = (0..4)
            .map(|_| crate::build_request(&next0, "ListDevices", None).expect("构造").id)
            .collect();
        assert!(ids.iter().all(|&i| i != 0), "误初始化 0 也不能产出 id=0: {ids:?}");
        assert_eq!(ids, vec![1, 2, 3, 4], "跳过 id=0 后仍严格递增: {ids:?}");
    }

    #[test]
    fn all_commands_roundtrip() {
        let cmds = vec![
            Command::GetStatus,
            Command::CreateQuickSession,
            Command::JoinQuickSession { code: "000000".into() },
            Command::CancelSession,
            Command::DisconnectPeer { peer: "dev-abc".into() },
            Command::ListPeers,
            Command::CreateFriendInvite { ttl: "24h".into(), max_uses: 3 },
            Command::RedeemFriendInvite { invite_id: "inv-1".into(), token: "mli_x".into() },
            Command::GetDiagnostics,
            Command::ListFriends,
            Command::ListDevices,
            Command::ListInvites,
            Command::RevokeInvite { invite_id: "inv-1".into() },
            Command::AcceptFriendship { friendship_id: "fr-1".into() },
            Command::RejectFriendship { friendship_id: "fr-1".into() },
            Command::ConnectFriend { device_id: "dev-b".into() },
            Command::AcceptConnectionRequest { session_id: "s1".into() },
            Command::RejectConnectionRequest { session_id: "s1".into() },
            Command::SetControllerUrl { url: "https://control.example.com".into() },
            Command::GetControllerStatus,
            Command::Heartbeat,
            Command::ListRecentConnections,
            Command::DeleteRecentConnection { remote_device_id: "dev-b".into() },
            Command::Shutdown,
            Command::RegisterLocalSupernode { sn_id: "sn-local".into(), host: "127.0.0.1".into(), port: 7654, priority: 100 },
        ];
        for (i, c) in cmds.into_iter().enumerate() {
            let req = Request { id: i as u64, command: c };
            let s = serde_json::to_string(&req).unwrap();
            let back: Request = serde_json::from_str(&s).unwrap();
            assert_eq!(back.id, i as u64);
        }
    }

    #[test]
    fn all_events_roundtrip() {
        let events = vec![
            Event::ControllerConnected { controller: crate::DEFAULT_CONTROLLER_URL.into(), device_id: "dev-a".into() },
            Event::WaitingForPeer { code: "482731".into(), session_id: "s1".into(), expires_at: Some("t".into()) },
            Event::PeerFound { peer_device_id: "dev-b".into() },
            Event::GatheringCandidates { count: 2 },
            Event::Punching { track: "B".into() },
            Event::NoiseHandshaking { role: "initiator".into() },
            Event::Connected {
                peer_device_id: "dev-b".into(),
                local_overlay_ip: "10.88.7.1".into(),
                peer_overlay_ip: "10.88.7.2".into(),
                path: "directlink".into(),
            },
            Event::PathChanged { detail: "direct".into() },
            Event::Disconnected { reason: "cancelled".into() },
            Event::Error { code: "PUNCH_FAILED".into(), message: "x".into() },
            Event::IncomingConnectionRequest {
                session_id: "s1".into(),
                from_device_id: "dev-a".into(),
                from_name: "Alice".into(),
            },
            Event::FriendPending { friendship_id: "fr-1".into(), peer_device_id: "dev-b".into(), peer_name: "Bob".into() },
            Event::FriendAccepted { friendship_id: "fr-1".into(), peer_device_id: "dev-b".into(), peer_name: "Bob".into() },
            Event::FriendRemoved { friendship_id: "fr-1".into(), peer_device_id: "dev-b".into() },
            Event::FriendOnline { device_id: "dev-b".into(), device_name: "Bob".into() },
            Event::FriendOffline { device_id: "dev-b".into() },
            Event::DeviceOnline { device_id: "dev-b".into() },
            Event::DeviceOffline { device_id: "dev-b".into() },
            Event::FriendConnected { device_id: "dev-b".into() },
            Event::FriendDisconnected { device_id: "dev-b".into() },
            Event::FriendsChanged,
            Event::RecentConnectionsChanged,
        ];
        for e in events {
            let s = serde_json::to_string(&e).unwrap();
            let back: Event = serde_json::from_str(&s).unwrap();
            assert_eq!(back, e);
        }
    }

    #[test]
    fn response_error_wire() {
        let r = Response { id: 3, ok: false, data: None, error: Some(IpcError::new("SESSION_NOT_FOUND", "会话不存在")) };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains(r#""ok":false"#));
        assert!(s.contains("SESSION_NOT_FOUND"));
        let back: Response = serde_json::from_str(&s).unwrap();
        assert_eq!(back.error.unwrap().code, "SESSION_NOT_FOUND");
    }

    #[test]
    fn line_framing() {
        let buf = b"{\"a\":1}\n{\"b\":2}\npartial";
        let (line, used) = decode_line(buf).unwrap().unwrap();
        assert_eq!(line, b"{\"a\":1}".as_slice());
        assert_eq!(used, 8);
        let rest = &buf[used..];
        let (line2, used2) = decode_line(rest).unwrap().unwrap();
        assert_eq!(line2, b"{\"b\":2}".as_slice());
        assert_eq!(used2, 8);
        assert!(decode_line(&rest[used2..]).unwrap().is_none(), "无完整行");
    }

    #[test]
    fn overlong_line_rejected() {
        let mut long = vec![b'x'; MAX_LINE_LEN + 10];
        long.push(b'\n');
        assert!(decode_line(&long).is_err());
    }
}
