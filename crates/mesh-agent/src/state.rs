//! Agent 状态机（用户规格九：14 个统一状态，UI 不自行推断）。

use serde::{Deserialize, Serialize};

/// 统一状态（wire 形态 = SCREAMING_SNAKE，与事件流对齐）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentState {
    Stopped,
    Starting,
    ControllerConnecting,
    Ready,
    SessionCreating,
    WaitingForPeer,
    PeerDiscovered,
    Gathering,
    Punching,
    NoiseHandshake,
    ConfiguringOverlay,
    Connected,
    Reconnecting,
    Failed,
}

impl AgentState {
    /// wire 形态字符串（与 `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]` 一致）。
    pub fn wire(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_default()
            .trim_matches('"')
            .to_string()
    }

    /// 用户化文案（规格十一：普通 UI 不显示 STUN/srflx/epoch 等术语）。
    pub fn user_facing(&self) -> &'static str {
        match self {
            Self::Stopped => "已停止",
            Self::Starting => "正在启动...",
            Self::ControllerConnecting => "正在连接服务...",
            Self::Ready => "已就绪",
            Self::SessionCreating => "正在创建连接...",
            Self::WaitingForPeer => "等待好友加入...",
            Self::PeerDiscovered => "已找到对方设备",
            Self::Gathering => "正在准备连接...",
            Self::Punching => "正在建立直连...",
            Self::NoiseHandshake => "正在建立安全连接...",
            Self::ConfiguringOverlay => "正在配置虚拟网络...",
            Self::Connected => "已连接",
            Self::Reconnecting => "正在重新连接...",
            Self::Failed => "连接失败",
        }
    }
}

/// 单个已连接/连接中的 peer 视图（ListPeers / 状态快照）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerView {
    pub device_id: String,
    pub connected: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_overlay_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_overlay_ip: Option<String>,
}

/// 当前会话快照（GetStatus data.session）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SessionSnapshot {
    pub session_id: String,
    /// creator | joiner
    pub role: String,
    /// 6 位码（仅创建者可见）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    pub network_id: String,
    /// Controller IPAM 分配的独占网段（如 10.88.7.0/24）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overlay_subnet: Option<String>,
    pub peers: Vec<PeerView>,
}

/// Agent 全局状态快照（GetStatus data）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StatusSnapshot {
    pub state: AgentState,
    pub user_facing: String,
    pub device_id: String,
    pub controller: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SessionSnapshot>,
    /// 顶层活动会话（UI 刷新 / 页面切换后可恢复 6 位码——用户规格四）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_session: Option<ActiveSession>,
}

/// 顶层活动会话（GetStatus data.active_session）。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActiveSession {
    pub session_id: String,
    /// 6 位码（仅创建者可见；固定宽度 string，保留前导零）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// 机器状态（SCREAMING_SNAKE，如 WAITING_FOR_PEER / CONNECTED）。
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

impl StatusSnapshot {
    pub fn new(state: AgentState, device_id: impl Into<String>, controller: impl Into<String>) -> Self {
        Self {
            user_facing: state.user_facing().into(),
            state,
            device_id: device_id.into(),
            controller: controller.into(),
            session: None,
            active_session: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_wire_is_screaming_snake() {
        assert_eq!(serde_json::to_string(&AgentState::ControllerConnecting).unwrap(), r#""CONTROLLER_CONNECTING""#);
        assert_eq!(serde_json::to_string(&AgentState::NoiseHandshake).unwrap(), r#""NOISE_HANDSHAKE""#);
        let back: AgentState = serde_json::from_str(r#""CONFIGURING_OVERLAY""#).unwrap();
        assert_eq!(back, AgentState::ConfiguringOverlay);
    }

    #[test]
    fn all_fourteen_states_covered_by_user_facing_copy() {
        let all = [
            AgentState::Stopped, AgentState::Starting, AgentState::ControllerConnecting,
            AgentState::Ready, AgentState::SessionCreating, AgentState::WaitingForPeer,
            AgentState::PeerDiscovered, AgentState::Gathering, AgentState::Punching,
            AgentState::NoiseHandshake, AgentState::ConfiguringOverlay, AgentState::Connected,
            AgentState::Reconnecting, AgentState::Failed,
        ];
        assert_eq!(all.len(), 14, "规格九：14 个统一状态");
        for s in &all {
            assert!(!s.user_facing().is_empty());
            assert!(!s.user_facing().contains("STUN"), "用户化文案不得泄漏术语（规格十一）");
        }
    }

    #[test]
    fn snapshot_roundtrip() {
        let snap = StatusSnapshot {
            state: AgentState::Connected,
            user_facing: "已连接".into(),
            device_id: "dev-a".into(),
            controller: mesh_ipc::DEFAULT_CONTROLLER_URL.into(),
            session: Some(SessionSnapshot {
                session_id: "s1".into(),
                role: "creator".into(),
                code: Some("482731".into()),
                expires_at: Some("t".into()),
                network_id: "meshlink".into(),
                overlay_subnet: Some("10.88.7.0/24".into()),
                peers: vec![PeerView {
                    device_id: "dev-b".into(),
                    connected: true,
                    local_overlay_ip: Some("10.88.7.1".into()),
                    peer_overlay_ip: Some("10.88.7.2".into()),
                }],
            }),
            active_session: None,
        };
        let s = serde_json::to_string(&snap).unwrap();
        assert!(s.contains(r#""state":"CONNECTED""#));
        let back: StatusSnapshot = serde_json::from_str(&s).unwrap();
        assert_eq!(back, snap);
    }
}
