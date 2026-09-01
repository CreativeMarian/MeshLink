//! 系统事件（文档 17.2）。事件序列化格式与 schemas/api/v1/events.schema.json 保持一致。

use serde::Serialize;

/// 结构化系统事件。所有路径切换/熔断/进程崩溃必须产生事件（文档 25.2）。
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SystemEvent {
    DeviceOnline { device_id: String },
    DeviceOffline { device_id: String },
    P2pConnected { peer_id: String, path_kind: String },
    P2pFailed { peer_id: String, code: u32 },
    /// 路径切换：必须记录 from/to/reason/score（文档 9.5）
    PathSwitched {
        peer_id: String,
        from_path: String,
        to_path: String,
        reason: String,
        score: Option<u8>,
    },
    /// 熔断器状态变更：每次状态迁移必须产生一条，状态未变不得重复产生。
    /// reason ∈ failure_threshold_reached / fatal_failure / cooldown_expired /
    ///   half_open_probe_succeeded / half_open_probe_failed / manual_reset / manual_open
    CircuitStateChanged {
        breaker_id: String,
        scope: String,
        previous_state: String,
        new_state: String,
        reason: String,
        consecutive_failures: u32,
        /// 单调时钟毫秒（禁止墙上时间，防止用户改系统时间干扰状态机）
        ts_monotonic_ms: u64,
    },
    N2nProcessCrash { pid: Option<u32> },
    N2nProcessRestarted { pid: Option<u32>, attempt: u32 },
    SupernodeDegraded { sn_id: String },
    SupernodeOffline { sn_id: String },
    SupernodeRecovered { sn_id: String },
    InviteUsed { invite_id: String },
    InviteRevoked { invite_id: String },
    /// 密码认证失败：只允许记录来源摘要，禁止记录来源明文与密码
    PasswordAuthFailed { source_summary: String },
    CloudflareTunnelDown { hostname: String },
    CloudflareTunnelRecovered { hostname: String },
}

impl SystemEvent {
    /// 事件名（与 serde tag 一致），用于日志与 IPC 通道。
    pub fn name(&self) -> &'static str {
        match self {
            Self::DeviceOnline { .. } => "DEVICE_ONLINE",
            Self::DeviceOffline { .. } => "DEVICE_OFFLINE",
            Self::P2pConnected { .. } => "P2P_CONNECTED",
            Self::P2pFailed { .. } => "P2P_FAILED",
            Self::PathSwitched { .. } => "PATH_SWITCHED",
            Self::CircuitStateChanged { .. } => "CIRCUIT_STATE_CHANGED",
            Self::N2nProcessCrash { .. } => "N2N_PROCESS_CRASH",
            Self::N2nProcessRestarted { .. } => "N2N_PROCESS_RESTARTED",
            Self::SupernodeDegraded { .. } => "SUPERNODE_DEGRADED",
            Self::SupernodeOffline { .. } => "SUPERNODE_OFFLINE",
            Self::SupernodeRecovered { .. } => "SUPERNODE_RECOVERED",
            Self::InviteUsed { .. } => "INVITE_USED",
            Self::InviteRevoked { .. } => "INVITE_REVOKED",
            Self::PasswordAuthFailed { .. } => "PASSWORD_AUTH_FAILED",
            Self::CloudflareTunnelDown { .. } => "CLOUDFLARE_TUNNEL_DOWN",
            Self::CloudflareTunnelRecovered { .. } => "CLOUDFLARE_TUNNEL_RECOVERED",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_switched_json_has_required_fields() {
        let ev = SystemEvent::PathSwitched {
            peer_id: "dev_1".into(),
            from_path: "n2n_relay:sn_hk_01".into(),
            to_path: "directlink".into(),
            reason: "failback".into(),
            score: Some(92),
        };
        let json = serde_json::to_string(&ev).unwrap();
        for key in ["PATH_SWITCHED", "from_path", "to_path", "reason", "score"] {
            assert!(json.contains(key), "缺少字段 {key}: {json}");
        }
    }

    #[test]
    fn password_auth_failure_never_contains_raw_source() {
        // 约定层面示例：构造时只传摘要
        let ev = SystemEvent::PasswordAuthFailed { source_summary: "a1b2c3d4".into() };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("a1b2c3d4"));
        assert_eq!(ev.name(), "PASSWORD_AUTH_FAILED");
    }
}
