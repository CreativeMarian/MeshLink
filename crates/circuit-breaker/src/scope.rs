//! 熔断对象 Scope 与 Key（M0-2 修正六/七）。
//!
//! 状态机只识别 [`BreakerKey`]，对 scope 种类零知识——
//! 未来新增 QUIC Relay / TURN Relay 等只需新增 [`BreakerScope`] 变体，
//! 熔断状态机与 Manager 逻辑零改动。

use std::fmt;

/// 熔断对象种类（确认版 §2.3 四类，可扩展）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum BreakerScope {
    /// 每 Peer 独立：DirectLink P2P 会话
    DirectLinkPeer { peer_id: String },
    /// N2N 引擎整体（edge 进程/内部异常）
    N2NProvider,
    /// 每个 Supernode 独立：SN-HK-01 OPEN 不影响其他 SN
    N2NSupernode { sn_id: String },
    /// WSS Relay；多 Relay 部署时按 relay_id 区分
    CloudflareRelay { relay_id: String },
}

impl BreakerScope {
    /// 单 Relay 部署的默认 scope。
    pub fn cloudflare_default() -> Self {
        Self::CloudflareRelay { relay_id: "default".to_string() }
    }

    /// scope 种类名（事件字段用）。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::DirectLinkPeer { .. } => "directlink_peer",
            Self::N2NProvider => "n2n_provider",
            Self::N2NSupernode { .. } => "n2n_supernode",
            Self::CloudflareRelay { .. } => "cloudflare_relay",
        }
    }
}

/// 全局唯一 key（Manager 的 HashMap 键）。
/// 格式：`<domain>.<object>:<id>`，与 schemas/身份体系命名保持一致。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BreakerKey(pub String);

impl BreakerKey {
    pub fn of(scope: &BreakerScope) -> Self {
        match scope {
            BreakerScope::DirectLinkPeer { peer_id } => {
                Self(format!("directlink.peer:{peer_id}"))
            }
            BreakerScope::N2NProvider => Self("n2n.provider".to_string()),
            BreakerScope::N2NSupernode { sn_id } => Self(format!("n2n.supernode:{sn_id}")),
            BreakerScope::CloudflareRelay { relay_id } => {
                Self(format!("cloudflare.relay:{relay_id}"))
            }
        }
    }
}

impl fmt::Display for BreakerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_unique_per_scope_instance() {
        let a = BreakerKey::of(&BreakerScope::N2NSupernode { sn_id: "sn_hk_01".into() });
        let b = BreakerKey::of(&BreakerScope::N2NSupernode { sn_id: "sn_hk_02".into() });
        let c = BreakerKey::of(&BreakerScope::N2NProvider);
        let d = BreakerKey::of(&BreakerScope::DirectLinkPeer { peer_id: "dev_a".into() });
        let e = BreakerKey::of(&BreakerScope::cloudflare_default());
        let all = [a.clone(), b, c, d, e.clone()];
        let mut seen = std::collections::HashSet::new();
        for k in &all {
            assert!(seen.insert(k.clone()), "key 冲突: {k}");
        }
        assert_eq!(a.0, "n2n.supernode:sn_hk_01");
        assert_eq!(e.0, "cloudflare.relay:default");
    }
}
