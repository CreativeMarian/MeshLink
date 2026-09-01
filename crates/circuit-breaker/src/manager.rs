//! 熔断器管理器（M0-2 修正六/七）。
//!
//! 以 `HashMap<BreakerKey, CircuitBreaker>` 持有全部熔断器实例，
//! 从数据结构上保证实例间完全隔离：每个 breaker 独立持有
//! state / failure_count / probe_count / cooldown。
//!
//! Manager 对 scope 种类零知识（不做 `if n2n / if cloudflare` 分派），
//! 新增 scope 变体（QUIC Relay / TURN Relay…）无需改动本文件。

use crate::breaker::{BreakerState, BreakerStatus, CircuitBreaker, Decision};
use crate::clock::Clock;
use crate::params::BreakerParams;
use crate::scope::{BreakerKey, BreakerScope};
use config_manager::RuntimeParams;
use mesh_common::SystemEvent;
use std::collections::HashMap;

/// 熔断器管理器：一个 meshlink 客户端进程内所有熔断器的唯一持有者。
#[derive(Debug)]
pub struct CircuitBreakerManager {
    /// 参数唯一来源（修正十一）：新 breaker 创建时从 RuntimeParams 派生参数。
    runtime: RuntimeParams,
    breakers: HashMap<BreakerKey, CircuitBreaker>,
}

impl CircuitBreakerManager {
    pub fn new(runtime: RuntimeParams) -> Self {
        Self { runtime, breakers: HashMap::new() }
    }

    /// 取得（或按统一配置创建）指定 scope 的熔断器。
    /// 同一 scope 永远返回同一实例——这是隔离性与计数连续性的保证。
    pub fn get_or_create(&mut self, scope: &BreakerScope) -> &mut CircuitBreaker {
        let key = BreakerKey::of(scope);
        if !self.breakers.contains_key(&key) {
            let params = BreakerParams::from(&self.runtime);
            self.breakers
                .insert(key.clone(), CircuitBreaker::new(scope.clone(), params));
        }
        self.breakers.get_mut(&key).expect("entry 刚插入必然存在")
    }

    pub fn contains(&self, scope: &BreakerScope) -> bool {
        self.breakers.contains_key(&BreakerKey::of(scope))
    }

    pub fn len(&self) -> usize {
        self.breakers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.breakers.is_empty()
    }

    /// 全部熔断器只读快照（按 key 排序，供监控页稳定展示）。
    pub fn statuses(&self, clock: &dyn Clock) -> Vec<BreakerStatus> {
        let mut all: Vec<BreakerStatus> =
            self.breakers.values().map(|b| b.status(clock)).collect();
        all.sort_by(|a, b| a.key.cmp(&b.key));
        all
    }

    // ---------- 事件转发（全部按 scope 定位实例） ----------

    /// 业务报文准入。
    pub fn allow_request(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Decision {
        self.get_or_create(scope).allow_request(clock)
    }

    pub fn record_success(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).record_success(clock)
    }

    pub fn record_failure(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).record_failure(clock)
    }

    pub fn record_fatal(
        &mut self,
        scope: &BreakerScope,
        clock: &dyn Clock,
        detail: impl Into<String>,
    ) -> Option<SystemEvent> {
        self.get_or_create(scope).record_fatal(clock, detail)
    }

    /// 申请探测名额。
    pub fn begin_probe(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> bool {
        self.get_or_create(scope).begin_probe(clock)
    }

    pub fn probe_success(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).probe_success(clock)
    }

    pub fn probe_failure(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).probe_failure(clock)
    }

    /// 时间推进钩子（周期任务调用；allow_request 内部也会先 evaluate）。
    pub fn evaluate(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).evaluate(clock)
    }

    // ---------- 手动 Override（修正九） ----------

    pub fn force_open(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).force_open(clock)
    }

    pub fn force_close(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).force_close(clock)
    }

    pub fn reset(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> Option<SystemEvent> {
        self.get_or_create(scope).reset(clock)
    }

    /// 当前状态（含先 evaluate，保证冷却到期即时反映）。
    pub fn state(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> BreakerState {
        let b = self.get_or_create(scope);
        b.evaluate(clock);
        b.state()
    }

    /// 单个熔断器只读快照（含先 evaluate，保证冷却到期即时反映）。
    pub fn status(&mut self, scope: &BreakerScope, clock: &dyn Clock) -> BreakerStatus {
        let b = self.get_or_create(scope);
        b.evaluate(clock);
        b.status(clock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::breaker::RejectReason;
    use crate::clock::FakeClock;

    fn manager() -> CircuitBreakerManager {
        CircuitBreakerManager::new(RuntimeParams::default())
    }

    fn sn(id: &str) -> BreakerScope {
        BreakerScope::N2NSupernode { sn_id: id.to_string() }
    }

    // 修正七：两个 SN breaker 状态完全隔离
    #[test]
    fn t19_supernode_breakers_fully_isolated() {
        let mut m = manager();
        let clock = FakeClock::new(0);

        // sn_hk_01 连续失败 3 次 → OPEN
        m.record_failure(&sn("hk01"), &clock);
        m.record_failure(&sn("hk01"), &clock);
        m.record_failure(&sn("hk01"), &clock);
        assert_eq!(m.state(&sn("hk01"), &clock), BreakerState::Open);

        // sn_hk_02 / sg01 完全不受影响：无失败、CLOSED、放行业务
        assert_eq!(m.state(&sn("hk02"), &clock), BreakerState::Closed);
        assert_eq!(m.state(&sn("sg01"), &clock), BreakerState::Closed);
        assert_eq!(
            m.allow_request(&sn("hk02"), &clock),
            Decision::Allowed,
            "hk01 OPEN 不得影响 hk02"
        );

        // 计数独立：hk02 记一次失败后 success 清零，hk01 仍 OPEN
        m.record_failure(&sn("hk02"), &clock);
        m.record_success(&sn("hk02"), &clock);
        let st = m.statuses(&clock);
        let hk01 = st.iter().find(|s| s.key == "n2n.supernode:hk01").unwrap();
        let hk02 = st.iter().find(|s| s.key == "n2n.supernode:hk02").unwrap();
        assert_eq!(hk01.state, BreakerState::Open);
        assert_eq!(hk02.state, BreakerState::Closed);
        assert_eq!(hk02.consecutive_failures, 0);
    }

    // 修正七：N2N Provider OPEN 不修改任何 SN breaker 内部状态（反向亦然）
    #[test]
    fn t20_provider_open_does_not_touch_supernode() {
        let mut m = manager();
        let clock = FakeClock::new(0);

        m.record_fatal(&BreakerScope::N2NProvider, &clock, "edge crashed");
        assert_eq!(m.state(&BreakerScope::N2NProvider, &clock), BreakerState::Open);

        // SN 未被传染：状态与计数都干净
        let sn_st = m.status(&sn("hk01"), &clock);
        assert_eq!(sn_st.state, BreakerState::Closed);
        assert_eq!(sn_st.consecutive_failures, 0);

        // SN 自身熔断也不影响 provider 之外的 peer
        m.record_fatal(&sn("hk01"), &clock, "sn unreachable");
        assert_eq!(m.state(&sn("hk01"), &clock), BreakerState::Open);
        let peer = BreakerScope::DirectLinkPeer { peer_id: "dev_a".into() };
        assert_eq!(m.state(&peer, &clock), BreakerState::Closed);
    }

    // 修正七：DirectLink Peer A OPEN 不影响 Peer B
    #[test]
    fn t21_peer_a_open_does_not_affect_peer_b() {
        let mut m = manager();
        let clock = FakeClock::new(0);

        let a = BreakerScope::DirectLinkPeer { peer_id: "dev_a".into() };
        let b = BreakerScope::DirectLinkPeer { peer_id: "dev_b".into() };

        m.record_fatal(&a, &clock, "hole punch exhausted");
        assert_eq!(m.allow_request(&a, &clock), Decision::Rejected(RejectReason::CircuitOpen));
        assert_eq!(m.allow_request(&b, &clock), Decision::Allowed);
        assert_eq!(m.len(), 2, "peer A/B 必须是两个独立 breaker 实例");
    }

    // get_or_create 幂等：同 scope 返回同一实例（计数连续）
    #[test]
    fn manager_same_scope_returns_same_instance() {
        let mut m = manager();
        let clock = FakeClock::new(0);
        let scope = sn("hk01");
        m.record_failure(&scope, &clock);
        m.record_failure(&scope, &clock);
        // 若不是同一实例，这里不会累积到 3 次触发 OPEN
        let ev = m.record_failure(&scope, &clock);
        assert!(ev.is_some(), "第三次失败应触发 OPEN 事件");
        assert_eq!(m.state(&scope, &clock), BreakerState::Open);
        assert_eq!(m.len(), 1);
    }

    // statuses 按 key 稳定排序（监控页依赖）
    #[test]
    fn manager_statuses_sorted_by_key() {
        let mut m = manager();
        let clock = FakeClock::new(0);
        m.record_success(&sn("sg01"), &clock);
        m.record_success(&BreakerScope::N2NProvider, &clock);
        m.record_success(&sn("hk01"), &clock);
        let keys: Vec<String> = m.statuses(&clock).into_iter().map(|s| s.key).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(keys.len(), 3);
    }
}
