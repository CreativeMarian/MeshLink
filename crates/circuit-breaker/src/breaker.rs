//! 三态熔断器状态机（纯逻辑，M0-2）。
//!
//! 纯度保证：本模块不依赖任何网络/进程/IO——只接收调用方注入的事件
//! （record_success / record_failure / record_fatal / probe_* ）并返回状态迁移事件。
//! 时间一律通过 [`Clock`] 注入（单调时钟 / FakeClock）。
//!
//! 状态机（文档 9.3 + M0-2 修正三/四/五）：
//!
//! ```text
//! CLOSED --连续失败>=threshold(Quality)--> OPEN --冷却到期--> HALF_OPEN --连续N次探测成功--> CLOSED
//! CLOSED/HALF_OPEN --record_fatal(Hard Failure, 无视阈值)--> OPEN
//! HALF_OPEN --任意一次探测失败--> OPEN（重新开始冷却）
//! HALF_OPEN 业务流量一律拒绝（探测专用窗口），并发探测数受 max_half_open_probes 限流
//! ```
//!
//! Hard Failure（record_fatal）与 Quality Degradation（连续失败计数）是两条独立触发线。

use crate::clock::Clock;
use crate::params::BreakerParams;
use crate::scope::{BreakerKey, BreakerScope};
use mesh_common::SystemEvent;

/// 熔断器状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::Open => "open",
            Self::HalfOpen => "half_open",
        }
    }
}

/// 状态迁移原因（M0-2 修正八：监控页必须能回答"为什么熔断/何时恢复"）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionReason {
    /// Quality Failure：连续失败达到阈值
    FailureThresholdReached,
    /// Hard Failure：无视阈值立即 OPEN
    FatalFailure,
    /// 冷却到期，OPEN → HALF_OPEN
    CooldownExpired,
    /// HALF_OPEN 连续探测成功达标，→ CLOSED
    HalfOpenProbeSucceeded,
    /// HALF_OPEN 探测失败，→ OPEN（重新冷却）
    HalfOpenProbeFailed,
    /// 手动复位/关闭
    ManualReset,
    /// 手动熔断（摘除节点/故障注入）
    ManualOpen,
}

impl TransitionReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FailureThresholdReached => "failure_threshold_reached",
            Self::FatalFailure => "fatal_failure",
            Self::CooldownExpired => "cooldown_expired",
            Self::HalfOpenProbeSucceeded => "half_open_probe_succeeded",
            Self::HalfOpenProbeFailed => "half_open_probe_failed",
            Self::ManualReset => "manual_reset",
            Self::ManualOpen => "manual_open",
        }
    }
}

/// 业务流量准入决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allowed,
    Rejected(RejectReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// 熔断中
    CircuitOpen,
    /// HALF_OPEN 窗口保留给探测，业务流量拒绝
    HalfOpenProbeOnly,
}

/// 熔断时的失败快照（诊断用）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureSnapshot {
    pub consecutive_failures: u32,
    pub detail: Option<String>,
    pub opened_at_ms: u64,
}

#[derive(Debug)]
struct OpenInfo {
    cooldown_until_ms: u64,
    reason: TransitionReason,
    snapshot: FailureSnapshot,
}

/// 对外只读状态快照（监控/诊断）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakerStatus {
    pub key: String,
    pub scope_kind: &'static str,
    pub state: BreakerState,
    pub consecutive_failures: u32,
    pub half_open_success_count: u32,
    pub probes_in_flight: u32,
    pub open_count: u64,
    pub open_reason: Option<&'static str>,
    /// OPEN 时剩余冷却毫秒；非 OPEN 为 0
    pub cooldown_remaining_ms: u64,
}

/// 三态熔断器。
#[derive(Debug)]
pub struct CircuitBreaker {
    key: BreakerKey,
    scope: BreakerScope,
    params: BreakerParams,
    state: BreakerState,
    consecutive_failures: u32,
    half_open_success_count: u32,
    probes_in_flight: u32,
    /// 累计进入 OPEN 次数（未来退避策略的输入）
    open_count: u64,
    open_info: Option<OpenInfo>,
}

impl CircuitBreaker {
    pub fn new(scope: BreakerScope, params: BreakerParams) -> Self {
        let key = BreakerKey::of(&scope);
        Self {
            key,
            scope,
            params,
            state: BreakerState::Closed,
            consecutive_failures: 0,
            half_open_success_count: 0,
            probes_in_flight: 0,
            open_count: 0,
            open_info: None,
        }
    }

    // ---------- 只读查询 ----------

    pub fn key(&self) -> &BreakerKey {
        &self.key
    }

    pub fn scope(&self) -> &BreakerScope {
        &self.scope
    }

    pub fn state(&self) -> BreakerState {
        self.state
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn open_snapshot(&self) -> Option<&FailureSnapshot> {
        self.open_info.as_ref().map(|i| &i.snapshot)
    }

    pub fn status(&self, clock: &dyn Clock) -> BreakerStatus {
        let remaining = match (&self.state, &self.open_info) {
            (BreakerState::Open, Some(info)) => {
                info.cooldown_until_ms.saturating_sub(clock.now_ms())
            }
            _ => 0,
        };
        BreakerStatus {
            key: self.key.0.clone(),
            scope_kind: self.scope.kind(),
            state: self.state,
            consecutive_failures: self.consecutive_failures,
            half_open_success_count: self.half_open_success_count,
            probes_in_flight: self.probes_in_flight,
            open_count: self.open_count,
            open_reason: self.open_info.as_ref().map(|i| i.reason.as_str()),
            cooldown_remaining_ms: remaining,
        }
    }

    // ---------- 业务流量 ----------

    /// 业务报文准入。OPEN / HALF_OPEN 一律拒绝（HALF_OPEN 窗口保留给探测）。
    /// 内部先 evaluate，保证冷却到期后即使没有 tick 也能及时进入 HALF_OPEN。
    pub fn allow_request(&mut self, clock: &dyn Clock) -> Decision {
        self.evaluate(clock);
        match self.state {
            BreakerState::Closed => Decision::Allowed,
            BreakerState::Open => Decision::Rejected(RejectReason::CircuitOpen),
            BreakerState::HalfOpen => Decision::Rejected(RejectReason::HalfOpenProbeOnly),
        }
    }

    /// 业务成功。CLOSED 下清空连续失败计数（修正三：success 即清零）。
    /// 成功永远不会改变状态，因此永远不产生事件。
    pub fn record_success(&mut self, _clock: &dyn Clock) -> Option<SystemEvent> {
        if self.state == BreakerState::Closed && self.consecutive_failures != 0 {
            self.consecutive_failures = 0;
        }
        None
    }

    /// 业务失败（Quality Failure 路径）。
    pub fn record_failure(&mut self, clock: &dyn Clock) -> Option<SystemEvent> {
        self.record_failure_inner(clock, None)
    }

    /// 带诊断细节的业务失败。
    pub fn record_failure_with_detail(
        &mut self,
        clock: &dyn Clock,
        detail: impl Into<String>,
    ) -> Option<SystemEvent> {
        self.record_failure_inner(clock, Some(detail.into()))
    }

    /// Hard Failure：无视阈值与当前状态，立即 OPEN（修正三）。
    /// 已处于 OPEN 时：刷新冷却并更新快照，不产生重复状态事件（修正八）。
    pub fn record_fatal(
        &mut self,
        clock: &dyn Clock,
        detail: impl Into<String>,
    ) -> Option<SystemEvent> {
        match self.state {
            BreakerState::Closed | BreakerState::HalfOpen => {
                self.transition_to_open(clock, TransitionReason::FatalFailure, Some(detail.into()))
            }
            BreakerState::Open => {
                if let Some(info) = self.open_info.as_mut() {
                    info.reason = TransitionReason::FatalFailure;
                    info.snapshot.detail = Some(detail.into());
                    info.cooldown_until_ms =
                        clock.now_ms() + self.params.cooldown_ms(self.open_count);
                }
                None
            }
        }
    }

    // ---------- 探测 ----------

    /// 申请发起一次探测。返回是否获准。
    /// - CLOSED：诊断性健康探测不受限（不占 HALF_OPEN 名额）
    /// - OPEN：拒绝（等待冷却到期进入 HALF_OPEN）
    /// - HALF_OPEN：受 max_half_open_probes 严格限流（第一版 = 1）
    pub fn begin_probe(&mut self, clock: &dyn Clock) -> bool {
        self.evaluate(clock);
        match self.state {
            BreakerState::Closed => true,
            BreakerState::Open => false,
            BreakerState::HalfOpen => {
                if self.probes_in_flight < self.params.max_half_open_probes {
                    self.probes_in_flight += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// 探测成功。
    /// - HALF_OPEN：计数 +1；达到 half_open_success_threshold → CLOSED（必须连续达标）
    /// - CLOSED：诊断探测成功同样证明健康，清空连续失败计数
    /// - OPEN：忽略（OPEN 下探测不会被批准）
    pub fn probe_success(&mut self, clock: &dyn Clock) -> Option<SystemEvent> {
        match self.state {
            BreakerState::HalfOpen => {
                self.probes_in_flight = self.probes_in_flight.saturating_sub(1);
                self.half_open_success_count += 1;
                if self.half_open_success_count >= self.params.half_open_success_threshold {
                    self.transition_to_closed(clock, TransitionReason::HalfOpenProbeSucceeded)
                } else {
                    None
                }
            }
            BreakerState::Closed => {
                self.consecutive_failures = 0;
                None
            }
            BreakerState::Open => None,
        }
    }

    /// 探测失败。
    /// - HALF_OPEN：立即 → OPEN 并重新开始冷却（修正五）
    /// - CLOSED：计入连续失败（探测失败同样是质量信号）
    /// - OPEN：忽略
    pub fn probe_failure(&mut self, clock: &dyn Clock) -> Option<SystemEvent> {
        match self.state {
            BreakerState::HalfOpen => {
                self.probes_in_flight = self.probes_in_flight.saturating_sub(1);
                self.half_open_success_count = 0;
                self.transition_to_open(clock, TransitionReason::HalfOpenProbeFailed, None)
            }
            BreakerState::Closed => self.record_failure(clock),
            BreakerState::Open => None,
        }
    }

    // ---------- 时间驱动 ----------

    /// 时间推进钩子：OPEN 冷却到期 → HALF_OPEN。
    /// 只在真正发生迁移时产生事件（修正八：无变化不刷事件）。
    pub fn evaluate(&mut self, clock: &dyn Clock) -> Option<SystemEvent> {
        if self.state != BreakerState::Open {
            return None;
        }
        let due = match &self.open_info {
            Some(info) => info.cooldown_until_ms,
            None => return None,
        };
        if clock.now_ms() >= due {
            let prev = self.state;
            self.state = BreakerState::HalfOpen;
            self.half_open_success_count = 0;
            self.probes_in_flight = 0;
            Some(self.make_event(clock, prev, BreakerState::HalfOpen, TransitionReason::CooldownExpired))
        } else {
            None
        }
    }

    // ---------- 手动 Override（修正九） ----------

    /// 手动熔断（管理员摘除节点 / 故障注入）。已 OPEN 时仅刷新冷却，不重复发事件。
    pub fn force_open(&mut self, clock: &dyn Clock) -> Option<SystemEvent> {
        match self.state {
            BreakerState::Open => {
                if let Some(info) = self.open_info.as_mut() {
                    info.cooldown_until_ms =
                        clock.now_ms() + self.params.cooldown_ms(self.open_count);
                }
                None
            }
            _ => self.transition_to_open(clock, TransitionReason::ManualOpen, Some("manual".into())),
        }
    }

    /// 手动关闭：回到 CLOSED，全部计数清零。状态未变时不产生事件。
    pub fn force_close(&mut self, clock: &dyn Clock) -> Option<SystemEvent> {
        match self.state {
            BreakerState::Closed => None,
            _ => self.transition_to_closed(clock, TransitionReason::ManualReset),
        }
    }

    /// 程序化复位：语义等同 force_close（用于开发调试/测试复位）。
    pub fn reset(&mut self, clock: &dyn Clock) -> Option<SystemEvent> {
        self.force_close(clock)
    }

    // ---------- 内部迁移 ----------

    fn record_failure_inner(
        &mut self,
        clock: &dyn Clock,
        detail: Option<String>,
    ) -> Option<SystemEvent> {
        match self.state {
            BreakerState::Closed => {
                self.consecutive_failures += 1;
                if self.consecutive_failures >= self.params.failure_threshold {
                    self.transition_to_open(clock, TransitionReason::FailureThresholdReached, detail)
                } else {
                    None
                }
            }
            // OPEN / HALF_OPEN 下的业务失败不影响状态：
            // OPEN 本就熔断；HALF_OPEN 业务流量被拒绝，不应有业务失败到达。
            BreakerState::Open | BreakerState::HalfOpen => None,
        }
    }

    fn transition_to_open(
        &mut self,
        clock: &dyn Clock,
        reason: TransitionReason,
        detail: Option<String>,
    ) -> Option<SystemEvent> {
        let prev = self.state;
        let now = clock.now_ms();
        self.open_count += 1;
        let cooldown_ms = self.params.cooldown_ms(self.open_count);
        self.open_info = Some(OpenInfo {
            cooldown_until_ms: now.saturating_add(cooldown_ms),
            reason,
            snapshot: FailureSnapshot {
                consecutive_failures: self.consecutive_failures,
                detail,
                opened_at_ms: now,
            },
        });
        self.state = BreakerState::Open;
        self.half_open_success_count = 0;
        self.probes_in_flight = 0;
        Some(self.make_event(clock, prev, BreakerState::Open, reason))
    }

    fn transition_to_closed(
        &mut self,
        clock: &dyn Clock,
        reason: TransitionReason,
    ) -> Option<SystemEvent> {
        let prev = self.state;
        self.state = BreakerState::Closed;
        self.consecutive_failures = 0;
        self.half_open_success_count = 0;
        self.probes_in_flight = 0;
        self.open_info = None;
        Some(self.make_event(clock, prev, BreakerState::Closed, reason))
    }

    fn make_event(
        &self,
        clock: &dyn Clock,
        previous_state: BreakerState,
        new_state: BreakerState,
        reason: TransitionReason,
    ) -> SystemEvent {
        SystemEvent::CircuitStateChanged {
            breaker_id: self.key.0.clone(),
            scope: self.scope.kind().to_string(),
            previous_state: previous_state.as_str().to_string(),
            new_state: new_state.as_str().to_string(),
            reason: reason.as_str().to_string(),
            consecutive_failures: self.consecutive_failures,
            ts_monotonic_ms: clock.now_ms(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::FakeClock;
    use config_manager::RuntimeParams;

    /// 参数构造：一律经由 RuntimeParams（修正十一：配置唯一来源）。
    fn params(threshold: u32, cooldown_secs: u64, success_threshold: u32, max_probes: u32) -> BreakerParams {
        let mut rt = RuntimeParams::default();
        rt.circuit_failure_threshold = threshold;
        rt.circuit_open_cooldown_secs = cooldown_secs;
        rt.half_open_success_threshold = success_threshold;
        rt.max_half_open_probes = max_probes;
        BreakerParams::from(&rt)
    }

    /// 默认参数 breaker：threshold=3 / cooldown=30s / success=3 / max_probes=1。
    fn breaker() -> CircuitBreaker {
        CircuitBreaker::new(BreakerScope::N2NProvider, params(3, 30, 3, 1))
    }

    /// 断言事件类型与迁移三元组，返回 (consecutive_failures, ts_ms)。
    fn assert_event(
        ev: Option<SystemEvent>,
        prev: &str,
        new: &str,
        reason: &str,
    ) -> (u32, u64) {
        let ev = ev.expect("应产生状态迁移事件");
        assert_eq!(ev.name(), "CIRCUIT_STATE_CHANGED");
        match ev {
            SystemEvent::CircuitStateChanged {
                previous_state, new_state, reason: r, consecutive_failures, ts_monotonic_ms, ..
            } => {
                assert_eq!(previous_state, prev, "previous_state 不符");
                assert_eq!(new_state, new, "new_state 不符");
                assert_eq!(r, reason, "reason 不符");
                (consecutive_failures, ts_monotonic_ms)
            }
            other => panic!("事件类型错误: {other:?}"),
        }
    }

    fn assert_no_event(ev: Option<SystemEvent>) {
        assert!(ev.is_none(), "状态未变不应产生事件: {ev:?}");
    }

    /// 工具：走完"3 连败 → OPEN → 冷却到期 → HALF_OPEN"。
    fn to_half_open(b: &mut CircuitBreaker, clock: &FakeClock) {
        b.record_failure(clock);
        b.record_failure(clock);
        b.record_failure(clock);
        clock.advance_ms(30_000);
        b.evaluate(clock);
        assert_eq!(b.state(), BreakerState::HalfOpen);
    }

    // ---------- 1~4：CLOSED 基础阈值 ----------

    #[test]
    fn t01_initial_state_is_closed() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!(b.consecutive_failures(), 0);
        assert_eq!(b.allow_request(&clock), Decision::Allowed);
        assert!(b.begin_probe(&clock), "CLOSED 下诊断探测不受限");
        assert!(b.open_snapshot().is_none());
    }

    #[test]
    fn t02_single_failure_stays_closed() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        assert_no_event(b.record_failure(&clock));
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!(b.consecutive_failures(), 1);
        assert_eq!(b.allow_request(&clock), Decision::Allowed);
    }

    #[test]
    fn t03_two_failures_stay_closed() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        assert_no_event(b.record_failure(&clock));
        assert_no_event(b.record_failure(&clock));
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!(b.consecutive_failures(), 2);
    }

    #[test]
    fn t04_three_consecutive_failures_open() {
        let mut b = breaker();
        let clock = FakeClock::new(1000);
        assert_no_event(b.record_failure(&clock));
        assert_no_event(b.record_failure(&clock));
        let (fails, ts) = assert_event(
            b.record_failure(&clock),
            "closed",
            "open",
            "failure_threshold_reached",
        );
        assert_eq!(fails, 3);
        assert_eq!(ts, 1000);
        assert_eq!(b.state(), BreakerState::Open);
        assert_eq!(b.allow_request(&clock), Decision::Rejected(RejectReason::CircuitOpen));
        let snap = b.open_snapshot().expect("OPEN 必须有快照");
        assert_eq!(snap.consecutive_failures, 3);
        assert_eq!(snap.opened_at_ms, 1000);
        // 快照：opened_at / cooldown_until / open_reason
        let st = b.status(&clock);
        assert_eq!(st.open_reason, Some("failure_threshold_reached"));
        assert_eq!(st.cooldown_remaining_ms, 30_000);
    }

    // ---------- 5：success 清零 ----------

    #[test]
    fn t05_success_resets_consecutive_failures() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        b.record_failure(&clock);
        b.record_failure(&clock);
        assert_no_event(b.record_success(&clock));
        assert_eq!(b.consecutive_failures(), 0, "success 必须清零连续失败计数");
        // 若未清零，这里 1 次失败就够 3；正确行为：仍 CLOSED 且无事件
        assert_no_event(b.record_failure(&clock));
        assert_eq!(b.state(), BreakerState::Closed);
        // 再补 2 次才应 OPEN
        assert_no_event(b.record_failure(&clock));
        assert_event(b.record_failure(&clock), "closed", "open", "failure_threshold_reached");
    }

    // ---------- 6：Hard Failure 立即 OPEN ----------

    #[test]
    fn t06_fatal_from_closed_opens_immediately() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        // 无任何 Quality 失败累积（0 < threshold=3），fatal 仍必须立即 OPEN
        let (_, _) = assert_event(b.record_fatal(&clock, "edge crashed"), "closed", "open", "fatal_failure");
        assert_eq!(b.state(), BreakerState::Open);
        let snap = b.open_snapshot().unwrap();
        assert_eq!(snap.detail.as_deref(), Some("edge crashed"));
        assert_eq!(b.status(&clock).open_reason, Some("fatal_failure"));
    }

    // ---------- 7~8：OPEN 冷却 ----------

    #[test]
    fn t07_open_rejects_probe_and_request_before_cooldown() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        b.record_fatal(&clock, "x");
        assert!(!b.begin_probe(&clock), "OPEN 未到期不得探测");
        assert_eq!(b.allow_request(&clock), Decision::Rejected(RejectReason::CircuitOpen));
        assert_eq!(b.state(), BreakerState::Open);
    }

    #[test]
    fn t08_cooldown_expiry_transitions_to_half_open() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        b.record_fatal(&clock, "x");
        clock.advance_ms(30_000);
        assert_event(b.evaluate(&clock), "open", "half_open", "cooldown_expired");
        assert_eq!(b.state(), BreakerState::HalfOpen);
        // HALF_OPEN：业务拒绝、探测通道可用
        assert_eq!(b.allow_request(&clock), Decision::Rejected(RejectReason::HalfOpenProbeOnly));
        assert!(b.begin_probe(&clock));
    }

    // ---------- 9 / 24：HALF_OPEN 限流 ----------

    #[test]
    fn t09_half_open_allows_only_configured_probe_count() {
        let mut b = breaker(); // max_half_open_probes = 1
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        assert!(b.begin_probe(&clock), "第 1 个探测名额应获准");
        assert!(!b.begin_probe(&clock), "超过 max_half_open_probes 必须拒绝");
        assert_eq!(b.status(&clock).probes_in_flight, 1);
    }

    #[test]
    fn t24_probe_slot_lifecycle_and_custom_limit() {
        // 默认 limit=1：释放后可再取
        let mut b = breaker();
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        assert!(b.begin_probe(&clock));
        assert!(!b.begin_probe(&clock));
        assert_no_event(b.probe_success(&clock)); // 1/3，名额释放
        assert!(b.begin_probe(&clock), "success 后名额必须可复用");
        b.probe_failure(&clock); // → OPEN，名额清零
        assert_eq!(b.status(&clock).probes_in_flight, 0);

        // 自定义 limit=2：前两个获准，第三个拒绝
        let mut b2 = CircuitBreaker::new(BreakerScope::N2NProvider, params(3, 30, 3, 2));
        to_half_open(&mut b2, &clock);
        assert!(b2.begin_probe(&clock));
        assert!(b2.begin_probe(&clock));
        assert!(!b2.begin_probe(&clock), "limit=2 时第 3 个必须拒绝");
    }

    // ---------- 10~12：HALF_OPEN 成功计数 ----------

    #[test]
    fn t10_half_open_first_success_still_half_open() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        assert!(b.begin_probe(&clock));
        assert_no_event(b.probe_success(&clock));
        assert_eq!(b.state(), BreakerState::HalfOpen);
        assert_eq!(b.status(&clock).half_open_success_count, 1);
    }

    #[test]
    fn t11_half_open_second_success_still_half_open() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        for _ in 0..2 {
            assert!(b.begin_probe(&clock));
            assert_no_event(b.probe_success(&clock));
        }
        assert_eq!(b.state(), BreakerState::HalfOpen);
        assert_eq!(b.status(&clock).half_open_success_count, 2);
    }

    #[test]
    fn t12_half_open_three_successes_close() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        for _ in 0..2 {
            assert!(b.begin_probe(&clock));
            assert_no_event(b.probe_success(&clock));
        }
        assert!(b.begin_probe(&clock));
        assert_event(b.probe_success(&clock), "half_open", "closed", "half_open_probe_succeeded");
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!(b.consecutive_failures(), 0);
        assert!(b.open_snapshot().is_none());
        // 恢复后业务放行
        assert_eq!(b.allow_request(&clock), Decision::Allowed);
    }

    // ---------- 13~14：HALF_OPEN 失败/fatal ----------

    #[test]
    fn t13_half_open_probe_failure_reopens_with_fresh_cooldown() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        assert!(b.begin_probe(&clock));
        assert_event(b.probe_failure(&clock), "half_open", "open", "half_open_probe_failed");
        assert_eq!(b.state(), BreakerState::Open);
        // 重新开始完整 30s 冷却：t=30000 起，到 60000
        clock.advance_ms(29_999);
        assert_no_event(b.evaluate(&clock));
        assert_eq!(b.state(), BreakerState::Open, "必须重新冷却，不得提前恢复");
        clock.advance_ms(1);
        assert_event(b.evaluate(&clock), "open", "half_open", "cooldown_expired");
    }

    #[test]
    fn t14_half_open_fatal_reopens_immediately() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        assert!(b.begin_probe(&clock));
        assert_event(b.record_fatal(&clock, "fatal in probe"), "half_open", "open", "fatal_failure");
        assert_eq!(b.state(), BreakerState::Open);
        // 新一轮冷却
        clock.advance_ms(29_999);
        assert_eq!(b.state(), BreakerState::Open);
        clock.advance_ms(1);
        assert_event(b.evaluate(&clock), "open", "half_open", "cooldown_expired");
        assert_eq!(b.state(), BreakerState::HalfOpen);
    }

    // ---------- 15：OPEN 期间的事件幂等 ----------

    #[test]
    fn t15_open_state_ignores_subsequent_failures() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        b.record_fatal(&clock, "x");
        clock.advance_ms(20_000);
        // 业务失败 / 探测失败 / 重复 fatal / 重复 force_open：均不改变状态、不刷事件
        assert_no_event(b.record_failure(&clock));
        assert_no_event(b.probe_failure(&clock));
        assert_eq!(b.state(), BreakerState::Open);
        // fatal 刷新冷却：剩余从 10s 回到满 30s
        assert_no_event(b.record_fatal(&clock, "again"));
        assert_eq!(b.status(&clock).cooldown_remaining_ms, 30_000);
        assert_no_event(b.force_open(&clock));
        assert_eq!(b.state(), BreakerState::Open);
        // 成功不产生事件，也不改变 OPEN
        assert_no_event(b.record_success(&clock));
        assert_eq!(b.state(), BreakerState::Open);
    }

    // ---------- 16~18：Manual Override ----------

    #[test]
    fn t16_force_open() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        b.record_failure(&clock);
        b.record_failure(&clock);
        let (fails, _) = assert_event(b.force_open(&clock), "closed", "open", "manual_open");
        assert_eq!(fails, 2, "事件必须带上触发时的失败快照");
        assert_eq!(b.status(&clock).open_reason, Some("manual_open"));
        // 已 OPEN 时重复 force_open 只刷新冷却
        clock.advance_ms(10_000);
        assert_no_event(b.force_open(&clock));
        assert_eq!(b.status(&clock).cooldown_remaining_ms, 30_000);
    }

    #[test]
    fn t17_force_close_resets_everything() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        b.record_fatal(&clock, "x");
        assert_eq!(b.state(), BreakerState::Open);
        assert_event(b.force_close(&clock), "open", "closed", "manual_reset");
        assert_eq!(b.state(), BreakerState::Closed);
        let st = b.status(&clock);
        assert_eq!(st.consecutive_failures, 0);
        assert_eq!(st.half_open_success_count, 0);
        assert_eq!(st.probes_in_flight, 0);
        assert!(b.open_snapshot().is_none());
        assert_eq!(b.allow_request(&clock), Decision::Allowed);
        // 已 CLOSED 重复 force_close：无事件
        assert_no_event(b.force_close(&clock));
    }

    #[test]
    fn t18_reset_from_half_open() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        to_half_open(&mut b, &clock);
        assert!(b.begin_probe(&clock));
        assert_event(b.reset(&clock), "half_open", "closed", "manual_reset");
        assert_eq!(b.state(), BreakerState::Closed);
        assert_eq!(b.status(&clock).half_open_success_count, 0);
    }

    // ---------- 22：时钟回拨 ----------

    #[test]
    fn t22_clock_rollback_does_not_corrupt_state() {
        let mut b = breaker();
        let clock = FakeClock::new(5_000);
        b.record_fatal(&clock, "x"); // cooldown_until = 35_000（单调基准）
        // 模拟"系统时间被回拨 1 小时"：状态机不得提前恢复
        clock.set_ms(0);
        assert_no_event(b.evaluate(&clock));
        assert_eq!(b.state(), BreakerState::Open, "回拨不得触发 HALF_OPEN");
        assert_eq!(b.status(&clock).cooldown_remaining_ms, 35_000);
        clock.set_ms(34_999);
        assert_eq!(b.state(), BreakerState::Open);
        clock.advance_ms(1); // 35_000
        assert_event(b.evaluate(&clock), "open", "half_open", "cooldown_expired");
    }

    // ---------- 23：冷却边界 ----------

    #[test]
    fn t23_cooldown_boundary_29999_vs_30000() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        b.record_fatal(&clock, "x");
        clock.advance_ms(29_999);
        assert_no_event(b.evaluate(&clock));
        assert_eq!(b.state(), BreakerState::Open, "29.999s 不得切换");
        clock.advance_ms(1); // 恰好 30.000s
        assert_event(b.evaluate(&clock), "open", "half_open", "cooldown_expired");
        assert_eq!(b.state(), BreakerState::HalfOpen);
    }

    // ---------- 25：事件字段完整性 ----------

    #[test]
    fn t25_event_fields_are_complete() {
        let mut b = breaker();
        let clock = FakeClock::new(4321);
        b.record_failure(&clock);
        b.record_failure(&clock);
        let ev = b.record_failure(&clock).expect("第三次失败必须产生事件");
        match ev {
            SystemEvent::CircuitStateChanged {
                breaker_id,
                scope,
                previous_state,
                new_state,
                reason,
                consecutive_failures,
                ts_monotonic_ms,
            } => {
                assert_eq!(breaker_id, "n2n.provider");
                assert_eq!(scope, "n2n_provider");
                assert_eq!(previous_state, "closed");
                assert_eq!(new_state, "open");
                assert_eq!(reason, "failure_threshold_reached");
                assert_eq!(consecutive_failures, 3);
                assert_eq!(ts_monotonic_ms, 4321, "必须是注入时钟的单调时间");
            }
            other => panic!("事件类型错误: {other:?}"),
        }
    }

    // ---------- 26：无变化不刷事件 ----------

    #[test]
    fn t26_no_duplicate_events_without_transition() {
        let mut b = breaker();
        let clock = FakeClock::new(0);
        // CLOSED：一切正常路径都不产生事件
        assert_no_event(b.record_success(&clock));
        assert_no_event(b.record_failure(&clock));
        assert_no_event(b.evaluate(&clock));
        assert_no_event(b.force_close(&clock));
        assert!(b.begin_probe(&clock));
        assert_no_event(b.probe_success(&clock));

        // OPEN：冷却期内重复 evaluate / record_* 不产生事件
        b.record_fatal(&clock, "x");
        clock.advance_ms(5_000);
        assert_no_event(b.evaluate(&clock));
        assert_no_event(b.evaluate(&clock));
        assert_no_event(b.record_failure(&clock));
        assert_no_event(b.record_fatal(&clock, "y"));
        assert_no_event(b.force_open(&clock));

        // 到期只发一次；HALF_OPEN 内重复 evaluate 也不再发
        // （注意：上面 force_open 已把冷却刷新到 t=35000）
        clock.advance_ms(30_000);
        assert!(b.evaluate(&clock).is_some(), "冷却到期应恰好产生一次事件");
        assert_no_event(b.evaluate(&clock));
        assert_no_event(b.evaluate(&clock));

        // HALF_OPEN 探测失败只发一次；随后 OPEN 内重复 probe_failure 不再发
        assert!(b.begin_probe(&clock));
        assert!(b.probe_failure(&clock).is_some());
        assert_no_event(b.probe_failure(&clock));
        assert_no_event(b.record_failure(&clock));
    }
}
