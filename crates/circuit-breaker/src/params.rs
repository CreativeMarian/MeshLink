//! 熔断器参数。
//!
//! 硬性规则（M0-2 修正十一）：本 crate 不定义任何默认值，
//! 全部参数从 config-manager::RuntimeParams 进入（配置唯一来源）。
//!
//! 冷却策略接口预留扩展（M0-2 修正四）：第一版仅实现 Fixed，
//! 结构上允许未来增加指数退避 / 最大冷却 / 抖动，不允许实现写死。

use config_manager::RuntimeParams;

/// 冷却策略。第一版固定 30s；指数退避等策略未来以新增变体接入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CooldownStrategy {
    Fixed { secs: u64 },
    // 预留（暂不实现）：
    // ExponentialBackoff { base_secs: u64, max_secs: u64, jitter_pct: u8 },
}

/// 熔断器运行参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BreakerParams {
    /// 连续失败阈值（Quality Failure；success 即清零）
    pub failure_threshold: u32,
    pub cooldown: CooldownStrategy,
    /// HALF_OPEN → CLOSED 需要的连续探测成功次数
    pub half_open_success_threshold: u32,
    /// HALF_OPEN 最大并发探测数（第一版 = 1，严格限流）
    pub max_half_open_probes: u32,
}

impl BreakerParams {
    /// 本次熔断的冷却毫秒数。
    ///
    /// `open_count`：该 breaker 累计进入 OPEN 的次数——
    /// 现在的 Fixed 策略忽略它，未来退避策略用它计算第 N 次熔断的冷却时长。
    pub fn cooldown_ms(&self, open_count: u64) -> u64 {
        let _ = open_count; // Fixed 策略忽略；退避策略实现时使用
        match &self.cooldown {
            CooldownStrategy::Fixed { secs } => secs.saturating_mul(1000),
        }
    }
}

impl From<&RuntimeParams> for BreakerParams {
    fn from(p: &RuntimeParams) -> Self {
        Self {
            failure_threshold: p.circuit_failure_threshold,
            cooldown: CooldownStrategy::Fixed { secs: p.circuit_open_cooldown_secs },
            half_open_success_threshold: p.half_open_success_threshold,
            max_half_open_probes: p.max_half_open_probes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params_come_from_config_manager_only() {
        // 唯一来源：RuntimeParams 默认值（3 / 30s / 3 / 1）
        let rt = RuntimeParams::default();
        let p = BreakerParams::from(&rt);
        assert_eq!(p.failure_threshold, 3);
        assert_eq!(p.cooldown, CooldownStrategy::Fixed { secs: 30 });
        assert_eq!(p.half_open_success_threshold, 3);
        assert_eq!(p.max_half_open_probes, 1);
        assert_eq!(p.cooldown_ms(1), 30_000);
        assert_eq!(p.cooldown_ms(99), 30_000, "Fixed 策略与 open_count 无关");
    }
}
