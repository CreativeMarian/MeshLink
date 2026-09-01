//! 可注入时钟。
//!
//! 硬性规则（M0-2 修正二）：
//! - 熔断器冷却时间只依赖单调时钟，禁止使用系统墙上时间——
//!   防止用户修改 Windows 系统时间导致熔断状态错乱。
//! - 单元测试使用 [`FakeClock`]，毫秒级完成，不允许 sleep。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// 时钟抽象。`now_ms()` 必须单调递增（FakeClock 的 set_ms 仅用于测试回拨场景验证）。
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

/// 生产用单调时钟：以进程启动点为 0，基于 `Instant`（OS 单调时钟）。
#[derive(Debug)]
pub struct MonotonicClock {
    start: Instant,
}

impl MonotonicClock {
    pub fn new() -> Self {
        Self { start: Instant::now() }
    }
}

impl Default for MonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
}

/// 测试用可控时钟。
#[derive(Debug)]
pub struct FakeClock {
    now: AtomicU64,
}

impl FakeClock {
    pub fn new(start_ms: u64) -> Self {
        Self { now: AtomicU64::new(start_ms) }
    }

    pub fn advance_ms(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    /// 仅供测试"时钟回拨"场景（真机 MonotonicClock 不会回拨）。
    pub fn set_ms(&self, ms: u64) {
        self.now.store(ms, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now_ms(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fake_clock_advance_and_set() {
        let c = FakeClock::new(1000);
        assert_eq!(c.now_ms(), 1000);
        c.advance_ms(29_000);
        assert_eq!(c.now_ms(), 30_000);
        c.set_ms(5); // 回拨（仅测试场景）
        assert_eq!(c.now_ms(), 5);
    }

    #[test]
    fn monotonic_clock_starts_near_zero() {
        let c = MonotonicClock::new();
        let t0 = c.now_ms();
        std::thread::sleep(std::time::Duration::from_millis(5));
        let t1 = c.now_ms();
        assert!(t0 < 100, "起始应接近 0: {t0}");
        assert!(t1 >= t0, "单调时钟不可回退");
    }
}
