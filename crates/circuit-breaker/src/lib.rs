//! 三态熔断器：纯状态机模块（文档 9.3 / M0-2 修正一~九）。
//!
//! 纯度保证（修正一）：本 crate 不依赖 N2N / DirectLink / Cloudflare /
//! Wintun / Controller / 任何网络与 IO —— 只接收调用方注入的事件
//! （record_success / record_failure / record_fatal / probe_* / allow_request /
//! evaluate），并产生状态迁移与结构化事件。
//!
//! 关键设计：
//! - 时间经 [`clock::Clock`] 注入：生产用单调时钟，测试用 FakeClock；
//!   冷却计算禁止依赖系统墙上时间（修正二）。
//! - 参数唯一来源为 config-manager::RuntimeParams（修正十一），本 crate 不定义默认值。
//! - 状态机只识别 [`scope::BreakerKey`]，对 scope 种类零知识（修正六）；
//!   [`manager::CircuitBreakerManager`] 以 `HashMap<BreakerKey, CircuitBreaker>`
//!   保证每个对象（如每个 Supernode）状态完全隔离（修正七）。
//! - 每次真实状态迁移产生一条 `SystemEvent::CircuitStateChanged`；
//!   状态未变绝不重复刷事件（修正八）。

pub mod breaker;
pub mod clock;
pub mod manager;
pub mod params;
pub mod scope;

pub use breaker::{
    BreakerState, BreakerStatus, CircuitBreaker, Decision, FailureSnapshot, RejectReason,
    TransitionReason,
};
pub use clock::{Clock, FakeClock, MonotonicClock};
pub use manager::CircuitBreakerManager;
pub use params::{BreakerParams, CooldownStrategy};
pub use scope::{BreakerKey, BreakerScope};
