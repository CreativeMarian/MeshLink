//! Overlay Router + Path Manager（M0-7 实现）。
//!
//! 解耦硬性规则：
//! - 只面向 transport-api::TransportProvider，禁止任何具体实现类型/分支。
//! - 路径选择 = PathPolicy(可配置) × 熔断门(四类) × 健康分。
//! - Hard Failure（Fatal 事件）→ 立即熔断并切换；Quality Degradation →
//!   健康分驱动（Critical <40 持续 3s）。两套触发机制分离（确认版 §4）。

pub mod placeholder {
    pub const TASK: &str = "M0-7: Provider 注册 + PathPolicy + 健康分 + 防抖 + 切换事件";
}
