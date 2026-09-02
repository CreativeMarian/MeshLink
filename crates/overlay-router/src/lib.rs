//! Overlay Router + Path Manager（M1-3 实现）。
//!
//! 解耦硬性规则：
//! - 只面向 transport-api::TransportProvider，禁止任何具体实现类型/分支。
//! - 路径选择 = 强制路径 × 熔断门(四类) × 健康分 × 防抖回切（见 path_manager 模块文档）。
//! - Hard Failure（Fatal 事件）→ 立即熔断并切换；Quality Degradation →
//!   健康分驱动（Critical <40 持续 3s）。两套触发机制分离（确认版 §4）。

pub mod path_manager;

pub use path_manager::{
    ActivePathInfo, PathHealthInfo, PathManager, PathManagerConfig, PathManagerSnapshot,
    PathSwitchRecord,
};
