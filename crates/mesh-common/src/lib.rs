//! meshlink 公共基础库：错误码、系统事件、日志规范。
//!
//! 硬性要求（文档 25.2）：
//! - 错误码与用户提示分离：`MeshError::code` 供程序/日志使用，
//!   `user_message()` 返回面向用户的、不泄露底层细节的文案。
//! - 敏感日志默认脱敏：任何疑似 token/密码/私钥的字段必须经 `redact` 处理。

pub mod error;
pub mod events;
pub mod logging;

pub use error::{ErrorCode, MeshError};
pub use events::SystemEvent;
