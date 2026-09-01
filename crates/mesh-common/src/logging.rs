//! 日志规范：tracing + 环境过滤 + 敏感字段脱敏。
//!
//! 约定：
//! - 任何密钥/token/密码值输出日志前必须经过 [`redact`]。
//! - JSON 模式供 Controller/Service 汇聚；控制台模式供开发调试。

use tracing_subscriber::EnvFilter;

/// 初始化全局日志。`json = true` 时输出结构化 JSON 行。
/// 幂等：已设置过全局 subscriber 时静默跳过（同进程多测试并行安全）。
pub fn init_logging(level: &str, json: bool) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level.to_string()));
    let builder = tracing_subscriber::fmt().with_env_filter(filter);
    let _ = if json {
        builder.json().flatten_event(true).try_init()
    } else {
        builder.try_init()
    };
}

/// 敏感值脱敏：保留前 2 后 2 字符，中间以 `***` 代替；短值整体替换。
pub fn redact(value: &str) -> String {
    let n = value.chars().count();
    if n <= 6 {
        "***".to_string()
    } else {
        let head: String = value.chars().take(2).collect();
        let tail: String = value.chars().skip(n - 2).collect();
        format!("{head}***{tail}")
    }
}

/// 判断字段名是否属于敏感字段（记录用）。
pub fn is_sensitive_field(field: &str) -> bool {
    const SENSITIVE: [&str; 10] = [
        "password", "token", "secret", "private_key", "session_key",
        "psk", "invite_token", "api_token", "tunnel_token", "credential",
    ];
    let f = field.to_ascii_lowercase();
    SENSITIVE.iter().any(|s| f.contains(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_short_values() {
        assert_eq!(redact("abc"), "***");
        assert_eq!(redact("123456"), "***");
    }

    #[test]
    fn redact_long_values_keep_head_tail() {
        let r = redact("AbCdEfGhIjKl");
        assert_eq!(r, "Ab***Kl");
    }

    #[test]
    fn sensitive_field_detection() {
        assert!(is_sensitive_field("invite_token"));
        assert!(is_sensitive_field("PRIVATE_KEY_PATH"));
        assert!(!is_sensitive_field("device_name"));
    }
}
