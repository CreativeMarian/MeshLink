//! webrtc 边界门禁（ADR DIRECTLINK_ICE.md / transport-api 硬性规则）：
//! rtc-ice / rtc-shared / sansio 三个 crate **只允许被 directlink（或 rtc 系
//! 家族内部互相依赖）直接依赖**。
//!
//! 用 `cargo tree -i <crate> --workspace` 反向依赖树验证：深度 1（第 0 列
//! `|--` / `` `-- `` 行）的直接依赖方，除 rtc 家族成员（rtc-* / sansio 内部
//! 组合，如 rtc-ice → rtc-shared）外，必须是 directlink。其他 workspace 成员
//! 经 directlink 传递获得依赖是预期的，但直接依赖（= 可直接 use 其符号）
//! 一律禁止，防止 webrtc 符号泄漏出 directlink 边界。

use std::process::Command;

const GATED: &[&str] = &["rtc-ice", "rtc-shared", "sansio"];
const ALLOWED_DEPENDENT: &str = "directlink";

/// rtc 家族内部依赖豁免（rtc-ice → rtc-shared/rtc-stun/rtc-mdns 属同族组合）。
fn is_rtc_family(name: &str) -> bool {
    name.starts_with("rtc-") || name.starts_with("sansio")
}

/// 移除 ANSI 转义序列（ESC '[' ... 终止符 的 CSI 序列）。
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            // 消费到 CSI 最终字节（0x40..=0x7E）
            while let Some(&c2) = chars.peek() {
                chars.next();
                if ('\u{40}'..='\u{7e}').contains(&c2) {
                    break;
                }
            }
        }
    }
    out
}

#[test]
fn webrtc_crates_only_directly_depended_by_directlink() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    for dep in GATED {
        let out = Command::new(&cargo)
            .args(["tree", "-i", dep, "--workspace", "--charset", "ascii", "--color", "never"])
            .output()
            .unwrap_or_else(|e| panic!("spawn cargo tree 失败: {e}"));
        assert!(
            out.status.success(),
            "cargo tree -i {dep} 失败:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        // 剥离 ANSI 转义（cargo tree 在 ConPTY 环境会输出颜色码，破坏行首前缀匹配）
        let stdout = strip_ansi(&String::from_utf8_lossy(&out.stdout));

        // 深度 1 的直接依赖方：行首（0 列）以 "|-- " 或 "`-- " 开始
        let dependents: Vec<&str> = stdout
            .lines()
            .filter(|l| l.starts_with("|-- ") || l.starts_with("`-- "))
            .map(|l| l[4..].split_whitespace().next().unwrap_or(""))
            .collect();

        assert!(
            dependents.iter().any(|d| *d == ALLOWED_DEPENDENT),
            "sanity: `{dep}` 应被 directlink 依赖（Track A 存在的前提）\n{stdout}"
        );
        for d in &dependents {
            assert!(
                *d == ALLOWED_DEPENDENT || is_rtc_family(d),
                "边界违规：`{dep}` 被非 directlink crate `{d}` 直接依赖\n反向树:\n{stdout}"
            );
        }
    }
}
