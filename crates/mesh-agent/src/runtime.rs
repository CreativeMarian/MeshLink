//! M1-1.5：runtime 临时目录。
//!
//! 与永久身份严格分离：
//! - 本模块只写**临时运行状态**：active_session / quick_code / runtime_token /
//!   temporary_candidates，全部属于 `runtime/` 目录，正常退出删除、异常退出由
//!   MeshLink ProcessSupervisor 下次启动检测并自动清理；
//! - 永久身份（device_id / X25519 私钥 / credential / 好友授权）在 data_dir 的
//!   secure-store 中，本模块绝不触碰、绝不删除（用户规格四）；
//! - `dir` 为空表示未启用（独立运行 / 测试未显式指定时不落盘）。
//!
//! 这些文件仅是「残留检测 + 崩溃恢复」的标记与快照，不承载任何安全敏感数据。

use serde_json::json;
use std::path::PathBuf;

pub const ACTIVE_SESSION: &str = "active_session.json";
pub const QUICK_CODE: &str = "quick_code.json";
pub const RUNTIME_TOKEN: &str = "runtime_token.json";
pub const TEMP_CANDIDATES: &str = "temporary_candidates.json";

/// runtime 目录状态句柄（轻量，Clone 便宜；失败只记录日志不阻断主流程）。
#[derive(Debug, Clone, Default)]
pub struct RuntimeState {
    pub dir: PathBuf,
}

impl RuntimeState {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    pub fn enabled(&self) -> bool {
        !self.dir.as_os_str().is_empty()
    }

    fn ensure(&self) -> std::io::Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        std::fs::create_dir_all(&self.dir)
    }

    fn write(&self, name: &str, value: &serde_json::Value) {
        if !self.enabled() {
            return;
        }
        let bytes = serde_json::to_vec_pretty(value).unwrap_or_else(|_| b"{}".to_vec());
        if let Err(e) = self.ensure().and_then(|_| std::fs::write(self.dir.join(name), bytes)) {
            tracing::warn!(file = name, error = %e, "runtime 临时文件写入失败");
        }
    }

    fn remove(&self, name: &str) {
        if !self.enabled() {
            return;
        }
        let _ = std::fs::remove_file(self.dir.join(name));
    }

    /// 6 位码会话创建：quick_code + active_session 同时落盘。
    pub fn on_session_created(&self, session_id: &str, code: &str, expires_at: Option<&str>, status: &str) {
        self.write(QUICK_CODE, &json!({ "code": code, "expires_at": expires_at }));
        self.write(
            ACTIVE_SESSION,
            &json!({
                "session_id": session_id,
                "code": code,
                "expires_at": expires_at,
                "status": status,
            }),
        );
    }

    /// 会话状态推进（连接/断开等）：刷新 active_session；code 缺失时保留原值。
    pub fn on_session_update(&self, session_id: &str, code: Option<&str>, status: &str) {
        let mut v = json!({ "session_id": session_id, "status": status });
        if let Some(code) = code {
            v["code"] = json!(code);
            self.write(QUICK_CODE, &json!({ "code": code }));
        }
        self.write(ACTIVE_SESSION, &v);
    }

    /// 身份注册完成：写 token 标记（仅证明本机曾完成身份初始化）。
    pub fn write_token(&self, device_id: &str) {
        self.write(RUNTIME_TOKEN, &json!({ "device_id": device_id }));
    }

    /// 候选收集/上传标记。
    pub fn write_candidates(&self, count: usize, track: &str) {
        self.write(TEMP_CANDIDATES, &json!({ "count": count, "track": track }));
    }

    /// 会话结束/取消：清 session 类临时文件（保留 runtime_token 标记直至退出）。
    pub fn clear_session(&self) {
        self.remove(ACTIVE_SESSION);
        self.remove(QUICK_CODE);
        self.remove(TEMP_CANDIDATES);
    }

    /// 优雅关闭/退出：清空全部 runtime 临时文件（supervisor 随后删除整个目录）。
    pub fn clear_all(&self) {
        for f in [ACTIVE_SESSION, QUICK_CODE, RUNTIME_TOKEN, TEMP_CANDIDATES] {
            self.remove(f);
        }
    }

    /// 是否存在残留（MeshLink 启动时检测，供 ProcessSupervisor 决定清理）。
    pub fn has_residue(&self) -> bool {
        if !self.enabled() {
            return false;
        }
        [ACTIVE_SESSION, QUICK_CODE, RUNTIME_TOKEN, TEMP_CANDIDATES]
            .iter()
            .any(|f| self.dir.join(f).exists())
    }
}
