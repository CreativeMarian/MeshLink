//! Cloudflare WSS Relay Provider（M0-9 实现）。
//!
//! 定位：仅最终灾备（Emergency / Last Resort），永不成为默认主数据面。
//!
//! 必须实现（M0-9 验收项）：
//! - heartbeat / 自动 reconnect / session resume + peer rebind
//! - 指数退避 + 最大重连时间
//! - 连接迁移后的 packet sequence 处理
//! - 主动断开 100 次自动恢复率验证
//!
//! 帧格式见 schemas/frame/directlink_frame_v1.md（Relay 帧为另一 magic，
//! 含 network_id/source_peer/target_peer/sequence/ciphertext，文档 8.1/14.3）。

pub mod placeholder {
    pub const TASK: &str = "M0-9: WSS 加密帧承载 + 断线恢复率实测";
}
