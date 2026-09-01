//! VNIC 错误分类（M0-3 要求十一：禁止所有错误归并成一个笼统 VnicError）。
//!
//! 每个变体映射 mesh-common::ErrorCode（VNic 域 0x0005_xxxx），
//! 上层（mesh-agent / overlay-router / 监控页）可按码值精确处理。

use crate::packet::PacketRejectReason;
use mesh_common::ErrorCode;
use std::fmt;

/// Wintun / IP Helper 的 OS 错误码。
pub type OsError = u32;

#[derive(Debug, Clone)]
pub enum VnicError {
    // ---- DLL 加载 ----
    /// 找不到 wintun.dll（含"cwd 伪 DLL 被拒绝"场景——只搜应用目录与 System32）
    DllNotFound { path: String, os: OsError },
    /// DLL 架构与本进程不符（如 x86 DLL 进 x64 进程，OS 193）
    DllArchitectureMismatch { path: String, os: OsError },
    /// DLL 存在但缺少必需的 Wintun API 符号（伪 DLL / 损坏 DLL）
    ApiSymbolMissing { symbol: &'static str, os: OsError },

    // ---- Adapter ----
    AdapterCreateFailed { os: OsError, reboot_required: bool },
    AdapterOpenFailed { name: String, os: OsError },
    /// 同名 Adapter 冲突（OS ERROR_ALREADY_EXISTS）
    AdapterConflict { name: String },
    /// M0-3.1-1：系统级 Global\Mutex 被另一 MeshAgentService Owner 正常持有
    /// （WaitForSingleObject = WAIT_TIMEOUT）。
    /// 产生本错误前绝不调用 WintunCreateAdapter（并发 CreateAdapter 的 stale handle
    /// 段错误曾导致 Wintun 全局损坏，本错误是那类事故的前置防御）。
    AdapterLockedByOtherProcess { mutex_name: String, holder_pid_guess: Option<u32> },
    /// M0-3.1：Mutex 的显式 DACL（仅 SY/BA）拒绝了本进程 —— 权限不足。
    /// 语义与「被另一进程持锁」不同：普通用户 Create/Open/Wait 均落入本错误。
    /// （注：WAIT_ABANDONED 接管成功不是错误，走 MutexAbandonedRecovered 事件。）
    AdapterMutexAccessDenied { mutex_name: String, os: OsError },
    /// M0-3.1：Mutex Create/Wait 返回 WAIT_FAILED 的其它 Win32 错误（os 携带具体码）。
    AdapterMutexWaitFailed { mutex_name: String, os: OsError },

    // ---- Session ----
    SessionStartFailed { os: OsError },

    // ---- 收发 ----
    /// ReceiveOther：除 NO_MORE_ITEMS / InvalidData 外的接收错误
    ReceiveOther { os: OsError },
    /// size 越界 / 非法包（DLL glitch 或伪造输入，丢弃不退出 worker）
    ReceiveInvalidData,
    SendRingFull,
    SendInvalidPacket,
    SendOther { os: OsError },

    // ---- IP / 路由 ----
    IpConfigurationFailed { ip: String, os: OsError },
    /// IP 已存在（识别为可接受场景的信号，见 ip_config）
    IpAlreadyExists { ip: String },
    RouteConfigurationFailed { os: OsError },
    /// Overlay CIDR 与本机现有网段重叠（M0-3 只检测报告，不自动避让）
    OverlaySubnetConflict { overlay: String, conflicting: Vec<String> },

    // ---- 生命周期 ----
    ShutdownTimeout { waited_ms: u64 },

    // ---- 包校验（drop + metric，不 panic——要求二十） ----
    PacketInvalid { reason: PacketRejectReason },

    // ---- 配置 ----
    RingCapacityInvalid { value: u32, reason: &'static str },
    ConfigInvalid { field: &'static str, reason: String },
}

impl VnicError {
    /// 映射到统一 ErrorCode（跨进程/跨语言稳定）。
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::DllNotFound { .. } => ErrorCode::VnicDllNotFound,
            Self::DllArchitectureMismatch { .. } => ErrorCode::VnicDllArchitectureMismatch,
            Self::ApiSymbolMissing { .. } => ErrorCode::VnicApiSymbolMissing,
            Self::AdapterCreateFailed { .. } => ErrorCode::VnicAdapterCreateFailed,
            Self::AdapterOpenFailed { .. } => ErrorCode::VnicAdapterOpenFailed,
            Self::AdapterConflict { .. } => ErrorCode::VnicAdapterConflict,
            Self::AdapterLockedByOtherProcess { .. } => ErrorCode::VnicAdapterLockedByOtherProcess,
            Self::AdapterMutexAccessDenied { .. } => ErrorCode::VnicAdapterMutexAccessDenied,
            Self::AdapterMutexWaitFailed { .. } => ErrorCode::VnicAdapterMutexWaitFailed,
            Self::SessionStartFailed { .. } => ErrorCode::VnicSessionStartFailed,
            Self::ReceiveOther { .. } => ErrorCode::VnicReceiveFailed,
            Self::ReceiveInvalidData => ErrorCode::VnicPacketInvalid,
            Self::SendRingFull => ErrorCode::VnicSendRingFull,
            Self::SendInvalidPacket => ErrorCode::VnicPacketInvalid,
            Self::SendOther { .. } => ErrorCode::VnicSendFailed,
            Self::IpConfigurationFailed { .. } | Self::IpAlreadyExists { .. } => {
                ErrorCode::VnicIpConfigurationFailed
            }
            Self::RouteConfigurationFailed { .. } => ErrorCode::VnicRouteConfigurationFailed,
            Self::OverlaySubnetConflict { .. } => ErrorCode::VnicSubnetConflict,
            Self::ShutdownTimeout { .. } => ErrorCode::VnicShutdownTimeout,
            Self::PacketInvalid { .. } => ErrorCode::VnicPacketInvalid,
            Self::RingCapacityInvalid { .. } => ErrorCode::VnicRingCapacityInvalid,
            Self::ConfigInvalid { .. } => ErrorCode::ConfigInvalid,
        }
    }
}

impl fmt::Display for VnicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DllNotFound { path, os } => write!(f, "DLL 未找到: {path} (os={os})"),
            Self::DllArchitectureMismatch { path, os } => {
                write!(f, "DLL 架构不匹配: {path} (os={os})")
            }
            Self::ApiSymbolMissing { symbol, .. } => write!(f, "缺少 API 符号: {symbol}"),
            Self::AdapterCreateFailed { os, reboot_required } => {
                write!(f, "Adapter 创建失败 (os={os}, reboot={reboot_required})")
            }
            Self::AdapterOpenFailed { name, os } => write!(f, "Adapter 打开失败: {name} (os={os})"),
            Self::AdapterConflict { name } => write!(f, "Adapter 名称冲突: {name}"),
            Self::AdapterLockedByOtherProcess { mutex_name, holder_pid_guess } => write!(
                f,
                "Adapter 已被另一进程持锁（并发 Create 会导致全局损坏，已拦截）：mutex={mutex_name} holder_pid={}",
                holder_pid_guess.map(|p| p.to_string()).unwrap_or_else(|| "unknown".into())
            ),
            Self::AdapterMutexAccessDenied { mutex_name, os } => write!(
                f,
                "Mutex 访问被显式 DACL 拒绝（仅 LocalSystem/Administrators 可操作）：mutex={mutex_name} os={os}"
            ),
            Self::AdapterMutexWaitFailed { mutex_name, os } => {
                write!(f, "Mutex Create/Wait 失败: mutex={mutex_name} os={os}")
            }
            Self::SessionStartFailed { os } => write!(f, "Session 启动失败 (os={os})"),
            Self::ReceiveOther { os } => write!(f, "接收错误 (os={os})"),
            Self::ReceiveInvalidData => write!(f, "接收包 size 异常（DLL 侧 glitch，已丢弃）"),
            Self::SendRingFull => write!(f, "发送 ring 满（backpressure 丢弃）"),
            Self::SendInvalidPacket => write!(f, "发送包长度非法（> 65535，已拒绝）"),
            Self::SendOther { os } => write!(f, "发送错误 (os={os})"),
            Self::IpConfigurationFailed { ip, os } => {
                write!(f, "IP 配置失败: {ip} (os={os})")
            }
            Self::IpAlreadyExists { ip } => write!(f, "IP 已存在: {ip}"),
            Self::RouteConfigurationFailed { os } => write!(f, "路由配置失败 (os={os})"),
            Self::OverlaySubnetConflict { overlay, conflicting } => {
                write!(f, "Overlay 网段 {overlay} 与本机网段冲突: {conflicting:?}")
            }
            Self::ShutdownTimeout { waited_ms } => {
                write!(f, "Shutdown 超时 (等待 {waited_ms}ms)")
            }
            Self::PacketInvalid { reason } => write!(f, "非法 L3 包: {}", reason.as_str()),
            Self::RingCapacityInvalid { value, reason } => {
                write!(f, "Ring capacity 非法: 0x{value:X} ({reason})")
            }
            Self::ConfigInvalid { field, reason } => {
                write!(f, "配置非法: {field} ({reason})")
            }
        }
    }
}

impl std::error::Error for VnicError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classes_map_to_distinct_codes() {
        let errs = [
            VnicError::DllNotFound { path: "wintun.dll".into(), os: 126 },
            VnicError::DllArchitectureMismatch { path: "wintun.dll".into(), os: 193 },
            VnicError::ApiSymbolMissing { symbol: "WintunCreateAdapter", os: 127 },
            VnicError::AdapterCreateFailed { os: 5, reboot_required: false },
            VnicError::AdapterLockedByOtherProcess { mutex_name: "m".into(), holder_pid_guess: None },
            VnicError::AdapterMutexAccessDenied { mutex_name: "m".into(), os: 5 },
            VnicError::AdapterMutexWaitFailed { mutex_name: "m".into(), os: 87 },
            VnicError::AdapterConflict { name: "MeshLink".into() },
            VnicError::SessionStartFailed { os: 87 },
            VnicError::SendRingFull,
            VnicError::IpConfigurationFailed { ip: "10.70.31.1".into(), os: 5 },
            VnicError::OverlaySubnetConflict {
                overlay: "10.70.31.0/24".into(),
                conflicting: vec!["10.70.31.5/24".into()],
            },
            VnicError::ShutdownTimeout { waited_ms: 5000 },
            VnicError::RingCapacityInvalid { value: 0x300000, reason: "非 2 的幂" },
        ];
        let mut seen = std::collections::HashSet::new();
        for e in &errs {
            assert!(seen.insert(e.code() as u32), "错误类应映射到不同 ErrorCode: {e}");
        }
    }
}
