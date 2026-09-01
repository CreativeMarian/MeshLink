//! 统一错误码体系。
//!
//! 编码规则：`0x{category:02X}_{index:04X}`
//! - category: 错误域（Transport/Crypto/Config/Controller/VNic/Policy/Internal）
//! - index: 域内序号
//!
//! 新增错误码只能追加，不能修改已有码值（跨组件稳定性契约）。

use std::fmt;

/// 稳定错误码。`u32` 值跨进程/跨语言（Go Controller、schema）保持一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum ErrorCode {
    // ---- 0x01 Transport（传输层） ----
    TransportStartFailed     = 0x0001_0001,
    TransportStopFailed      = 0x0001_0002,
    TransportPeerUnreachable = 0x0001_0003,
    TransportSendFailed      = 0x0001_0004,
    TransportTimeout         = 0x0001_0005,
    TransportFatal           = 0x0001_0006, // 触发 Provider 级 Hard Failure 熔断
    // M1-2 N2N 追加（新增只能在尾部，不改已有码值稳定契约）：
    /// 所有 N2N Supernode 熔断/不可达
    N2NSupernodeUnavailable = 0x0001_0007,
    /// Supernode 未发现对端（peer 离线或不在同一社区）
    N2NPeerNotFound         = 0x0001_0008,

    // ---- 0x02 Crypto（加密会话） ----
    CryptoHandshakeFailed = 0x0002_0001,
    CryptoDecryptFailed   = 0x0002_0002,
    CryptoReplayRejected  = 0x0002_0003,
    CryptoKeyMismatch     = 0x0002_0004, // 对端静态公钥与注册表不符
    CryptoEpochInvalid    = 0x0002_0005, // epoch 过期/未知
    // M1-2 N2N 追加：Noise 通道尚未建立（N2N relay 路径数据面未就绪）
    NoiseNotEstablished   = 0x0002_0006,

    // ---- 0x03 Config（配置） ----
    ConfigInvalid  = 0x0003_0001,
    ConfigNotFound = 0x0003_0002,

    // ---- 0x04 Controller（控制面） ----
    ControllerUnreachable = 0x0004_0001,
    ControllerAuthFailed  = 0x0004_0002,
    ControllerProtocol    = 0x0004_0003,

    // ---- 0x05 VNic（虚拟网卡） ----
    VnicOpenFailed = 0x0005_0001,
    VnicIoFailed   = 0x0005_0002,
    // M0-3 追加（追加不改已有码值）：
    // -- DLL 加载 --
    VnicDllNotFound              = 0x0005_0003,
    VnicDllHashMismatch          = 0x0005_0004,
    VnicDllArchitectureMismatch  = 0x0005_0005,
    VnicApiSymbolMissing         = 0x0005_0006,
    // -- Adapter --
    VnicAdapterCreateFailed      = 0x0005_0007,
    VnicAdapterOpenFailed        = 0x0005_0008,
    VnicAdapterConflict          = 0x0005_0009,
    // -- Session --
    VnicSessionStartFailed       = 0x0005_000A,
    // -- 收发 --
    VnicReceiveFailed            = 0x0005_000B, // ReceiveOther（NoMoreItems/EOF/InvalidData 走 details）
    VnicSendFailed               = 0x0005_000C,
    VnicSendRingFull             = 0x0005_000D, // TX backpressure：ring/queue 满（drop 计数）
    // -- IP / 路由 --
    VnicIpConfigurationFailed    = 0x0005_000E,
    VnicRouteConfigurationFailed = 0x0005_000F,
    VnicSubnetConflict           = 0x0005_0010, // OverlaySubnetConflict：检测到网段重叠
    // -- 生命周期 --
    VnicShutdownTimeout          = 0x0005_0011,
    VnicRingCapacityInvalid      = 0x0005_0012, // 非 2 的幂 / 越界，启动前拒绝
    VnicPacketInvalid            = 0x0005_0013, // 非法 L3 包（drop + metric，不 panic）
    // M0-3.1 追加（新增只能在尾部，不改已有码值稳定契约）：
    /// 另一进程（MeshAgentService 或非法用户）已持 Global\Mutex。
    /// 调用方不应再调用 WintunCreateAdapter；必须先退出或等待 Owner 释放。
    VnicAdapterLockedByOtherProcess = 0x0005_0014,
    /// M0-3.1：命名 Mutex 的显式 DACL（SY/BA only）拒绝了本进程 —— 语义与
    /// 「被另一进程正常持锁」不同：前者是权限不足，后者是资源占用。
    VnicAdapterMutexAccessDenied   = 0x0005_0015,
    /// M0-3.1：CreateMutexW / WaitForSingleObject 返回 WAIT_FAILED 的其它 Win32 错误。
    VnicAdapterMutexWaitFailed     = 0x0005_0016,
    /// Overlay MVP：Agent 侧 Overlay 数据面（Wintun/Mock）启动或读写失败。
    VnicOverlaySetupFailed         = 0x0005_0017,

    // ---- 0x06 Policy（策略/路径） ----
    PolicyNoPathAvailable = 0x0006_0001,

    // ---- 0x0F Internal ----
    Internal = 0x000F_0001,
}

impl ErrorCode {
    /// 面向用户的文案：不泄露底层参数、进程名、地址等细节。
    pub fn user_message(self) -> &'static str {
        match self {
            Self::TransportStartFailed | Self::TransportStopFailed => "网络组件启动/停止失败，请查看日志",
            Self::TransportPeerUnreachable => "暂时无法连接对方设备",
            Self::TransportSendFailed | Self::TransportTimeout => "数据发送失败或超时",
            Self::TransportFatal => "网络组件发生严重错误",
            Self::N2NSupernodeUnavailable => "中继服务器暂不可用",
            Self::N2NPeerNotFound => "未找到对方设备（可能离线）",
            Self::CryptoHandshakeFailed => "与对方建立安全通道失败",
            Self::CryptoDecryptFailed => "收到无法校验的数据",
            Self::CryptoReplayRejected => "检测到异常数据包并已拦截",
            Self::CryptoKeyMismatch => "对方设备身份校验失败",
            Self::CryptoEpochInvalid => "安全会话已过期",
            Self::NoiseNotEstablished => "安全通道尚未建立",
            Self::ConfigInvalid => "配置文件不合法",
            Self::ConfigNotFound => "配置文件不存在",
            Self::ControllerUnreachable => "无法连接管理服务器",
            Self::ControllerAuthFailed => "身份认证失败",
            Self::ControllerProtocol => "与管理服务器的通信出现异常",
            Self::VnicOpenFailed => "虚拟网卡创建失败，请检查驱动安装",
            Self::VnicIoFailed => "虚拟网卡读写异常",
            Self::VnicDllNotFound | Self::VnicDllHashMismatch
            | Self::VnicDllArchitectureMismatch | Self::VnicApiSymbolMissing => {
                "虚拟网卡驱动组件缺失或损坏，请重新安装"
            }
            Self::VnicAdapterCreateFailed | Self::VnicAdapterOpenFailed
            | Self::VnicAdapterConflict => "虚拟网卡创建失败，请检查管理员权限",
            Self::VnicSessionStartFailed => "虚拟网卡会话启动失败",
            Self::VnicReceiveFailed => "虚拟网卡接收数据异常",
            Self::VnicSendFailed | Self::VnicSendRingFull => "虚拟网卡发送繁忙或失败",
            Self::VnicIpConfigurationFailed | Self::VnicRouteConfigurationFailed => {
                "虚拟网络地址配置失败，请检查管理员权限"
            }
            Self::VnicSubnetConflict => "虚拟网段与本机现有网络冲突，请修改网段配置",
            Self::VnicShutdownTimeout => "虚拟网卡停止超时",
            Self::VnicRingCapacityInvalid => "虚拟网卡缓冲区配置非法",
            Self::VnicPacketInvalid => "收到非法数据包并已丢弃",
            Self::VnicAdapterLockedByOtherProcess => "虚拟网卡已被另一个 MeshAgent 服务实例占用，请关闭另一实例后重试",
            Self::VnicAdapterMutexAccessDenied => "当前用户无权操作虚拟网卡，请以管理员身份运行",
            Self::VnicAdapterMutexWaitFailed => "虚拟网卡互斥等待失败，请查看日志",
            Self::VnicOverlaySetupFailed => "虚拟网络数据面启动或读写失败",
            Self::PolicyNoPathAvailable => "当前没有可用网络路径",
            Self::Internal => "内部错误，请查看日志",
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "E{:04X}", *self as u32)
    }
}

/// 统一错误类型。
#[derive(Debug, Clone, thiserror::Error)]
#[error("{code} {code:?}: {details}")]
pub struct MeshError {
    pub code: ErrorCode,
    pub details: String,
}

impl MeshError {
    pub fn new(code: ErrorCode, details: impl Into<String>) -> Self {
        Self { code, details: details.into() }
    }
}

impl From<ErrorCode> for MeshError {
    fn from(code: ErrorCode) -> Self {
        Self { code, details: String::new() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_unique() {
        let codes = [
            ErrorCode::TransportStartFailed,
            ErrorCode::TransportStopFailed,
            ErrorCode::TransportPeerUnreachable,
            ErrorCode::TransportSendFailed,
            ErrorCode::TransportTimeout,
            ErrorCode::TransportFatal,
            ErrorCode::CryptoHandshakeFailed,
            ErrorCode::CryptoDecryptFailed,
            ErrorCode::CryptoReplayRejected,
            ErrorCode::CryptoKeyMismatch,
            ErrorCode::CryptoEpochInvalid,
            ErrorCode::ConfigInvalid,
            ErrorCode::ConfigNotFound,
            ErrorCode::ControllerUnreachable,
            ErrorCode::ControllerAuthFailed,
            ErrorCode::ControllerProtocol,
            ErrorCode::VnicOpenFailed,
            ErrorCode::VnicIoFailed,
            ErrorCode::VnicDllNotFound,
            ErrorCode::VnicDllHashMismatch,
            ErrorCode::VnicDllArchitectureMismatch,
            ErrorCode::VnicApiSymbolMissing,
            ErrorCode::VnicAdapterCreateFailed,
            ErrorCode::VnicAdapterOpenFailed,
            ErrorCode::VnicAdapterConflict,
            ErrorCode::VnicSessionStartFailed,
            ErrorCode::VnicReceiveFailed,
            ErrorCode::VnicSendFailed,
            ErrorCode::VnicSendRingFull,
            ErrorCode::VnicIpConfigurationFailed,
            ErrorCode::VnicRouteConfigurationFailed,
            ErrorCode::VnicSubnetConflict,
            ErrorCode::VnicShutdownTimeout,
            ErrorCode::VnicRingCapacityInvalid,
            ErrorCode::VnicPacketInvalid,
            ErrorCode::VnicAdapterLockedByOtherProcess,
            ErrorCode::VnicAdapterMutexAccessDenied,
            ErrorCode::VnicAdapterMutexWaitFailed,
            ErrorCode::VnicOverlaySetupFailed,
            ErrorCode::PolicyNoPathAvailable,
            ErrorCode::Internal,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in codes {
            assert!(seen.insert(c as u32), "重复错误码: {c}");
        }
    }

    #[test]
    fn user_message_never_equals_debug() {
        // 用户文案不应包含底层细节（如进程名/地址）——最小约束：非空且非空串
        for c in [ErrorCode::TransportFatal, ErrorCode::VnicOpenFailed] {
            assert!(!c.user_message().is_empty());
        }
    }
}
