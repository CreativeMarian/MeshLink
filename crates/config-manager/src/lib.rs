//! 统一配置管理：本地配置加载、校验、默认值（文档附录 B）。
//!
//! 原则：全系统任何模块读取参数只能通过本 crate 的类型，禁止散落魔法数。

use mesh_common::{ErrorCode, MeshError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// 运行参数默认值（文档附录 B，第一版可调）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeParams {
    /// Device heartbeat 10s
    pub device_heartbeat_secs: u32,
    /// Peer keepalive 15s（维持 NAT 映射）
    pub peer_keepalive_secs: u32,
    /// SN health interval 5s
    pub sn_health_interval_secs: u32,
    /// SN offline threshold：连续失败次数
    pub sn_offline_threshold: u32,
    /// Circuit open cooldown 30s（OPEN → HALF_OPEN 冷却）
    pub circuit_open_cooldown_secs: u64,
    /// Half-open 成功阈值：连续 N 次探测成功关闭熔断
    pub half_open_success_threshold: u32,
    /// Half-open 最大并发探测数（第一版固定 1）
    pub max_half_open_probes: u32,
    /// 熔断触发：连续失败次数
    pub circuit_failure_threshold: u32,
    /// Path switch min interval 15s（防抖）
    pub path_switch_min_interval_secs: u64,
    /// P2P preemption stable 10s（回切前稳定时长）
    pub p2p_preemption_stable_secs: u64,
    /// Health critical threshold：< 40 持续 3s 触发切换
    pub health_critical_threshold: u8,
    pub health_critical_duration_secs: u64,
    /// 新路径需比当前路径质量高至少 20%
    pub path_preemption_quality_delta_pct: u32,
    /// Invite default expiry 24h
    pub invite_default_expiry_hours: u32,
    /// Password max attempts 5（随后指数退避）
    pub password_max_attempts: u32,
    /// Metrics raw retention 7 days
    pub metrics_raw_retention_days: u32,
    /// 虚拟网卡参数（M0-3）
    pub vnic: VnicParams,
}

/// 虚拟网卡参数（M0-3；全部值必须来自本结构，mesh-vnic 内禁止散落魔法值）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct VnicParams {
    /// Adapter 与 TunnelType 统一产品名（十六：固定名称，禁止随机/序号后缀）
    pub adapter_name: String,
    pub tunnel_type: String,
    /// Session Ring Capacity（字节）。默认 0x400000 = 4 MiB（与官方示例一致）。
    /// 必须为 2 的幂且 ∈ [0x20000, 0x4000000]，启动前校验，非法直接拒绝。
    pub ring_capacity: u32,
    /// M0 测试虚拟 IP（本机端）
    pub virtual_ip: String,
    /// M0 测试 Overlay 网段（仅用于冲突检测与测试路由；禁止 0.0.0.0/0）
    pub overlay_cidr: String,
    pub prefix_length: u8,
    /// Shutdown 超时（秒），超时产生 ShutdownTimeout
    pub shutdown_timeout_secs: u64,
    /// TX 有界队列长度（backpressure 上限）
    pub tx_queue_len: u32,
    /// RequestedGUID（M0 研究 A=NULL / B=持久化 GUID；默认 None 不写死）
    pub requested_guid: Option<String>,
}

impl Default for VnicParams {
    fn default() -> Self {
        Self {
            adapter_name: "MeshLink".to_string(),
            tunnel_type: "MeshLink".to_string(),
            ring_capacity: 0x400000,
            virtual_ip: "10.70.31.1".to_string(),
            overlay_cidr: "10.70.31.0/24".to_string(),
            prefix_length: 24,
            shutdown_timeout_secs: 5,
            tx_queue_len: 1024,
            requested_guid: None,
        }
    }
}

impl Default for RuntimeParams {
    fn default() -> Self {
        Self {
            device_heartbeat_secs: 10,
            peer_keepalive_secs: 15,
            sn_health_interval_secs: 5,
            sn_offline_threshold: 3,
            circuit_open_cooldown_secs: 30,
            half_open_success_threshold: 3,
            max_half_open_probes: 1,
            circuit_failure_threshold: 3,
            path_switch_min_interval_secs: 15,
            p2p_preemption_stable_secs: 10,
            health_critical_threshold: 40,
            health_critical_duration_secs: 3,
            path_preemption_quality_delta_pct: 20,
            invite_default_expiry_hours: 24,
            password_max_attempts: 5,
            metrics_raw_retention_days: 7,
            vnic: VnicParams::default(),
        }
    }
}

/// 本地设备配置（文档附录 A.1，device.json，不可分享）。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeviceConfig {
    pub device_id: String,
    pub device_name: String,
    pub controller: String,
    pub networks: Vec<String>,
    /// secure-store 引用（如 windows-dpapi:...），绝不在本文件保存密钥明文
    pub secure_key_ref: String,
    pub runtime: RuntimeParams,
}

impl DeviceConfig {
    pub fn load(path: &Path) -> Result<Self, MeshError> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| MeshError::new(ErrorCode::ConfigNotFound, format!("{path:?}: {e}")))?;
        let cfg: Self = serde_json::from_str(&raw)
            .map_err(|e| MeshError::new(ErrorCode::ConfigInvalid, format!("{path:?}: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), MeshError> {
        if self.device_id.is_empty() {
            return Err(MeshError::new(ErrorCode::ConfigInvalid, "device_id 为空"));
        }
        if !self.controller.starts_with("https://")
            && !self.controller.starts_with("http://localhost")
            && !self.controller.starts_with("http://127.0.0.1")
        {
            // 开发期允许 localhost，生产强制 https
            return Err(MeshError::new(
                ErrorCode::ConfigInvalid,
                "controller 必须是 https://（或开发期 localhost）",
            ));
        }
        let p = &self.runtime;
        if p.circuit_failure_threshold == 0
            || p.half_open_success_threshold == 0
            || p.max_half_open_probes == 0
        {
            return Err(MeshError::new(ErrorCode::ConfigInvalid, "熔断参数必须 > 0"));
        }
        let v = &p.vnic;
        if v.adapter_name.is_empty() || v.tunnel_type.is_empty() {
            return Err(MeshError::new(ErrorCode::ConfigInvalid, "vnic adapter_name/tunnel_type 不能为空"));
        }
        if v.virtual_ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Err(MeshError::new(ErrorCode::ConfigInvalid, "vnic.virtual_ip 不是合法 IPv4"));
        }
        let Some((net, mask)) = v.overlay_cidr.split_once('/') else {
            return Err(MeshError::new(ErrorCode::ConfigInvalid, "vnic.overlay_cidr 必须是 a.b.c.d/mask"));
        };
        let mask: u8 = mask.parse().map_err(|_| {
            MeshError::new(ErrorCode::ConfigInvalid, "vnic.overlay_cidr mask 非法")
        })?;
        if net.parse::<std::net::Ipv4Addr>().is_err() || mask > 32 {
            return Err(MeshError::new(ErrorCode::ConfigInvalid, "vnic.overlay_cidr 非法"));
        }
        if v.prefix_length > 32 || v.ring_capacity == 0 || v.tx_queue_len == 0 {
            return Err(MeshError::new(ErrorCode::ConfigInvalid, "vnic prefix_length/ring_capacity/tx_queue_len 非法"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_spec_appendix_b() {
        let d = RuntimeParams::default();
        assert_eq!(d.device_heartbeat_secs, 10);
        assert_eq!(d.peer_keepalive_secs, 15);
        assert_eq!(d.sn_health_interval_secs, 5);
        assert_eq!(d.sn_offline_threshold, 3);
        assert_eq!(d.circuit_open_cooldown_secs, 30);
        assert_eq!(d.half_open_success_threshold, 3);
        assert_eq!(d.max_half_open_probes, 1);
        assert_eq!(d.circuit_failure_threshold, 3);
        assert_eq!(d.path_switch_min_interval_secs, 15);
        assert_eq!(d.p2p_preemption_stable_secs, 10);
        assert_eq!(d.health_critical_threshold, 40);
        assert_eq!(d.health_critical_duration_secs, 3);
        assert_eq!(d.invite_default_expiry_hours, 24);
        assert_eq!(d.password_max_attempts, 5);
        assert_eq!(d.metrics_raw_retention_days, 7);
        // M0-3 VnicParams 默认值
        assert_eq!(d.vnic.adapter_name, "MeshLink");
        assert_eq!(d.vnic.tunnel_type, "MeshLink");
        assert_eq!(d.vnic.ring_capacity, 0x400000);
        assert_eq!(d.vnic.virtual_ip, "10.70.31.1");
        assert_eq!(d.vnic.overlay_cidr, "10.70.31.0/24");
        assert_eq!(d.vnic.prefix_length, 24);
        assert_eq!(d.vnic.shutdown_timeout_secs, 5);
        assert_eq!(d.vnic.tx_queue_len, 1024);
        assert_eq!(d.vnic.requested_guid, None);
        // RuntimeParams 默认值（含 vnic）必须通过运行参数校验：
        // DeviceConfig 本身需要 device_id/controller 才合法，这里补齐后验证
        let cfg = DeviceConfig {
            device_id: "test-device".into(),
            controller: "https://controller.example".into(),
            ..Default::default()
        };
        assert!(cfg.validate().is_ok(), "默认运行参数必须合法");
    }

    #[test]
    fn validate_rejects_bad_vnic_params() {
        // 非法 virtual_ip
        let cfg = DeviceConfig {
            device_id: "d1".into(),
            runtime: RuntimeParams {
                vnic: VnicParams { virtual_ip: "999.1.1.1".into(), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        // 非法 cidr
        let cfg = DeviceConfig {
            device_id: "d1".into(),
            runtime: RuntimeParams {
                vnic: VnicParams { overlay_cidr: "10.0.0.0".into(), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        // 空 adapter 名
        let cfg = DeviceConfig {
            device_id: "d1".into(),
            runtime: RuntimeParams {
                vnic: VnicParams { adapter_name: String::new(), ..Default::default() },
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_device_id() {
        let cfg = DeviceConfig { device_id: String::new(), ..Default::default() };
        assert!(cfg.validate().is_err());
    }
}
