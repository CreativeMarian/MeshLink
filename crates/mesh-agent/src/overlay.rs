//! Overlay 数据面后端（用户规格七：Wintun 只有 MeshAgentService 能创建和持有）。
//!
//! 两个实现共用同一 trait：
//! - [`WintunOverlay`]：生产路径，包装 [`mesh_vnic::MeshVnic`]（本 crate 是
//!   系统唯一经 MeshVnic 接触 Wintun 的服务层）；
//! - [`MockOverlay`]：自动集成测试 / MVP Gate（用户规格十三）用——模拟 Windows
//!   协议栈行为：注入包若为 ICMP Echo Request 则自动应答（内核语义），
//!   使加密 ping 全链路可在无管理员/无 DLL 环境自动验证。
//!
//! 数据流（规格七）：
//! - 上行：Overlay RX（本机协议栈要发出去的包）→ Noise encrypt → DirectLink；
//! - 下行：DirectLink → Noise decrypt → Overlay TX（注入本机协议栈）。

use mesh_common::{ErrorCode, MeshError};
use std::collections::VecDeque;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// bring_up 输入：Controller IPAM 下发的 Overlay 地址信息（规格六：不硬编码 .2/.3）。
#[derive(Debug, Clone)]
pub struct OverlayConfig {
    pub adapter_name: String,
    /// Wintun tunnel type（与 VnicParams 默认一致）
    pub tunnel_type: String,
    /// 本机 Overlay IPv4（Controller 分配）
    pub local_ip: Ipv4Addr,
    /// 会话独占网段（如 10.88.7.0）
    pub subnet: Ipv4Addr,
    pub prefix: u8,
}

/// Overlay 后端统一接口（Agent 编排层唯一依赖形态）。
pub trait OverlayBackend: Send {
    /// 创建/配置 Overlay 接口 + 本机 IP（幂等：已 up 时返回 Ok）。
    fn bring_up(&mut self, cfg: OverlayConfig) -> Result<(), MeshError>;
    /// 注入一个 L3 包到本机协议栈（下行：Noise 解密后）。
    fn send_packet(&self, pkt: &[u8]) -> Result<(), MeshError>;
    /// 取走本机协议栈要发出的一个 L3 包（上行：加密发送前）；`Ok(None)` = 暂无。
    fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>, MeshError>;
    /// 安装对端 /32 主机路由（规格八：仅对端 Overlay IP，绝不抢默认路由）。
    fn add_peer_route(&mut self, peer: Ipv4Addr) -> Result<(), MeshError>;
    /// 已安装的对端 /32 路由（诊断）。
    fn routes_installed(&self) -> Vec<Ipv4Addr>;
    /// 本机 Overlay IP（未 up = None）。
    fn local_ip(&self) -> Option<Ipv4Addr>;
    /// 拆除接口（回收 /32 路由随 MeshVnic stop 统一完成）。
    fn teardown(&mut self) -> Result<(), MeshError>;
    /// 实现标识（诊断输出："wintun" | "mock"）。
    fn kind(&self) -> &'static str;
}

fn overlay_err(context: &str, e: impl std::fmt::Display) -> MeshError {
    MeshError::new(ErrorCode::VnicOverlaySetupFailed, format!("{context}: {e}"))
}

// ---------------------------------------------------------------------------
// Wintun（生产）
// ---------------------------------------------------------------------------

/// 生产 Overlay：唯一持有 MeshVnic（= Wintun adapter/session）的层。
pub struct WintunOverlay {
    vnic: Option<mesh_vnic::MeshVnic>,
    ip: Option<Ipv4Addr>,
}

impl Default for WintunOverlay {
    fn default() -> Self {
        Self { vnic: None, ip: None }
    }
}

impl WintunOverlay {
    /// 当前 VNIC 只读统计（诊断）。
    pub fn stats(&self) -> Option<mesh_vnic::VnicStats> {
        self.vnic.as_ref().map(|v| v.stats())
    }
}

impl OverlayBackend for WintunOverlay {
    fn bring_up(&mut self, cfg: OverlayConfig) -> Result<(), MeshError> {
        if self.vnic.as_ref().is_some_and(|v| v.is_running()) {
            return Ok(()); // 幂等
        }
        // 与 VnicParams::default() 一致的 ring/queue/超时（config-manager 默认）。
        let vnic_cfg = mesh_vnic::VnicConfig {
            adapter_name: cfg.adapter_name,
            tunnel_type: cfg.tunnel_type,
            ring_capacity: 0x400000,
            virtual_ip: cfg.local_ip,
            prefix_len: cfg.prefix.min(30), // on-link 前缀（/24 会话网段）
            overlay_net: cfg.subnet,
            overlay_prefix: cfg.prefix,
            tx_queue_len: 1024,
            shutdown_timeout: Duration::from_secs(5),
            requested_guid: None, // M0 模式 A（同名复用即 crash recovery）
        };
        let vnic = mesh_vnic::MeshVnic::create(vnic_cfg)
            .map_err(|e| overlay_err("Wintun Overlay 启动失败", e))?;
        self.ip = Some(cfg.local_ip);
        self.vnic = Some(vnic);
        Ok(())
    }

    fn send_packet(&self, pkt: &[u8]) -> Result<(), MeshError> {
        let v = self.vnic.as_ref().ok_or_else(|| {
            MeshError::new(ErrorCode::VnicOverlaySetupFailed, "Overlay 未启动（Wintun）")
        })?;
        v.send(pkt.to_vec()).map_err(|e| overlay_err("Overlay TX 失败", e))
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>, MeshError> {
        let v = self.vnic.as_ref().ok_or_else(|| {
            MeshError::new(ErrorCode::VnicOverlaySetupFailed, "Overlay 未启动（Wintun）")
        })?;
        v.recv_timeout(timeout).map_err(|e| overlay_err("Overlay RX 失败", e))
    }

    fn add_peer_route(&mut self, peer: Ipv4Addr) -> Result<(), MeshError> {
        let v = self.vnic.as_ref().ok_or_else(|| {
            MeshError::new(ErrorCode::VnicOverlaySetupFailed, "Overlay 未启动（Wintun）")
        })?;
        v.add_peer_route(peer).map_err(|e| overlay_err("安装对端 /32 路由失败", e))
    }

    fn routes_installed(&self) -> Vec<Ipv4Addr> {
        self.vnic.as_ref().map(|v| v.installed_peer_routes()).unwrap_or_default()
    }

    fn local_ip(&self) -> Option<Ipv4Addr> {
        self.ip
    }

    fn teardown(&mut self) -> Result<(), MeshError> {
        if let Some(mut v) = self.vnic.take() {
            v.stop().map_err(|e| overlay_err("Wintun Overlay 停止失败", e))?;
        }
        self.ip = None;
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "wintun"
    }
}

// ---------------------------------------------------------------------------
// Mock（自动集成测试 / MVP Gate）
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    up: bool,
    local_ip: Option<Ipv4Addr>,
    subnet: Option<Ipv4Addr>,
    prefix: u8,
    routes: Vec<Ipv4Addr>,
    /// 本机"协议栈"待发出（recv_timeout 取走 → 上行加密）
    outbound: VecDeque<Vec<u8>>,
    /// 已注入本机"协议栈"（send_packet 写入 → 测试断言）
    injected: Vec<Vec<u8>>,
    stats: (u64, u64), // (injected, drained)
}

/// Mock Overlay：模拟 Windows TCP/IP 栈对 Agent 的两个方向。
///
/// - `send_packet`（下行注入）：记录到 `injected`；若为 ICMP Echo Request 且
///   dst == 本机 Overlay IP → 内核语义自动应答（应答进 `outbound`，
///   模拟协议栈主动发包）；
/// - `recv_timeout`（上行取走）：弹出 `outbound`；
/// - 测试通过 [`MockOverlay::inject_outgoing`] 模拟本机应用发起的流量
///   （如 ping 对端），用 [`MockOverlay::take_injected`] 断言注入结果。
pub struct MockOverlay {
    state: Arc<Mutex<MockState>>,
}

impl Default for MockOverlay {
    fn default() -> Self {
        Self { state: Arc::new(Mutex::new(MockState::default())) }
    }
}

impl MockOverlay {
    /// 测试驱动：模拟本机协议栈/应用发出一个 L3 包（对端收方视角 = 加密上行）。
    pub fn inject_outgoing(&self, pkt: Vec<u8>) {
        let mut s = self.state.lock().unwrap();
        if s.up {
            s.outbound.push_back(pkt);
        }
    }

    /// 测试断言：已注入本机协议栈的全部包（按序），取出后清空。
    pub fn take_injected(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.state.lock().unwrap().injected)
    }

    /// Mock 迷你栈是否 up。
    pub fn is_up(&self) -> bool {
        self.state.lock().unwrap().up
    }
}

impl OverlayBackend for MockOverlay {
    fn bring_up(&mut self, cfg: OverlayConfig) -> Result<(), MeshError> {
        let mut s = self.state.lock().unwrap();
        if s.up {
            return Ok(());
        }
        s.up = true;
        s.local_ip = Some(cfg.local_ip);
        s.subnet = Some(cfg.subnet);
        s.prefix = cfg.prefix;
        Ok(())
    }

    fn send_packet(&self, pkt: &[u8]) -> Result<(), MeshError> {
        let mut s = self.state.lock().unwrap();
        if !s.up {
            return Err(MeshError::new(ErrorCode::VnicOverlaySetupFailed, "Overlay 未启动（Mock）"));
        }
        s.injected.push(pkt.to_vec());
        s.stats.0 += 1;
        // 内核语义：任意发给本机 Overlay IP 的 Echo Request → 自动应答
        // （不限 id——用户 ping 与 Agent 冒烟同路径，真实栈行为）
        let local = s.local_ip;
        drop(s);
        if let Some(local_ip) = local {
            let dst = pkt.get(16..20).map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            if dst == Some(local_ip) {
                if let Some(reply) = crate::icmp::kernel_echo_reply_for(pkt) {
                    self.inject_outgoing(reply);
                }
            }
        }
        Ok(())
    }

    fn recv_timeout(&self, timeout: Duration) -> Result<Option<Vec<u8>>, MeshError> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let mut s = self.state.lock().unwrap();
                if !s.up {
                    return Err(MeshError::new(ErrorCode::VnicOverlaySetupFailed, "Overlay 未启动（Mock）"));
                }
                if let Some(pkt) = s.outbound.pop_front() {
                    s.stats.1 += 1;
                    return Ok(Some(pkt));
                }
            }
            if std::time::Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn add_peer_route(&mut self, peer: Ipv4Addr) -> Result<(), MeshError> {
        let mut s = self.state.lock().unwrap();
        if !s.up {
            return Err(MeshError::new(ErrorCode::VnicOverlaySetupFailed, "Overlay 未启动（Mock）"));
        }
        // 规格八策略校验（与 MeshVnic 同口径）：peer 必须在会话网段内
        let (net, prefix) = (s.subnet, s.prefix);
        if let (Some(net), prefix) = (net, prefix) {
            if prefix > 0 {
                let mask = u32::MAX << (32 - prefix.min(32) as u32);
                let in_net = (u32::from(peer) & mask) == (u32::from(net) & mask);
                if !in_net {
                    return Err(MeshError::new(
                        ErrorCode::ConfigInvalid,
                        format!("{peer} 不在 overlay 网段 {net}/{prefix} 内（规格八）"),
                    ));
                }
            }
        }
        if !s.routes.contains(&peer) {
            s.routes.push(peer);
        }
        Ok(())
    }

    fn routes_installed(&self) -> Vec<Ipv4Addr> {
        self.state.lock().unwrap().routes.clone()
    }

    fn local_ip(&self) -> Option<Ipv4Addr> {
        self.state.lock().unwrap().local_ip
    }

    fn teardown(&mut self) -> Result<(), MeshError> {
        let mut s = self.state.lock().unwrap();
        s.up = false;
        s.local_ip = None;
        s.subnet = None;
        s.routes.clear();
        s.outbound.clear();
        s.injected.clear();
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "mock"
    }
}

/// 共享句柄（测试从 Agent 外部驱动 Mock）。
///
/// MockOverlay 内部是 `Arc<Mutex<...>>`，clone 出的句柄指向同一迷你栈；
/// Agent 持有的 trait 对象与测试句柄操作同一状态。
impl Clone for MockOverlay {
    fn clone(&self) -> Self {
        Self { state: Arc::clone(&self.state) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(local: Ipv4Addr) -> OverlayConfig {
        OverlayConfig {
            adapter_name: "MeshLink-Test".into(),
            tunnel_type: "MeshLink".into(),
            local_ip: local,
            subnet: Ipv4Addr::new(10, 88, 7, 0),
            prefix: 24,
        }
    }

    #[test]
    fn mock_lifecycle_route_policy_and_echo_auto_reply() {
        let mut ov = MockOverlay::default();
        assert!(ov.local_ip().is_none());
        ov.bring_up(cfg(Ipv4Addr::new(10, 88, 7, 1))).unwrap();
        assert_eq!(ov.local_ip(), Some(Ipv4Addr::new(10, 88, 7, 1)));

        // 规格八：网段内允许、网段外拒绝
        ov.add_peer_route(Ipv4Addr::new(10, 88, 7, 2)).unwrap();
        assert!(ov.add_peer_route(Ipv4Addr::new(10, 88, 8, 2)).is_err());
        assert_eq!(ov.routes_installed(), vec![Ipv4Addr::new(10, 88, 7, 2)]);

        // 内核语义：Echo Request → 自动应答（等会注入 outbound）
        let req = crate::icmp::echo_request(Ipv4Addr::new(10, 88, 7, 2), Ipv4Addr::new(10, 88, 7, 1));
        ov.send_packet(&req).unwrap();
        let injected = ov.take_injected();
        assert_eq!(injected.len(), 1, "请求必须注入本机栈");
        let got = ov.recv_timeout(Duration::from_millis(200)).unwrap().expect("自动应答必须出现");
        assert!(crate::icmp::is_smoke_reply(&got));

        // 幂等 bring_up / teardown 后收发拒绝
        ov.bring_up(cfg(Ipv4Addr::new(10, 88, 7, 1))).unwrap();
        ov.teardown().unwrap();
        assert!(ov.recv_timeout(Duration::from_millis(10)).is_err());
        assert!(ov.send_packet(&req).is_err());
        assert!(!ov.is_up());
    }

    #[test]
    fn mock_clone_shares_stack() {
        let mut ov = MockOverlay::default();
        ov.bring_up(cfg(Ipv4Addr::new(10, 88, 7, 1))).unwrap();
        let handle = ov.clone();
        handle.inject_outgoing(vec![1, 2, 3]);
        let got = ov.recv_timeout(Duration::from_millis(50)).unwrap();
        assert_eq!(got, Some(vec![1, 2, 3]));
    }
}
