//! ICE Candidate（RFC 8445 精简）与 Candidate Gathering。
//!
//! M0-4R.1 硬化后的 gathering 范围：
//! - Host candidate：**全部物理/虚拟 IPv4 接口**（经 [`super::ifinfo`] 枚举），
//!   附接口名/index/类型；排除 loopback / unspecified / multicast / broadcast；
//!   **TUN/TAP/Overlay 类硬排除**（含 MeshLink 自有 Wintun，防递归路由）；
//!   VM 类虚拟网卡收录但降权（Physical > srflx > Virtual，§八）。
//!   私网 unicast（10/8、172.16/12、192.168/16）**必须保留**（Same LAN host↔host 依赖）。
//! - Server-reflexive candidate：向 STUN 服务器 Binding 交换取得。
//! - Relay candidate：M0-4 明确不做（无 CF Relay / TURN）。
//! - 同机 loopback 测试不再产出 127.0.0.1 候选（跨机场景对端连自身 socket 的
//!   假成功教训）；本机对连走真实网卡 IP。

use super::ifinfo::list_ipv4_interfaces;
use super::stun::{binding_exchange_with, new_txid, StunError};
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Host,
    ServerReflexive,
    PeerReflexive,
}

/// 单个候选（PoC 只覆盖 IPv4）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub kind: CandidateKind,
    /// 对端可达地址（host 地址 / srflx 反射地址）
    pub addr: SocketAddrV4,
    /// 本地 socket 基地址（host candidate 时 = addr）
    pub base: SocketAddrV4,
    /// M0-4R.1 §六：来源接口 index（srflx/未知 = 0）
    pub if_index: u32,
    /// M0-4R.1 §六：来源接口描述（如 "Intel(R) Wi-Fi 6"；未知 = 空）
    pub if_name: String,
    /// M0-4R.1 §六：接口大类（Ethernet/Wi-Fi/Virtual/Other；未知 = 空）
    pub iface_kind: String,
    /// M0-4R.1 §六：是否虚拟接口（影响 priority 降权）
    pub is_virtual: bool,
}

impl Candidate {
    pub fn host(addr: SocketAddrV4) -> Self {
        Self { kind: CandidateKind::Host, addr, base: addr, if_index: 0, if_name: String::new(), iface_kind: String::new(), is_virtual: false }
    }

    pub fn srflx(addr: SocketAddrV4, base: SocketAddrV4) -> Self {
        Self { kind: CandidateKind::ServerReflexive, addr, base, if_index: 0, if_name: String::new(), iface_kind: String::new(), is_virtual: false }
    }

    /// RFC 8445 §5.1.2.1 精简优先级，叠加 M0-4R.1 §八 虚拟接口降权：
    /// Physical host(126) > prflx(110) > srflx(100) > **Virtual host(80)**。
    pub fn priority(&self) -> u32 {
        let type_pref: u32 = match (self.kind, self.is_virtual) {
            (CandidateKind::Host, false) => 126,
            (CandidateKind::Host, true) => 80,
            (CandidateKind::ServerReflexive, _) => 100,
            (CandidateKind::PeerReflexive, _) => 110,
        };
        (type_pref << 24) | (65535 << 8) | (256 - 1)
    }

    /// 候选展示串（候选 trace 日志用）：`ip:port [Wi-Fi:desc]`。
    pub fn display(&self) -> String {
        if self.if_name.is_empty() {
            format!("{}:{}", self.addr.ip(), self.addr.port())
        } else {
            format!("{}:{} [{}:{}]", self.addr.ip(), self.addr.port(), self.iface_kind, self.if_name)
        }
    }
}

/// Gathering 出错。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatherError {
    #[error("socket bind/listen 失败: {0}")]
    Socket(String),
    #[error("STUN 交换失败: {0:?}")]
    Stun(StunError),
    #[error("未取得任何可用 host candidate")]
    NoCandidates,
}

impl From<StunError> for GatherError {
    fn from(e: StunError) -> Self {
        Self::Stun(e)
    }
}

/// 枚举本机主出口 IPv4 地址（UDP connect-trick：不发包，仅查路由选择结果）。
/// 直连公网失败时回退到 LAN 网关探测地址（10.255.255.255 不可达同样只查路由表）。
pub fn primary_local_ipv4() -> Option<Ipv4Addr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    for probe in ["8.8.8.8:80", "192.168.255.255:9", "10.255.255.255:9"] {
        if sock.connect(probe).is_ok() {
            if let Ok(local) = sock.local_addr() {
                if let SocketAddr::V4(v4) = local {
                    if !v4.ip().is_unspecified() {
                        return Some(*v4.ip());
                    }
                }
            }
        }
    }
    None
}

/// 创建打洞 socket 并产出 host candidate 列表（`port=0` 时自动用实际绑定端口）。
///
/// 端口复用是打洞关键：host candidate 与后续 connectivity check 必须
/// 共用同一个本地端口（NAT 映射按五元组分配）。
///
/// M0-4R.1：多接口枚举 + 安全过滤 + 排序（Physical > Virtual；TUN 类硬排除）。
pub fn gather_host_candidates(port: u16) -> Result<(UdpSocket, Vec<Candidate>), GatherError> {
    let sock = UdpSocket::bind(("0.0.0.0", port)).map_err(|e| GatherError::Socket(e.to_string()))?;
    sock.set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|e| GatherError::Socket(e.to_string()))?;
    // 候选地址必须是 socket 实际绑定端口（port=0 时由 OS 分配；
    // 通告 port 0 的候选对端不可达，打洞必然失败）
    let bound = sock.local_addr().map_err(|e| GatherError::Socket(e.to_string()))?.port();

    let mut cands: Vec<Candidate> = Vec::new();
    for ifc in list_ipv4_interfaces() {
        // TUN/TAP/Overlay 硬排除（MeshLink 自有 Wintun 双保险关键词）
        if ifc.is_tun_class() {
            continue;
        }
        if !ifc.oper_up {
            continue;
        }
        let ip = ifc.ip;
        // 只拒绝 loopback / unspecified / multicast / broadcast；私网 unicast 保留
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            continue;
        }
        cands.push(Candidate {
            kind: CandidateKind::Host,
            addr: SocketAddrV4::new(ip, bound),
            base: SocketAddrV4::new(ip, bound),
            if_index: ifc.index,
            if_name: ifc.descr.clone(),
            iface_kind: ifc.kind.as_str().to_string(),
            is_virtual: ifc.kind.is_virtual(),
        });
    }
    if cands.is_empty() {
        // 兜底：ifinfo 枚举失败（API 异常）时用 connect-trick 主出口 IP
        if let Some(ip) = primary_local_ipv4() {
            cands.push(Candidate::host(SocketAddrV4::new(ip, bound)));
        }
    }
    // 排序：物理 Ethernet/WiFi → 其他物理 → 虚拟（punch 尝试顺序与之对齐）
    cands.sort_by_key(|c| {
        let phys = if c.is_virtual { 2u8 } else { match c.iface_kind.as_str() { "Ethernet" | "Wi-Fi" => 0, "" => 1, _ => 1 } };
        phys
    });
    Ok((sock, cands))
}

/// 向 STUN 服务器发起 Binding 交换，取得 server-reflexive candidate。
///
/// `send`/`recv`（recvfrom 语义）注入与 [`binding_exchange_with`] 相同：
/// 打洞 socket 复用同一本地端口，混入流量按噪音忽略。
pub fn gather_srflx<F, G>(
    base: SocketAddrV4,
    server: SocketAddrV4,
    send: F,
    recv: G,
    rto: Duration,
    retries: u32,
) -> Result<Candidate, GatherError>
where
    F: FnMut(&[u8]) -> std::io::Result<usize>,
    G: FnMut(Duration) -> Option<(SocketAddrV4, Vec<u8>)>,
{
    let result = binding_exchange_with(new_txid(), server, send, recv, rto, retries)?;
    Ok(Candidate::srflx(result.mapped, base))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_priority_gt_srflx() {
        let h = Candidate::host(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 40000));
        let s = Candidate::srflx(
            SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 40000),
            SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 40000),
        );
        assert!(h.priority() > s.priority(), "host 必须优先于 srflx（RFC 8445 type preference）");
        assert_eq!(h.base, h.addr);
        assert_eq!(s.base, h.addr, "srflx base 必须是本地 socket 地址");
    }

    #[test]
    fn primary_local_ipv4_returns_something() {
        // 开发机必有回退路径；只验证不 panic 且不是 0.0.0.0
        if let Some(ip) = primary_local_ipv4() {
            assert!(!ip.is_unspecified());
        }
    }

    #[test]
    fn srflx_gather_via_injected_io() {
        use std::cell::RefCell;

        let base = SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 5), 40000);
        let server = SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 3478);
        // 假 STUN：从请求中取出真实 txid，回 XOR-MAPPED = 5.6.7.8:61000
        // （binding_exchange_with 会按 txid 匹配响应，假 server 必须回真实 txid）
        let resp: RefCell<Option<Vec<u8>>> = RefCell::new(None);
        let c = gather_srflx(
            base,
            server,
            |req| {
                let req = crate::ice::stun::StunMessage::decode(req).unwrap();
                let reply = crate::ice::stun::StunMessage {
                    msg_type: crate::ice::stun::BINDING_RESPONSE,
                    txid: req.txid,
                    attrs: vec![crate::ice::stun::StunAttr::XorMapped(SocketAddrV4::new(
                        Ipv4Addr::new(5, 6, 7, 8),
                        61000,
                    ))],
                }
                .encode();
                let n = reply.len();
                *resp.borrow_mut() = Some(reply);
                Ok(n)
            },
            |_| resp.borrow().clone().map(|b| (server, b)),
            Duration::from_millis(5),
            1,
        )
        .expect("注入式 srflx gathering 必须成功");
        assert_eq!(c.kind, CandidateKind::ServerReflexive);
        assert_eq!(c.addr, SocketAddrV4::new(Ipv4Addr::new(5, 6, 7, 8), 61000));
    }
}
