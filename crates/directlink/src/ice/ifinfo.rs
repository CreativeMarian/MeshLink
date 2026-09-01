//! 网络接口信息（M0-4R.1 §六七八）。
//!
//! 用 IP Helper（GetIpAddrTable + GetIfEntry）枚举本机 IPv4 接口，为 host
//! candidate 附加 interface_name / if_index / interface_type / is_virtual。
//!
//! 分层策略（M0-4R.1 用户确认）：
//! - **收录但降权**：VM 类虚拟网卡（VMware/Hyper-V/VirtualBox/WSL/Docker）——
//!   桥接模拟、容器网络是合法测试路径，但优先级必须低于物理网卡与 srflx。
//! - **硬排除**：TUN/TAP 类（Wintun/TAP/Tailscale/Tunnel）——底层 P2P 不可能
//!   走 Overlay 隧道，且 **MeshLink 自有 Wintun（Overlay VNIC）必须排除**，
//!   否则正式程序会拿 Overlay IP 当底层 P2P candidate 形成递归路由。
//!   判定关键词含 "meshlink" 双保险。
//! - **保留**：私网 unicast（10/8、172.16/12、192.168/16）——Same LAN
//!   host↔host 必需；只拒绝 loopback/unspecified/multicast/broadcast。
//!
//! ABI 注意（沿用 M0-3 布局断言纪律）：MIB_IFROW / MIB_IPADDRROW 按
//! iprtrmib.h 字段序手写；MIB_IFROW.wszName 为 [u16; 256]
//! （MAX_INTERFACE_NAME_LEN=256），bPhysAddr 为 [u8; 8]（MAXLEN_PHYSADDR）。

#![allow(non_snake_case)]

use std::net::Ipv4Addr;

/// 接口大类（对外用字符串表示，进 JSON 报告）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IfaceKind {
    Ethernet,
    WiFi,
    Virtual(VirtualKind),
    Other,
}

impl IfaceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            IfaceKind::Ethernet => "Ethernet",
            IfaceKind::WiFi => "Wi-Fi",
            IfaceKind::Virtual(_) => "Virtual",
            IfaceKind::Other => "Other",
        }
    }

    pub fn is_virtual(&self) -> bool {
        matches!(self, IfaceKind::Virtual(_))
    }
}

/// 虚拟接口细分（报告/诊断用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualKind {
    Vmware,
    HyperV,
    VirtualBox,
    Wsl,
    Docker,
    Tailscale,
    Wintun,
    Tap,
    Tunnel,
    UnknownVirtual,
}

/// 单个 IPv4 接口信息（GetIpAddrTable 地址 × GetIfEntry 属性 join）。
#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub index: u32,
    pub descr: String,
    pub if_type: u32,
    pub oper_up: bool,
    pub ip: Ipv4Addr,
    pub kind: IfaceKind,
}

impl IfaceInfo {
    /// 是否为 TUN/TAP/Overlay 类（必须从 candidate gathering 排除）。
    pub fn is_tun_class(&self) -> bool {
        matches!(self.kind, IfaceKind::Virtual(VirtualKind::Wintun | VirtualKind::Tap | VirtualKind::Tailscale | VirtualKind::Tunnel))
            || self.descr.to_lowercase().contains("meshlink")
    }

    /// 排序权重：Ethernet/WiFi 物理 = 0，其他物理 = 1，虚拟 = 2。
    pub fn physical_rank(&self) -> u8 {
        match self.kind {
            IfaceKind::Ethernet | IfaceKind::WiFi => 0,
            IfaceKind::Other => 1,
            IfaceKind::Virtual(_) => 2,
        }
    }
}

const MAXLEN_PHYSADDR: usize = 8;
const MAXLEN_IFDESCR: usize = 256;
const MAX_INTERFACE_NAME_LEN: usize = 256;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const NO_ERROR: u32 = 0;
/// INTERNAL_IF_OPER_STATUS（iprtrmib.h）：CONNECTED=4 / OPERATIONAL=5。
/// GetIfEntry 对可用接口（含 loopback）通常返回 OPERATIONAL(5)。
const IF_OPER_STATUS_CONNECTED: u32 = 4;
const IF_OPER_STATUS_OPERATIONAL: u32 = 5;

#[repr(C)]
struct MIB_IPADDRROW {
    dwAddr: u32,
    dwIndex: u32,
    dwMask: u32,
    dwBCastAddr: u32,
    dwReasmSize: u32,
    unused1: u16,
    unused2: u16,
}

#[repr(C)]
struct MIB_IPADDRTABLE {
    dwNumEntries: u32,
    table: [MIB_IPADDRROW; 1], // ANY_SIZE：实际按 dwNumEntries 容量读取
}

#[repr(C)]
struct MIB_IFROW {
    wszName: [u16; MAX_INTERFACE_NAME_LEN],
    dwIndex: u32,
    dwType: u32,
    dwMtu: u32,
    dwSpeed: u32,
    dwPhysAddrLen: u32,
    bPhysAddr: [u8; MAXLEN_PHYSADDR],
    dwAdminStatus: u32,
    dwOperStatus: u32,
    dwLastChange: u32,
    dwInOctets: u32,
    dwInUcastPkts: u32,
    dwInNUcastPkts: u32,
    dwInDiscards: u32,
    dwInErrors: u32,
    dwInUnknownProtos: u32,
    dwOutOctets: u32,
    dwOutUcastPkts: u32,
    dwOutNUcastPkts: u32,
    dwOutDiscards: u32,
    dwOutErrors: u32,
    dwOutQLen: u32,
    dwDescrLen: u32, // 描述长度在前
    bDescr: [u8; MAXLEN_IFDESCR], // 内联 ANSI 描述（不是指针！）
}
// x64/x86 同值：512 wszName + 8 bPhysAddr + 21×4 DWORD + 256 bDescr = 860
const _: () = assert!(std::mem::size_of::<MIB_IFROW>() == 860);

#[link(name = "iphlpapi")]
extern "system" {
    fn GetIpAddrTable(pIpAddrTable: *mut MIB_IPADDRTABLE, pdwSize: *mut u32, bOrder: u32) -> u32;
    fn GetIfEntry(pIfRow: *mut MIB_IFROW) -> u32;
}

/// 枚举本机全部 IPv4 接口地址（含属性）。失败返回空表（调用方有 connect-trick 兜底）。
pub fn list_ipv4_interfaces() -> Vec<IfaceInfo> {
    let mut size: u32 = 0;
    // SAFETY：size 查询；首次传 NULL 返回所需 buffer 大小
    let rc = unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
    if rc != ERROR_INSUFFICIENT_BUFFER || size < std::mem::size_of::<MIB_IPADDRTABLE>() as u32 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size as usize];
    let rc = unsafe { GetIpAddrTable(buf.as_mut_ptr() as *mut MIB_IPADDRTABLE, &mut size, 1) };
    if rc != NO_ERROR {
        return Vec::new();
    }
    let table = unsafe { &*(buf.as_ptr() as *const MIB_IPADDRTABLE) };
    let n = table.dwNumEntries as usize;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        // SAFETY：table[0..dwNumEntries] 由 GetIpAddrTable 填充
        let row = unsafe { &*table.table.as_ptr().add(i) };
        let ip = Ipv4Addr::from(u32::from_be(row.dwAddr));
        out.push(fill_if_entry(row.dwIndex, ip));
    }
    out
}

/// 按 IPv4 地址查接口信息（Track A host candidate 转换时补接口元数据）。
pub fn find_by_ipv4(ip: Ipv4Addr) -> Option<IfaceInfo> {
    list_ipv4_interfaces().into_iter().find(|i| i.ip == ip)
}

/// GetIfEntry 填充接口属性（type/descr/oper）。
fn fill_if_entry(index: u32, ip: Ipv4Addr) -> IfaceInfo {
    let mut row = MIB_IFROW {
        wszName: [0; MAX_INTERFACE_NAME_LEN],
        dwIndex: index,
        dwType: 0,
        dwMtu: 0,
        dwSpeed: 0,
        dwPhysAddrLen: 0,
        bPhysAddr: [0; MAXLEN_PHYSADDR],
        dwAdminStatus: 0,
        dwOperStatus: 0,
        dwLastChange: 0,
        dwInOctets: 0,
        dwInUcastPkts: 0,
        dwInNUcastPkts: 0,
        dwInDiscards: 0,
        dwInErrors: 0,
        dwInUnknownProtos: 0,
        dwOutOctets: 0,
        dwOutUcastPkts: 0,
        dwOutNUcastPkts: 0,
        dwOutDiscards: 0,
        dwOutErrors: 0,
        dwOutQLen: 0,
        dwDescrLen: 0,
        bDescr: [0; MAXLEN_IFDESCR],
    };
    let rc = unsafe { GetIfEntry(&mut row) };
    let (descr, if_type, oper_up) = if rc == NO_ERROR {
        // bDescr 是内联 ANSI 字节缓冲（长度 dwDescrLen ≤ MAXLEN_IFDESCR），带 NUL 结尾
        let len = (row.dwDescrLen as usize).min(MAXLEN_IFDESCR);
        let descr = String::from_utf8_lossy(&row.bDescr[..len])
            .trim_end_matches('\0')
            .to_string();
        let status = row.dwOperStatus;
        (descr, row.dwType, status == IF_OPER_STATUS_CONNECTED || status == IF_OPER_STATUS_OPERATIONAL)
    } else {
        (String::new(), 0, false)
    };
    let kind = classify(&descr, if_type);
    IfaceInfo { index, descr, if_type, oper_up, ip, kind }
}

/// 按描述与 IANA ifType 分类（虚拟识别关键词经 descr 小写匹配）。
fn classify(descr: &str, if_type: u32) -> IfaceKind {
    let d = descr.to_lowercase();
    let hit = |kw: &str| d.contains(kw);
    // 顺序敏感：具体产品关键词优先于泛化 TUN/TAP
    if hit("vmware") {
        return IfaceKind::Virtual(VirtualKind::Vmware);
    }
    if hit("hyper-v") || hit("microsoft wi-fi direct virtual") {
        return IfaceKind::Virtual(VirtualKind::HyperV);
    }
    if hit("virtualbox") {
        return IfaceKind::Virtual(VirtualKind::VirtualBox);
    }
    if hit("wsl") {
        return IfaceKind::Virtual(VirtualKind::Wsl);
    }
    if hit("docker") {
        return IfaceKind::Virtual(VirtualKind::Docker);
    }
    if hit("tailscale") {
        return IfaceKind::Virtual(VirtualKind::Tailscale);
    }
    if hit("wintun") || hit("meshlink") {
        return IfaceKind::Virtual(VirtualKind::Wintun);
    }
    if hit("tap-") || hit("tap windows") || hit("tap adapter") {
        return IfaceKind::Virtual(VirtualKind::Tap);
    }
    if hit("teredo") || hit("isatap") || hit("tunnel") || if_type == 131 {
        return IfaceKind::Virtual(VirtualKind::Tunnel);
    }
    match if_type {
        6 => IfaceKind::Ethernet,           // IF_TYPE_ETHERNET_CSMACD
        71 => IfaceKind::WiFi,              // IF_TYPE_IEEE80211
        24 => IfaceKind::Virtual(VirtualKind::UnknownVirtual), // softwareLoopback
        53 | 23 | 244 | 245 => IfaceKind::Virtual(VirtualKind::UnknownVirtual), // propVirtual/ppp/3g
        _ => IfaceKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_physical_and_virtual() {
        assert_eq!(classify("Intel(R) Wi-Fi 6 AX201 160MHz", 71), IfaceKind::WiFi);
        assert_eq!(classify("Realtek PCIe GbE Family Controller", 6), IfaceKind::Ethernet);
        assert_eq!(classify("VMware Virtual Ethernet Adapter for VMnet8", 6), IfaceKind::Virtual(VirtualKind::Vmware));
        assert_eq!(classify("Hyper-V Virtual Ethernet Adapter", 6), IfaceKind::Virtual(VirtualKind::HyperV));
        assert_eq!(classify("Wintun Userspace Tunnel", 131), IfaceKind::Virtual(VirtualKind::Wintun));
        assert_eq!(classify("TAP-Windows Adapter V9", 6), IfaceKind::Virtual(VirtualKind::Tap));
        assert!(classify("Wintun Userspace Tunnel", 131).is_virtual());
    }

    #[test]
    fn meshlink_descr_is_tun_class() {
        let mut i = fill_if_entry(0, std::net::Ipv4Addr::new(10, 0, 0, 1));
        i.descr = "MeshLink Overlay Tunnel".into();
        i.kind = classify(&i.descr, 131);
        assert!(i.is_tun_class(), "MeshLink 自有 Wintun 必须被 gathering 硬排除");
    }

    #[test]
    fn physical_rank_ordering() {
        assert!(classify("Intel Wi-Fi", 71).is_virtual() == false);
        let eth = IfaceKind::Ethernet;
        let vm = IfaceKind::Virtual(VirtualKind::Vmware);
        assert!(IfaceInfo { index: 1, descr: String::new(), if_type: 6, oper_up: true, ip: std::net::Ipv4Addr::LOCALHOST, kind: eth }.physical_rank()
            < IfaceInfo { index: 2, descr: String::new(), if_type: 6, oper_up: true, ip: std::net::Ipv4Addr::LOCALHOST, kind: vm }.physical_rank());
    }

    /// 真机冒烟：GetIpAddrTable + GetIfEntry 全路径（debug 阶段用，--no-capture 看输出）。
    #[test]
    fn list_interfaces_smoke_real_ffi() {
        let mut size: u32 = 0;
        let rc1 = unsafe { GetIpAddrTable(std::ptr::null_mut(), &mut size, 0) };
        println!("stage1 rc={rc1} size={size}");
        assert_eq!(rc1, ERROR_INSUFFICIENT_BUFFER, "首查应返回 ERROR_INSUFFICIENT_BUFFER");
        let mut buf = vec![0u8; size as usize];
        let rc2 = unsafe { GetIpAddrTable(buf.as_mut_ptr() as *mut MIB_IPADDRTABLE, &mut size, 1) };
        println!("stage2 rc={rc2}");
        assert_eq!(rc2, NO_ERROR);
        let table = unsafe { &*(buf.as_ptr() as *const MIB_IPADDRTABLE) };
        let n = table.dwNumEntries as usize;
        println!("stage3 entries={n} bufsize={}", buf.len());
        for i in 0..n {
            let row = unsafe { &*table.table.as_ptr().add(i) };
            let ip = Ipv4Addr::from(u32::from_be(row.dwAddr));
            println!("  [{i}] idx={} ip={ip}", row.dwIndex);
            let info = fill_if_entry(row.dwIndex, ip);
            println!("      descr={:?} type={} up={}", info.descr, info.if_type, info.oper_up);
        }
    }
}
