//! IPv4 地址配置（M0-3 要求十三/十四）。
//!
//! 硬性规则：
//! - 禁止 shell out（netsh / PowerShell / cmd.exe）；只用 Windows IP Helper API：
//!   `WintunGetAdapterLUID` + `CreateUnicastIpAddressEntry`。
//! - M0 禁止 0.0.0.0/0 默认路由：本模块只配置 Overlay 单播地址，
//!   on-link 路由由 TCP/IP 栈随地址配置自然生成（仅限测试 CIDR）。
//! - CIDR 冲突只检测报告（OverlaySubnetConflict），不自动避让（M1 Controller 能力）。
//!
//! FFI 结构布局对照 Windows SDK netioapi.h / ws2ipdef.h（ABI 稳定公开结构）。

use crate::api::{NetLuid, ERROR_ALREADY_EXISTS};
use crate::error::{OsError, VnicError};
use std::net::Ipv4Addr;

const AF_INET: u16 = 2;

// ---- netioapi.h 枚举值（MIB_UNICASTIPADDRESS_ROW 字段） ----
const NL_PREFIX_ORIGIN_MANUAL: u32 = 1;
const NL_SUFFIX_ORIGIN_MANUAL: u32 = 1;
// IpDadStatePreferred = 4（netioapi.h NL_DAD_STATE：0=Invalid,1=Tentative,2=Duplicate,3=Deprecated,4=Preferred）
const NL_DAD_STATE_PREFERRED: u32 = 4;
const LIFETIME_INFINITE: u32 = 0xFFFF_FFFF;

// ---- CreateUnicastIpAddressEntry 返回码 ----
const ERROR_OBJECT_ALREADY_EXISTS: OsError = 5010;

/// SOCKADDR_INET（MSVC x64 ABI：sizeof=28，alignof=4）。
/// 对齐关键：C 端 SOCKADDR_INET union 的最大成员对齐来自 SOCKADDR_IN6.sin6_flowinfo（ULONG align=4），
/// 因此必须显式 `repr(align(4))` —— 若用默认 `bytes:[u8;28]`（align=1）会导致父结构在嵌套/嵌入时
/// 与 C MSVC 的结构体尾填充/后续字段对齐出现微妙差异（IP_ADDRESS_PREFIX 等）。
/// offset 0..2 = si_family；IPv4: 2..4 = sin_port(0)，4..8 = sin_addr。
#[repr(C, align(4))]
#[derive(Debug, Clone, Copy)]
struct SockaddrInet {
    bytes: [u8; 28],
}

impl Default for SockaddrInet {
    fn default() -> Self {
        Self { bytes: [0; 28] }
    }
}

impl SockaddrInet {
    fn new_ipv4(ip: Ipv4Addr) -> Self {
        let mut s = Self::default();
        s.bytes[0..2].copy_from_slice(&AF_INET.to_le_bytes());
        s.bytes[4..8].copy_from_slice(&ip.octets());
        s
    }

    fn family(&self) -> u16 {
        u16::from_le_bytes([self.bytes[0], self.bytes[1]])
    }

    fn ipv4(&self) -> Option<Ipv4Addr> {
        if self.family() == AF_INET {
            Some(Ipv4Addr::new(self.bytes[4], self.bytes[5], self.bytes[6], self.bytes[7]))
        } else {
            None
        }
    }
}

/// MIB_UNICASTIPADDRESS_ROW（权威 ABI 来自 diag_abi.exe: MSVC x64 sizeof=80 align=8）。
/// 字段顺序与各字段 offset 完全对照 MSVC cl.exe 编译的 offsetof() 输出：
///   Address@0(28) → [pad 4, 因 InterfaceLuid align=8] → InterfaceLuid@32(8) → InterfaceIndex@40(4)
///   → PrefixOrigin@44(4) → SuffixOrigin@48(4) → ValidLifetime@52(4) → PreferredLifetime@56(4)
///   → OnLinkPrefixLength@60(1) → SkipAsSource@61(1) → [pad 2, DadState u32 align=4]
///   → DadState@64(4) → ScopeId@68(4) → CreationTimeStamp@72(8)
/// 结构尾天然落在 80（alignof=8 的倍数），无需额外尾填充。
/// 之前的致命 bug：① InterfaceIndex 写在 InterfaceLuid 之前（整体 4B 错位，Create 成功但地址不落接口）；
///   ② 尾加 _reserved[4] 使 Rust sizeof=88（超过 C 的 80）→ GetUnicastIpAddressTable 返回的 OS 表
///     stride=80，但 Rust 按 88 步进读取导致 ptr::copy_nonoverlapping UB → 栈溢出 abort 0xC0000409。
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct MibUnicastIpAddressRow {
    address: SockaddrInet,          // 0..28  (align=4 → size 28)
    // [编译器自动 pad 4B @28..31，因为下一个 u64 要求 align=8]
    interface_luid: u64,            // 32..40
    interface_index: u32,           // 40..44
    prefix_origin: u32,             // 44..48
    suffix_origin: u32,             // 48..52
    valid_lifetime: u32,            // 52..56
    preferred_lifetime: u32,        // 56..60
    on_link_prefix_length: u8,      // 60..61
    skip_as_source: u8,             // 61..62
    _pad_before_dad: [u8; 2],       // 62..64  (DadState u32 按 4 对齐)
    dad_state: u32,                 // 64..68
    scope_id: u32,                  // 68..72
    creation_timestamp: i64,        // 72..80 (i64 align=8 OK, 尾落在 80)
}

impl Default for MibUnicastIpAddressRow {
    fn default() -> Self {
        // 全零初始化（FFI 输入结构；字段随后显式赋值）
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
struct MibUnicastIpAddressTable {
    num_entries: u32,
    first: [MibUnicastIpAddressRow; 1],
}

/// MIB_IPFORWARD_ROW2（netioapi.h，x64，size = 104，已对照 Windows SDK 10.0.26100）：
/// InterfaceLuid(8) InterfaceIndex(4) DestinationPrefix(32) NextHop(28)
/// SitePrefixLength(1) pad(3) ValidLifetime(4) PreferredLifetime(4) Metric(4)
/// Protocol(4) 4×BOOLEAN(4) Age(4) Origin(4)。
/// 创建/删除 /32 路由需要写 ValidLifetime..Origin 全部字段，故完整声明（勿用 _rest）。
#[repr(C)]
struct MibIpForwardRow {
    interface_luid: u64,          // 0..8
    interface_index: u32,         // 8..12
    /// IP_ADDRESS_PREFIX（32 字节）：SOCKADDR_INET Prefix(28) + UINT8 PrefixLength@28
    destination_prefix: [u8; 32], // 12..44
    next_hop: [u8; 28],           // 44..72
    site_prefix_length: u8,       // 72..73
    _pad: [u8; 3],                // 73..76
    valid_lifetime: u32,          // 76..80
    preferred_lifetime: u32,      // 80..84
    metric: u32,                  // 84..88
    protocol: u32,                // 88..92（NL_ROUTE_PROTOCOL）
    loopback: u8,                 // 92..93（BOOLEAN）
    unreachable: u8,              // 93..94
    publish: u8,                  // 94..95
    immortal: u8,                 // 95..96
    age: u32,                     // 96..100
    origin: u32,                  // 100..104（NL_ROUTE_ORIGIN）
}

#[repr(C)]
struct MibIpForwardTable {
    num_entries: u32,
    _pad: u32, // 行数组按 8 对齐
    first: [MibIpForwardRow; 1],
}

#[link(name = "iphlpapi")]
extern "system" {
    fn InitializeUnicastIpAddressEntry(row: *mut MibUnicastIpAddressRow);
    fn CreateUnicastIpAddressEntry(row: *const MibUnicastIpAddressRow) -> OsError;
    fn GetUnicastIpAddressTable(family: u16, table: *mut *mut MibUnicastIpAddressTable) -> OsError;
    fn GetIpForwardTable2(family: u16, table: *mut *mut MibIpForwardTable) -> OsError;
    fn FreeMibTable(memory: *mut std::ffi::c_void);
    fn ConvertInterfaceLuidToIndex(luid: *const NetLuid, index: *mut u32) -> OsError;
    // Overlay MVP 规格八（/32 对端路由安装/删除）
    fn InitializeIpForwardEntry(row: *mut MibIpForwardRow);
    fn CreateIpForwardEntry2(row: *const MibIpForwardRow) -> OsError;
    fn DeleteIpForwardEntry2(row: *const MibIpForwardRow) -> OsError;
}

// ---- DeleteIpForwardEntry2 返回码 ----
const ERROR_NOT_FOUND: OsError = 1168;

// ---- NL_ROUTE_PROTOCOL（netioapi.h）----
/// RouteProtocolNetMgmt = 3（`route add` 同源；人工管理路由的协议标识）
const NL_ROUTE_PROTOCOL_NETMGMT: u32 = 3;

/// 在指定接口上配置 IPv4 单播地址（on-link prefix）。
///
/// 返回值语义：
/// - `Ok(())`：创建成功
/// - `Err(IpAlreadyExists)`：该地址已在本接口存在（重复创建被识别）
/// - `Err(IpConfigurationFailed)`：其它失败（权限 / 参数 / 栈拒绝）
pub fn set_ipv4(luid: NetLuid, ip: Ipv4Addr, prefix_len: u8) -> Result<(), VnicError> {
    assert!(prefix_len <= 32, "prefix 非法（config 层已校验）");
    // 双填 LUID + InterfaceIndex（SDK 文档说任一即可，但部分 Windows 版本只填 LUID 会
    // 导致 on-link_prefix_length 被误解或 InterfaceIndex=0 引发的怪异行为）。
    let mut if_index: u32 = 0;
    let os_conv = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
    if os_conv != 0 {
        tracing::warn!(target: "vnic", "ConvertInterfaceLuidToIndex 失败(os={os_conv})，仅填 LUID");
    }

    let mut row = MibUnicastIpAddressRow::default();
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.address = SockaddrInet::new_ipv4(ip);
    row.interface_luid = luid.0;
    if os_conv == 0 {
        row.interface_index = if_index;
    }
    row.on_link_prefix_length = prefix_len;
    row.prefix_origin = NL_PREFIX_ORIGIN_MANUAL;
    row.suffix_origin = NL_SUFFIX_ORIGIN_MANUAL;
    row.valid_lifetime = LIFETIME_INFINITE;
    row.preferred_lifetime = LIFETIME_INFINITE;
    row.dad_state = NL_DAD_STATE_PREFERRED;
    row.skip_as_source = 0;

    {
        // 调试级 FFI 结构快照：RUST_LOG=mesh_vnic=debug 时可见。
        // （E2E --nocapture 下默认 info 级别不打印，保证 stdout/stderr 仅测试协议行）。
        let ptr = &row as *const _ as *const u8;
        let bytes = unsafe { std::slice::from_raw_parts(ptr, 80) };
        let mut out = String::from("[ROW AFTER_SET]");
        for (i, b) in bytes.iter().enumerate() {
            if i % 8 == 0 { out.push_str(&format!(" {i:02X}:")); }
            out.push_str(&format!("{b:02X}"));
        }
        out.push_str(&format!(" | if_index={if_index} conv_os={os_conv}"));
        tracing::debug!(target: "vnic", "{out}");
    }

    let os = unsafe { CreateUnicastIpAddressEntry(&row) };
    match os {
        0 => {
            // 调试级 READ_BACK：校验 OS 确实将目标地址+前缀注册到目标接口上。
            if tracing::enabled!(target: "vnic", tracing::Level::DEBUG) {
                if let Ok(all) = local_ipv4_addresses_raw() {
                    tracing::debug!(target: "vnic", "[READ_BACK] total_rows={} looking for luid=0x{:X} ip={ip}", all.len(), luid.0);
                    for (i, r) in all.iter().enumerate() {
                        let rip = r.address.ipv4();
                        let matches = r.interface_luid == luid.0 && rip == Some(ip);
                        let interesting = matches
                            || (r.interface_luid != 0)
                            || rip.map(|a| a.octets()[0] == 10).unwrap_or(false);
                        if !interesting { continue; }
                        let ptr = r as *const _ as *const u8;
                        let bytes = unsafe { std::slice::from_raw_parts(ptr, 80) };
                        let mut out = format!(
                            "[ROW #{i}] luid=0x{:X} ip={rip:?} olpl={} idx={}",
                            r.interface_luid, r.on_link_prefix_length, r.interface_index,
                        );
                        for (j, b) in bytes.iter().enumerate() {
                            if j % 8 == 0 { out.push_str(&format!(" {j:02X}:")); }
                            out.push_str(&format!("{b:02X}"));
                        }
                        if matches { out.push_str(" ***MATCH***"); }
                        tracing::debug!(target: "vnic", "{out}");
                    }
                }
            }
            tracing::info!(target: "vnic", "IPv4 已配置: {ip}/{prefix_len} (luid=0x{:X})", luid.0);
            Ok(())
        }
        os if os == ERROR_OBJECT_ALREADY_EXISTS || os == ERROR_ALREADY_EXISTS => {
            tracing::warn!(target: "vnic", "IPv4 已存在（识别重复）: {ip}");
            Err(VnicError::IpAlreadyExists { ip: ip.to_string() })
        }
        os => {
            tracing::error!(target: "vnic", "CreateUnicastIpAddressEntry 失败: {ip}/{prefix_len} (os={os})");
            Err(VnicError::IpConfigurationFailed { ip: ip.to_string(), os })
        }
    }
}

/// 本机全部 IPv4 单播地址行（raw 结构，诊断专用；返回值语义同 local_ipv4_addresses）。
fn local_ipv4_addresses_raw() -> Result<Vec<MibUnicastIpAddressRow>, VnicError> {
    let mut table: *mut MibUnicastIpAddressTable = std::ptr::null_mut();
    let os = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if os != 0 {
        return Err(VnicError::IpConfigurationFailed { ip: "*enum*".into(), os });
    }
    assert!(!table.is_null());
    let out = unsafe {
        let n = (*table).num_entries as usize;
        let slice = std::slice::from_raw_parts((*table).first.as_ptr(), n);
        slice.to_vec()
    };
    unsafe { FreeMibTable(table as *mut _) };
    Ok(out)
}

/// 本机全部 IPv4 单播地址（含 prefix）快照。
pub fn local_ipv4_addresses() -> Result<Vec<(Ipv4Addr, u8, u64)>, VnicError> {
    let mut table: *mut MibUnicastIpAddressTable = std::ptr::null_mut();
    let os = unsafe { GetUnicastIpAddressTable(AF_INET, &mut table) };
    if os != 0 {
        return Err(VnicError::IpConfigurationFailed { ip: "*enum*".into(), os });
    }
    assert!(!table.is_null());
    let rows = unsafe {
        let n = (*table).num_entries as usize;
        std::slice::from_raw_parts((*table).first.as_ptr(), n)
    };
    let out: Vec<_> = rows
        .iter()
        .filter_map(|r| {
            // 部分虚拟/残留适配器会上报 > 32 的非法前缀（原始 IP Helper 表不清洗）。
            // 钳到 /32：既不让冲突检测 panic，也保持保守（仅精确 IP 重叠才误报）。
            let prefix = r.on_link_prefix_length.min(32) as u8;
            r.address.ipv4().map(|ip| (ip, prefix, r.interface_luid))
        })
        .collect();
    unsafe { FreeMibTable(table as *mut _) };
    Ok(out)
}

fn mask(prefix: u8) -> u32 {
    let p = prefix.min(32) as u32;
    if p == 0 { 0 } else { u32::MAX << (32 - p) }
}

fn to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

/// 检测 Overlay 网段与本机现有 IPv4 网段是否重叠（要求十四）。
///
/// `exclude_luid`：排除自身接口（已配置的 overlay 地址不算冲突）。
/// 双向重叠：本机地址落入 Overlay，或 Overlay 落入本机某网段。
/// M0 只检测报告；自动避让属于 M1 Controller。
pub fn detect_subnet_conflicts(
    overlay_net: Ipv4Addr,
    overlay_prefix: u8,
    exclude_luid: Option<u64>,
) -> Result<Vec<String>, VnicError> {
    let own = to_u32(overlay_net) & mask(overlay_prefix);
    let mut conflicts = Vec::new();
    for (ip, ip_prefix, luid) in local_ipv4_addresses()? {
        if Some(luid) == exclude_luid {
            continue;
        }
        let a = to_u32(ip);
        let a_net = a & mask(overlay_prefix);
        let own_in_a = own & mask(ip_prefix) == a & mask(ip_prefix);
        if a_net == own || own_in_a {
            conflicts.push(format!("{ip}/{ip_prefix}"));
        }
    }
    Ok(conflicts)
}

/// 查询指定地址是否已配置在指定接口上（重复 IP / 残留 IP 验证用）。
pub fn ip_exists_on(luid: NetLuid, ip: Ipv4Addr) -> Result<bool, VnicError> {
    Ok(local_ipv4_addresses()?
        .into_iter()
        .any(|(a, _, l)| l == luid.0 && a == ip))
}

/// 枚举指定接口上的全部 IPv4 路由（验收 22：证明没有 0.0.0.0/0 经由本接口）。
/// 返回 (目标网段, 前缀长度) 列表。
pub fn routes_via(luid: u64) -> Result<Vec<(Ipv4Addr, u8)>, VnicError> {
    const SIZEOF_ROW: usize = 104;
    debug_assert_eq!(std::mem::size_of::<MibIpForwardRow>(), SIZEOF_ROW);
    debug_assert_eq!(std::mem::offset_of!(MibIpForwardRow, destination_prefix), 12);

    let mut table: *mut MibIpForwardTable = std::ptr::null_mut();
    let os = unsafe { GetIpForwardTable2(AF_INET, &mut table) };
    if os != 0 {
        return Err(VnicError::RouteConfigurationFailed { os });
    }
    let rows = unsafe {
        let n = (*table).num_entries as usize;
        std::slice::from_raw_parts((*table).first.as_ptr(), n)
    };
    let mut out = Vec::new();
    for r in rows {
        if r.interface_luid != luid {
            continue;
        }
        let p = &r.destination_prefix;
        if u16::from_le_bytes([p[0], p[1]]) != AF_INET {
            continue;
        }
        let dst = Ipv4Addr::new(p[4], p[5], p[6], p[7]);
        // 权威 ABI：IP_ADDRESS_PREFIX = SOCKADDR_INET(28) + PrefixLength@28
        // (diag_abi.exe: offsetof(IP_ADDRESS_PREFIX, PrefixLength) == 28)
        let prefix_len = p[28];
        if tracing::enabled!(target: "vnic", tracing::Level::DEBUG) {
            let mut hex = String::new();
            for (i, b) in p.iter().enumerate() {
                if i % 8 == 0 { hex.push_str(&format!(" {i:02X}:")); }
                hex.push_str(&format!("{b:02X}"));
            }
            tracing::debug!(target: "vnic", "[ROUTE dst={dst}] family={:02X}{:02X} PrefixLength@28={prefix_len} bytes={hex}",
                p[0], p[1]);
        }
        out.push((dst, prefix_len.min(32)));
    }
    unsafe { FreeMibTable(table as *mut _) };
    Ok(out)
}

// ---------------------------------------------------------------------------
// /32 对端主机路由（Overlay MVP 规格八：路由最小化）
// ---------------------------------------------------------------------------

/// 构造一条指向本接口的 on-link /32 主机路由行（netioapi ABI 行，未提交）。
///
/// 硬性规则（规格八）：
/// - PrefixLength 固定 32——**绝不**写 0.0.0.0/0 或任何聚合前缀；
/// - NextHop = 0.0.0.0（on-link，无网关）：对端 Overlay IP 与本机虚拟 IP 同子网，
///   路由只负责把该 /32 的最长前缀匹配钉在 Wintun 接口上；
/// - 不触碰默认路由 / DNS / 其它接口的路由。
fn build_host_route_row(luid: NetLuid, peer_ip: Ipv4Addr) -> (MibIpForwardRow, OsError) {
    let mut if_index: u32 = 0;
    let os_conv = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut if_index) };
    if os_conv != 0 {
        tracing::warn!(target: "vnic", "ConvertInterfaceLuidToIndex 失败(os={os_conv})，仅填 LUID");
    }

    let mut row: MibIpForwardRow = unsafe { std::mem::zeroed() };
    unsafe { InitializeIpForwardEntry(&mut row) };
    // DestinationPrefix = IP_ADDRESS_PREFIX{ SOCKADDR_INET(ip), PrefixLength=32 }
    row.destination_prefix[0..2].copy_from_slice(&AF_INET.to_le_bytes());
    row.destination_prefix[4..8].copy_from_slice(&peer_ip.octets());
    row.destination_prefix[28] = 32;
    // NextHop：on-link 路由必须清零（仅 family 标记 IPv4）
    row.next_hop[0..2].copy_from_slice(&AF_INET.to_le_bytes());
    row.interface_luid = luid.0;
    if os_conv == 0 {
        row.interface_index = if_index;
    }
    row.valid_lifetime = LIFETIME_INFINITE;
    row.preferred_lifetime = LIFETIME_INFINITE;
    row.metric = 0; // 偏移量 0：/32 已是最长前缀，无需再压 metric
    row.protocol = NL_ROUTE_PROTOCOL_NETMGMT;
    row.publish = 0;
    row.immortal = 1;
    (row, os_conv)
}

/// 在指定接口上安装对端 Overlay IP 的 /32 主机路由（规格八）。
///
/// 幂等：该路由已存在（ERROR_OBJECT_ALREADY_EXISTS）→ `Ok(())`。
/// 其它失败 → `RouteConfigurationFailed`（携带 OS 错误码）。
pub fn set_host_route(luid: NetLuid, peer_ip: Ipv4Addr) -> Result<(), VnicError> {
    let (row, _) = build_host_route_row(luid, peer_ip);
    let os = unsafe { CreateIpForwardEntry2(&row) };
    match os {
        0 => {
            tracing::info!(
                target: "vnic",
                "对端 /32 路由已安装: {peer_ip}/32 → luid=0x{:X}",
                luid.0
            );
            Ok(())
        }
        os if os == ERROR_OBJECT_ALREADY_EXISTS || os == ERROR_ALREADY_EXISTS => {
            tracing::info!(target: "vnic", "对端 /32 路由已存在（幂等接受）: {peer_ip}");
            Ok(())
        }
        os => {
            tracing::error!(
                target: "vnic",
                "CreateIpForwardEntry2 失败: {peer_ip}/32 (os={os})"
            );
            Err(VnicError::RouteConfigurationFailed { os })
        }
    }
}

/// 删除由 [`set_host_route`] 安装的 /32 主机路由（规格八：会话断开必须回收）。
///
/// 幂等：路由不存在（ERROR_NOT_FOUND / 接口已消失）→ `Ok(())`。
pub fn remove_host_route(luid: NetLuid, peer_ip: Ipv4Addr) -> Result<(), VnicError> {
    let (row, _) = build_host_route_row(luid, peer_ip);
    let os = unsafe { DeleteIpForwardEntry2(&row) };
    match os {
        0 => {
            tracing::info!(target: "vnic", "对端 /32 路由已删除: {peer_ip}");
            Ok(())
        }
        os if os == ERROR_NOT_FOUND => {
            tracing::info!(target: "vnic", "对端 /32 路由不存在（幂等接受）: {peer_ip}");
            Ok(())
        }
        os => {
            tracing::error!(
                target: "vnic",
                "DeleteIpForwardEntry2 失败: {peer_ip}/32 (os={os})"
            );
            Err(VnicError::RouteConfigurationFailed { os })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_inet_layout_matches_abi() {
        let s = SockaddrInet::new_ipv4(Ipv4Addr::new(10, 70, 31, 1));
        // 权威对照 (diag_abi.exe MSVC x64): sizeof(SOCKADDR_INET)=28 alignof=4
        assert_eq!(std::mem::size_of::<SockaddrInet>(), 28);
        assert_eq!(std::mem::align_of::<SockaddrInet>(), 4, "显式 repr(align(4)) 匹配 C SOCKADDR_INET union align");
        assert_eq!(s.family(), AF_INET);
        assert_eq!(s.ipv4(), Some(Ipv4Addr::new(10, 70, 31, 1)));
    }

    #[test]
    fn unicast_ipaddress_row_layout_matches_msvc_80_bytes() {
        // 权威对照 (cl.exe /EHsc diag_abi.c + offsetof):
        //   sizeof=80 alignof=8；字段 offset 一一核对：
        println!(
            "sizeof={} align={} offsets: address={} luid={} ifindex={} po={} so={} vl={} pl={} olpl={} skip={} dad={} scope={} ts={}",
            std::mem::size_of::<MibUnicastIpAddressRow>(),
            std::mem::align_of::<MibUnicastIpAddressRow>(),
            std::mem::offset_of!(MibUnicastIpAddressRow, address),
            std::mem::offset_of!(MibUnicastIpAddressRow, interface_luid),
            std::mem::offset_of!(MibUnicastIpAddressRow, interface_index),
            std::mem::offset_of!(MibUnicastIpAddressRow, prefix_origin),
            std::mem::offset_of!(MibUnicastIpAddressRow, suffix_origin),
            std::mem::offset_of!(MibUnicastIpAddressRow, valid_lifetime),
            std::mem::offset_of!(MibUnicastIpAddressRow, preferred_lifetime),
            std::mem::offset_of!(MibUnicastIpAddressRow, on_link_prefix_length),
            std::mem::offset_of!(MibUnicastIpAddressRow, skip_as_source),
            std::mem::offset_of!(MibUnicastIpAddressRow, dad_state),
            std::mem::offset_of!(MibUnicastIpAddressRow, scope_id),
            std::mem::offset_of!(MibUnicastIpAddressRow, creation_timestamp),
        );
        assert_eq!(std::mem::size_of::<MibUnicastIpAddressRow>(), 80, "x64 MIB_UNICASTIPADDRESS_ROW sizeof=80 (MSVC diag_abi.exe 权威)");
        assert_eq!(std::mem::align_of::<MibUnicastIpAddressRow>(), 8);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, address), 0);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, interface_luid), 32);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, interface_index), 40);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, prefix_origin), 44);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, suffix_origin), 48);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, valid_lifetime), 52);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, preferred_lifetime), 56);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, on_link_prefix_length), 60);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, skip_as_source), 61);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, dad_state), 64);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, scope_id), 68);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, creation_timestamp), 72);
    }

    #[test]
    fn ipforward_row_layout_is_104_bytes() {
        // netioapi.h 64 位 ABI：sizeof(MIB_IPFORWARD_ROW2) == 104（曾错写 120，步长错位导致路由解析失败）
        assert_eq!(std::mem::size_of::<MibIpForwardRow>(), 104);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, interface_luid), 0);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, destination_prefix), 12);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, next_hop), 44);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, site_prefix_length), 72);
    }

    #[test]
    fn ipforward_row_write_fields_layout_matches_abi() {
        // 写路径（Create/DeleteIpForwardEntry2）字段 offset 权威对照 Windows SDK
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, valid_lifetime), 76);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, preferred_lifetime), 80);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, metric), 84);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, protocol), 88);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, loopback), 92);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, unreachable), 93);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, publish), 94);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, immortal), 95);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, age), 96);
        assert_eq!(std::mem::offset_of!(MibIpForwardRow, origin), 100);
    }

    #[test]
    fn host_route_row_carries_exact_peer_prefix_32() {
        let luid = NetLuid(0x1234_5678_9ABC_DEF0);
        let (row, _) = build_host_route_row(luid, Ipv4Addr::new(10, 88, 7, 2));
        // 规格八：前缀固定 /32（禁止任何聚合 / 默认路由）
        assert_eq!(row.destination_prefix[28], 32);
        // 目标 = 对端 Overlay IP（SOCKADDR_IN：family@0..2，sin_addr@4..8）
        assert_eq!(&row.destination_prefix[4..8], &[10, 88, 7, 2]);
        // on-link：NextHop 地址全零（无网关，不借道第三方接口）
        assert!(row.next_hop[4..28].iter().all(|&b| b == 0));
        assert_eq!(row.interface_luid, luid.0);
        // 无限生命周期 + 人工管理路由（route add 同源协议号）
        assert_eq!(row.valid_lifetime, 0xFFFF_FFFF);
        assert_eq!(row.preferred_lifetime, 0xFFFF_FFFF);
        assert_eq!(row.protocol, NL_ROUTE_PROTOCOL_NETMGMT);
    }

    #[test]
    fn table_containers_first_field_offset_matches_os_abi() {
        // 变长数组 Table：ULONG NumEntries + ROW[ANY_SIZE]。
        // ROW 对齐 = 8（内含 u64 LUID），因此 C MSVC / Rust repr(C) 均在 NumEntries 后补 4 字节，
        // first[] 必须从 offset 8 开始。错位将导致 slice 越界（STATUS_ACCESS_VIOLATION）。
        // 注：MibIpForwardTable 曾显式加 _pad:u32 被怀疑破坏隐式对齐契约，此处强制验证。
        assert_eq!(std::mem::align_of::<MibUnicastIpAddressRow>(), 8);
        assert_eq!(std::mem::align_of::<MibIpForwardRow>(), 8);
        assert_eq!(std::mem::align_of::<MibUnicastIpAddressTable>(), 8);
        assert_eq!(std::mem::align_of::<MibIpForwardTable>(), 8);
        assert_eq!(std::mem::offset_of!(MibUnicastIpAddressTable, first), 8);
        assert_eq!(std::mem::offset_of!(MibIpForwardTable, first), 8);
        // 打印实际 sizeof（便于肉眼核对 netioapi.h：4 + 对齐 + 1 个 row）
        println!(
            "sizeof Table[1 row]: Unicast={} IpForward={}",
            std::mem::size_of::<MibUnicastIpAddressTable>(),
            std::mem::size_of::<MibIpForwardTable>(),
        );
    }

    #[test]
    fn subnet_overlap_math() {
        let overlay = Ipv4Addr::new(10, 70, 31, 0);
        assert_eq!(to_u32(overlay) & mask(24), to_u32(Ipv4Addr::new(10, 70, 31, 77)) & mask(24));
        assert_ne!(to_u32(overlay) & mask(24), to_u32(Ipv4Addr::new(10, 70, 32, 1)) & mask(24));
        // /16 内含 /24
        assert!(to_u32(Ipv4Addr::new(10, 70, 0, 1)) & mask(16) == to_u32(overlay) & mask(16));
    }
}
