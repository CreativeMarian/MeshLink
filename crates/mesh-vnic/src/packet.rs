//! L3 包校验与受控 PacketBuffer（M0-3 要求二十）。
//!
//! 第一版 IPv4 only：
//! - `len >= 20`、`version == 4`、IHL 合法（>=5 且 <= len/4）、
//!   `total_length` 合法且 `<= actual buffer`
//! - IPv6 / 其它版本 / 组播 dst：识别为「不支持」（PacketDisposition 独立分类）
//! - 格式坏 IPv4：`MalformedIpv4`
//! - 策略丢弃（预留，如 overlay_cidr 范围外 src/dst）：`PolicyDrop`
//! - 结构不假设 header 固定 20 字节（IPv4 options 存在，IHL 决定）
//! - 非法包一律 drop + 按 disposition 独立计数，绝不 panic（M0-3.1-3 拆分指标）

use mesh_common::ErrorCode;

/// 校验输出（M0-3.1-2 / M0-3.1-3）：取代之前 `Result<PacketInfo, PacketRejectReason>`，
/// 明确区分「合法通过」「v1 当前暂不支持（非 malformed，不污染 Path Health）」
/// 「格式坏 IPv4（真正异常）」「策略丢弃」四类。Metrics 模块按本 enum 标签聚合。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketDisposition {
    /// AcceptIpv4Unicast：合法 IPv4 单播，进入上层路由/队列。附带 header 摘要。
    AcceptIpv4Unicast(PacketInfo),
    /// UnsupportedIpv6：IPv6 包（version==6）。v1 只跑 IPv4 overlay，不视为错误。
    UnsupportedIpv6,
    /// UnsupportedMulticast：IPv4/IPv6 组播 / 广播（224.0.0.0/4、255.255.255.255、
    /// 33:33、D类 dst）。是合法 L2 帧，但 v1 data plane 暂不转发。
    UnsupportedMulticast,
    /// MalformedIpv4：格式坏 IPv4（短包/坏 IHL/坏 total_len/version 非 4/6 等）。
    /// 对应旧 PacketRejectReason 里非「不支持」的条目。
    MalformedIpv4(MalformedKind),
    /// PolicyDrop：未来策略丢弃（例如 overlay_cidr 范围外、ACL deny list）。
    /// v1 未启用具体 policy，本值保留给 ADR 优化路径使用。
    PolicyDrop,
}

/// MalformedIpv4 的子原因（用于日志 label，不单独分裂 ErrorCode）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MalformedKind {
    TooShort,               // buf.len < 20
    InvalidIhl,             // IHL < 5 或 IHL*4 > buf.len
    InvalidTotalLength,     // total_len < IHL*4
    TotalLengthExceedsBuffer, // total_len > buf.len
    UnsupportedVersion,     // version 非 4 且非 6（如 5/7/0 等协议实验）
    InvalidChecksum,        // 头 checksum 错误（v1 暂不校验，但字段占位，将来验证后落此处）
}

impl MalformedKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::InvalidIhl => "invalid_ihl",
            Self::InvalidTotalLength => "invalid_total_length",
            Self::TotalLengthExceedsBuffer => "total_length_exceeds_buffer",
            Self::UnsupportedVersion => "unsupported_version",
            Self::InvalidChecksum => "invalid_checksum",
        }
    }
}

impl PacketDisposition {
    /// 对 Path Health 指标：是否算作「真正的错误/损坏包」。
    /// UnsupportedIpv6 / UnsupportedMulticast / PolicyDrop 全返回 false（不损伤健康分）。
    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::MalformedIpv4(_))
    }
    /// 用于 VnicStats 四分类映射：rx_dropped_unsupported_ipv6 / _unsupported_multicast /
    /// rx_dropped_malformed_ipv4 / rx_dropped_policy。
    /// Accept 变体返回 None（不应计入 rx drop 计数器）。
    pub fn rx_drop_key(&self) -> Option<&'static str> {
        Some(match self {
            Self::AcceptIpv4Unicast(_) => return None,
            Self::UnsupportedIpv6 => "unsupported_ipv6",
            Self::UnsupportedMulticast => "unsupported_multicast",
            Self::MalformedIpv4(_) => "malformed_ipv4",
            Self::PolicyDrop => "policy",
        })
    }
}

// ---------------------------------------------------------------------------
// 兼容性桥（旧 PacketRejectReason 保留：对外 VnicError::PacketInvalid.reason
// 仍使用它，不破坏已有 ErrorCode 映射；内部 validate 则全部走 PacketDisposition）
// ---------------------------------------------------------------------------
#[deprecated(note = "内部使用 PacketDisposition；仅 VnicError::PacketInvalid 继续使用旧枚举映射到稳定 ErrorCode")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketRejectReason {
    TooShort,
    TooLong,
    UnsupportedIpVersion,
    InvalidIhl,
    InvalidTotalLength,
    TotalLengthExceedsBuffer,
}

#[allow(deprecated)]
impl PacketRejectReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooShort => "too_short",
            Self::TooLong => "too_long",
            Self::UnsupportedIpVersion => "unsupported_ip_version",
            Self::InvalidIhl => "invalid_ihl",
            Self::InvalidTotalLength => "invalid_total_length",
            Self::TotalLengthExceedsBuffer => "total_length_exceeds_buffer",
        }
    }
    pub fn code(self) -> ErrorCode { ErrorCode::VnicPacketInvalid }
}

/// 校验通过的包信息（header 布局摘要，供后续路由/统计使用）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    /// IP header 长度（IHL * 4，IPv4 options 会使它 > 20）
    pub header_len: usize,
    /// IP total length（含 header，网络层声称的包长）
    pub total_len: usize,
    /// 协议号（1=ICMP, 6=TCP, 17=UDP）
    pub protocol: u8,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

/// 校验 L3 包（v1 IPv4 only）。输出 `PacketDisposition`：Accept/Unsupported* / Malformed / Policy。
///
/// IPv4 multicast / broadcast 判定：
/// - dst 首字节 D 类（224~239）→ UnsupportedMulticast（合法协议包，非坏包）
/// - dst == 255.255.255.255 → 同上
/// - IPv6（version==6）→ UnsupportedIpv6
/// - version 非 4/6 → Malformed(UnsupportedVersion)
pub fn classify(buf: &[u8]) -> PacketDisposition {
    use PacketDisposition::*;
    use MalformedKind::*;
    if buf.len() < 1 {
        return MalformedIpv4(TooShort);
    }
    let version = buf[0] >> 4;
    if version == 6 {
        return UnsupportedIpv6;
    }
    if version != 4 {
        return MalformedIpv4(UnsupportedVersion);
    }
    // --- IPv4 路径 -----------------------------------------------------------
    if buf.len() < 20 {
        return MalformedIpv4(TooShort);
    }
    let ihl_words = (buf[0] & 0x0F) as usize;
    if ihl_words < 5 {
        return MalformedIpv4(InvalidIhl);
    }
    let header_len = ihl_words * 4;
    if header_len > buf.len() {
        return MalformedIpv4(InvalidIhl);
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    if total_len < header_len {
        return MalformedIpv4(InvalidTotalLength);
    }
    if total_len > buf.len() {
        return MalformedIpv4(TotalLengthExceedsBuffer);
    }
    let dst = [buf[16], buf[17], buf[18], buf[19]];
    // 组播/广播：D 类地址范围 224.0.0.0/4（高 4 位 = 1110 = 0xE）
    let is_mcast = (dst[0] & 0xF0) == 0xE0;
    let is_bcast = dst == [255, 255, 255, 255];
    if is_mcast || is_bcast {
        return UnsupportedMulticast;
    }
    AcceptIpv4Unicast(PacketInfo {
        header_len,
        total_len,
        protocol: buf[9],
        src: [buf[12], buf[13], buf[14], buf[15]],
        dst,
    })
}

/// 兼容旧接口（旧 VnicError::PacketInvalid.reason + 测试使用）：
/// 把新 Disposition 的 Malformed/Unsupported 分支映射回旧 Result<PacketInfo,PacketRejectReason>。
#[allow(deprecated)]
pub fn validate_ipv4(buf: &[u8]) -> Result<PacketInfo, PacketRejectReason> {
    match classify(buf) {
        PacketDisposition::AcceptIpv4Unicast(i) => Ok(i),
        PacketDisposition::UnsupportedIpv6
        | PacketDisposition::UnsupportedMulticast
        | PacketDisposition::PolicyDrop => Err(PacketRejectReason::UnsupportedIpVersion),
        PacketDisposition::MalformedIpv4(k) => Err(match k {
            MalformedKind::TooShort => PacketRejectReason::TooShort,
            MalformedKind::InvalidIhl => PacketRejectReason::InvalidIhl,
            MalformedKind::InvalidTotalLength => PacketRejectReason::InvalidTotalLength,
            MalformedKind::TotalLengthExceedsBuffer => PacketRejectReason::TotalLengthExceedsBuffer,
            MalformedKind::UnsupportedVersion | MalformedKind::InvalidChecksum => {
                PacketRejectReason::UnsupportedIpVersion
            }
        }),
    }
}

/// 受控 PacketBuffer：从 Wintun ring 拷贝后的上层安全形态（要求九）。
pub type PacketBuffer = Vec<u8>;

/// ICMP checksum（互联网校验和）。
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum >> 16) + (sum & 0xFFFF);
    }
    !(sum as u16)
}

/// 构造 ICMP Echo Reply（响应 Echo Request）。
/// 输入必须是合法 IPv4+ICMP echo request；否则返回 None。
/// 集成测试（要求二十一）用它证明 TX 路径可向 Windows TCP/IP 栈回包。
pub fn icmp_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    let info = validate_ipv4(request).ok()?;
    if info.protocol != 1 {
        return None;
    }
    let icmp = &request[info.header_len..];
    if icmp.len() < 8 || icmp[0] != 8 {
        // type 8 = echo request
        return None;
    }

    let mut pkt = request[..info.total_len].to_vec();
    // IPv4: 交换 src/dst；重算 TTL/checksum
    pkt[12..16].copy_from_slice(&info.dst);
    pkt[16..20].copy_from_slice(&info.src);
    pkt[6] &= 0xF0; // 清 flags/fragment 高位简化
    pkt[7] = 0; // fragment offset
    pkt[8] = 64; // TTL
    pkt[10] = 0;
    pkt[11] = 0;
    let hdr_sum = icmp_checksum(&pkt[..info.header_len]);
    pkt[10..12].copy_from_slice(&hdr_sum.to_be_bytes());

    // ICMP: type 0 = echo reply，重算 checksum
    pkt[info.header_len] = 0;
    pkt[info.header_len + 2] = 0;
    pkt[info.header_len + 3] = 0;
    let icmp_sum = icmp_checksum(&pkt[info.header_len..]);
    pkt[info.header_len + 2..info.header_len + 4].copy_from_slice(&icmp_sum.to_be_bytes());
    Some(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // M0-3.1-3: PacketDisposition 四象限单测（rx_drop_four_classification 的
    // 统计基础；证明 UnsupportedIpv6 / UnsupportedMulticast 不算 malformed，
    // 而 MalformedIpv4(MalformedKind) 才计入 Path Health 损伤）。
    // -----------------------------------------------------------------------

    /// 构造最小 IPv6 40 字节基础头（version=6, payload_len=8, next_header=UDP,
    /// hop_limit=64, src=::1, dst=::1）+ UDP payload 8B。用于 UnsupportedIpv6 判定。
    fn build_v6_min() -> Vec<u8> {
        let mut p = vec![0u8; 40 + 8];
        p[0] = 0x60;                 // version=6, traffic class=0, flow label=0
        p[4..6].copy_from_slice(&8u16.to_be_bytes()); // payload_length=8
        p[6] = 17;                   // next header = UDP
        p[7] = 64;                   // hop limit = 64
        p[30] = 1;                   // src = ::1 (最后一字节)
        p[39] = 1;                   // dst = ::1
        p
    }

    /// 构造 IPv4 header（IHL=5）+ payload，可选将 dst 设为组播 / 广播。
    fn build_v4_dst(protocol: u8, payload_len: usize, dst: [u8; 4]) -> Vec<u8> {
        let mut p = build_v4(protocol, payload_len, 5);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn packet_disposition_classify_four_quadrants() {
        // (1) AcceptIpv4Unicast：合法 IPv4 单播
        let uni = build_v4(1, 8, 5);
        let d = classify(&uni);
        assert!(matches!(d, PacketDisposition::AcceptIpv4Unicast(_)),
            "合法单播必须 Accept，实际 {d:?}");
        assert!(!d.is_malformed());
        assert_eq!(d.rx_drop_key(), None, "Accept 返回 None（不计入 rx drop）");

        // (2) UnsupportedIpv6：IPv6 包（合法不支持，非错误）
        let v6 = build_v6_min();
        let d = classify(&v6);
        assert_eq!(d, PacketDisposition::UnsupportedIpv6);
        assert!(!d.is_malformed(), "IPv6 本身不视为 malformed！Path Health 不损伤");
        assert_eq!(d.rx_drop_key(), Some("unsupported_ipv6"));

        // (3) UnsupportedMulticast：IPv4 224.0.0.1 组播（D类高4位=1110，合法协议）
        let mcast = build_v4_dst(17, 16, [224, 0, 0, 1]);
        let d = classify(&mcast);
        assert_eq!(d, PacketDisposition::UnsupportedMulticast);
        assert!(!d.is_malformed(), "组播本身不视为 malformed！Path Health 不损伤");
        assert_eq!(d.rx_drop_key(), Some("unsupported_multicast"));

        // (3b) UnsupportedMulticast：255.255.255.255 广播
        let bcast = build_v4_dst(17, 16, [255, 255, 255, 255]);
        let d = classify(&bcast);
        assert_eq!(d, PacketDisposition::UnsupportedMulticast);
        assert_eq!(d.rx_drop_key(), Some("unsupported_multicast"));

        // (4) MalformedIpv4(TooShort)：真正损坏
        let short: Vec<u8> = vec![0x45u8; 19]; // 20B 最小 IPv4 头还差 1B
        let d = classify(&short);
        assert!(matches!(d, PacketDisposition::MalformedIpv4(MalformedKind::TooShort)),
            "19B IPv4 必须 Malformed(TooShort)，实际 {d:?}");
        assert!(d.is_malformed(), "真正 malformed 必须 true！Path Health 计入损伤");
        assert_eq!(d.rx_drop_key(), Some("malformed_ipv4"));

        // (5) MalformedIpv4(UnsupportedVersion)：version=7 既非 4 非 6
        let weird: Vec<u8> = {
            let mut p = vec![0u8; 20];
            p[0] = 0x70 | 5; // version=7, IHL=5
            p
        };
        let d = classify(&weird);
        assert!(matches!(d, PacketDisposition::MalformedIpv4(MalformedKind::UnsupportedVersion)));
        assert_eq!(d.rx_drop_key(), Some("malformed_ipv4"));

        // (6) PolicyDrop 占位：v1 暂未启用，通过显式构造确认 rx_drop_key
        let d = PacketDisposition::PolicyDrop;
        assert!(!d.is_malformed());
        assert_eq!(d.rx_drop_key(), Some("policy"));
    }

    #[test]
    fn rx_drop_key_covers_all_four_categories_without_accept() {
        // 验证 rx_drop_key 输出完全对应 VnicStats 四个拆分字段名：
        //   unsupported_ipv6 / unsupported_multicast / malformed_ipv4 / policy
        // 且没有出现旧版 "invalid" 混合命名残留
        use PacketDisposition::*;
        let cases = [
            (UnsupportedIpv6, Some("unsupported_ipv6"), false),
            (UnsupportedMulticast, Some("unsupported_multicast"), false),
            (MalformedIpv4(MalformedKind::InvalidIhl), Some("malformed_ipv4"), true),
            (PolicyDrop, Some("policy"), false),
        ];
        for (disp, expect_key, expect_mal) in cases {
            assert_eq!(disp.rx_drop_key(), expect_key, "{disp:?} 的 rx_drop_key 与 VnicStats 字段名不一致");
            assert_eq!(disp.is_malformed(), expect_mal, "{disp:?} 的 is_malformed 与分类规则不一致");
            // 禁止旧命名残留
            if let Some(k) = disp.rx_drop_key() {
                assert!(!k.contains("invalid"), "禁止残留旧版 rx_dropped_invalid 命名: {k}");
            }
        }
    }

    /// 构造最小合法 IPv4 header（IHL=5）+ payload。
    fn build_v4(protocol: u8, payload_len: usize, ihl_words: usize) -> Vec<u8> {
        let mut p = vec![0u8; ihl_words * 4 + payload_len];
        p[0] = 0x40 | ihl_words as u8;
        p[1] = 0; // DSCP
        let total = (ihl_words * 4 + payload_len) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[9] = protocol;
        p[12..16].copy_from_slice(&[10, 70, 31, 2]);
        p[16..20].copy_from_slice(&[10, 70, 31, 1]);
        p
    }

    #[test]
    fn valid_ipv4_passes() {
        let p = build_v4(1, 8, 5);
        let info = validate_ipv4(&p).expect("合法包必须通过");
        assert_eq!(info.header_len, 20);
        assert_eq!(info.total_len, 28);
        assert_eq!(info.protocol, 1);
        assert_eq!(info.src, [10, 70, 31, 2]);
        assert_eq!(info.dst, [10, 70, 31, 1]);
    }

    #[test]
    fn too_short_rejected() {
        let p = vec![0x45u8; 19];
        assert_eq!(validate_ipv4(&p), Err(PacketRejectReason::TooShort));
        assert_eq!(validate_ipv4(&[]), Err(PacketRejectReason::TooShort));
    }

    #[test]
    fn ipv6_identified_and_rejected_not_panic() {
        let mut p = build_v4(6, 8, 5);
        p[0] = 0x60; // version 6
        assert_eq!(validate_ipv4(&p), Err(PacketRejectReason::UnsupportedIpVersion));
    }

    #[test]
    fn invalid_ihl_rejected() {
        let mut p = build_v4(6, 8, 5);
        p[0] = 0x44; // IHL=4 < 5
        assert_eq!(validate_ipv4(&p), Err(PacketRejectReason::InvalidIhl));
        // IHL 声称超过 buffer
        let p = build_v4(6, 0, 5);
        let mut p = p;
        p[0] = 0x4F; // IHL=15 → 60 bytes > 20 bytes buffer
        assert_eq!(validate_ipv4(&p), Err(PacketRejectReason::InvalidIhl));
    }

    #[test]
    fn invalid_total_length_rejected() {
        // total_length < header
        let mut p = build_v4(6, 0, 5);
        p[2..4].copy_from_slice(&16u16.to_be_bytes());
        assert_eq!(validate_ipv4(&p), Err(PacketRejectReason::InvalidTotalLength));
        // total_length > buffer
        let p = build_v4(6, 0, 5);
        let mut p = p;
        p[2..4].copy_from_slice(&1000u16.to_be_bytes());
        assert_eq!(validate_ipv4(&p), Err(PacketRejectReason::TotalLengthExceedsBuffer));
    }

    #[test]
    fn ipv4_options_do_not_break_validation() {
        // IHL=6（24 字节 header，4 字节 options）
        let mut p = build_v4(1, 8, 6);
        p[20..24].copy_from_slice(&[0x01, 0x01, 0x01, 0x01]); // NOP options
        let info = validate_ipv4(&p).expect("带 options 的包必须通过");
        assert_eq!(info.header_len, 24, "结构不得假设 header 恒为 20 字节");
    }

    #[test]
    fn icmp_echo_reply_transforms_request() {
        let mut req = build_v4(1, 8, 5);
        req[20] = 8; // echo request
        req[21] = 0;
        req[22..24].copy_from_slice(&[0, 0]); // checksum 占位
        // ICMP header(8B: type/code/checksum/id/seq) 只填 8 字节 payload
        req[24] = 0x12;
        req[25] = 0x34;
        req[26] = 0x00;
        req[27] = 0x01;

        let reply = icmp_echo_reply(&req).expect("echo request 必须可构造 reply");
        assert_eq!(reply[20], 0, "type 必须变为 0 (echo reply)");
        assert_eq!(&reply[12..16], &[10, 70, 31, 1], "src/dst 必须交换");
        assert_eq!(&reply[16..20], &[10, 70, 31, 2]);
        // checksum 自洽
        let sum = icmp_checksum(&reply[20..]);
        assert_eq!(sum, 0, "ICMP checksum 校验和必须为 0");
        // 非法输入安全
        assert!(icmp_echo_reply(&[0u8; 4]).is_none());
        let mut tcp = build_v4(6, 8, 5);
        tcp[20] = 0x50;
        assert!(icmp_echo_reply(&tcp).is_none(), "TCP 包不得误构造 reply");
    }
}
