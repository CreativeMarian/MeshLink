//! Overlay 冒烟探测（规格十二条件 8：Encrypted overlay smoke passed）。
//!
//! Agent 级 ICMP Echo：请求经 Noise 加密发往对端；对端 Agent 收到解密包后
//! 既注入本机协议栈（真实 Wintun 场景 Windows 内核还会再答一次——无害），
//! 也用 [`mesh_vnic::icmp_echo_reply`] 内置应答（Mock Overlay 与内核双路径统一）。
//! 应答携带相同 id/seq/payload，发起端据此判定加密数据面往返可用。

use std::net::Ipv4Addr;

/// 冒烟标识（ICMP identifier；区分 Agent 冒烟与用户自己的 ping）。
pub const SMOKE_ID: u16 = 0x4D4C; // "ML"
/// 冒烟序号（当前会话固定 1；重发幂等匹配同一序号即可）。
pub const SMOKE_SEQ: u16 = 1;
/// 冒烟载荷（应答匹配校验）。
pub const SMOKE_PAYLOAD: &[u8] = b"meshlink-smoke-v1";

/// 构造 IPv4 + ICMP Echo Request（校验和完整，Windows 栈可直接处理）。
pub fn echo_request(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let icmp_len = 8 + SMOKE_PAYLOAD.len();
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    // IPv4 header
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[1] = 0; // DSCP
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[4..6].copy_from_slice(&(0x1234u16).to_be_bytes()); // id
    pkt[6] = 0x40; // DF
    pkt[7] = 0;
    pkt[8] = 64; // TTL
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let hdr_sum = mesh_vnic::icmp_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    // ICMP echo request（头 8 字节：type/code/checksum/id/seq，载荷从偏移 28 起）
    pkt[20] = 8;
    pkt[21] = 0;
    pkt[24..26].copy_from_slice(&SMOKE_ID.to_be_bytes());
    pkt[26..28].copy_from_slice(&SMOKE_SEQ.to_be_bytes());
    pkt[28..total].copy_from_slice(SMOKE_PAYLOAD);
    let icmp_sum = mesh_vnic::icmp_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    pkt
}

/// 判断解密收到的包是否为对端 Agent 冒烟应答（id/seq/payload 全匹配）。
pub fn is_smoke_reply(pkt: &[u8]) -> bool {
    // 最小长度 + IPv4 + ICMP echo reply
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() < ihl + 8 {
        return false;
    }
    let icmp = &pkt[ihl..];
    if icmp[0] != 0 {
        return false; // type 0 = echo reply
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    id == SMOKE_ID && seq == SMOKE_SEQ && &icmp[8..] == SMOKE_PAYLOAD
}

/// Mock 迷你栈的内核语义应答：任意发给本机 Overlay IP 的 ICMP Echo Request
/// 都应答（真实 Windows TCP/IP 栈不限 id——用户自己的 ping 同样被应答；
/// Agent 冒烟与用户 ping 靠 id 区分，见 [`SMOKE_ID`]）。
pub fn kernel_echo_reply_for(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    if pkt[ihl] != 8 {
        return None; // 仅应答 Echo Request（type 8）
    }
    mesh_vnic::icmp_echo_reply(pkt)
}

/// 解密收到的包若是对端冒烟请求（type 8 + 标识匹配）→ 构造应答（None = 非匹配包）。
pub fn smoke_reply_for(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return None;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    let icmp = &pkt[ihl..];
    if icmp[0] != 8 {
        return None;
    }
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    if id != SMOKE_ID || seq != SMOKE_SEQ || &icmp[8..] != SMOKE_PAYLOAD {
        return None;
    }
    mesh_vnic::icmp_echo_reply(pkt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_request_reply_roundtrip() {
        let a = Ipv4Addr::new(10, 88, 7, 1);
        let b = Ipv4Addr::new(10, 88, 7, 2);
        let req = echo_request(a, b);
        // IPv4 头校验和必须为 0（含校验和字段的全 16bit 求和补码为 0）
        assert_eq!(mesh_vnic::icmp_checksum(&req[..20]), 0, "IPv4 头校验和必须自洽");
        // ICMP 校验和同样自洽（含校验和字段整体重算 = 0）
        assert_eq!(mesh_vnic::icmp_checksum(&req[20..]), 0, "ICMP 校验和必须自洽");

        // 对端收到请求 → 内置应答 → 应答必须匹配发起端判定
        let reply = smoke_reply_for(&req).expect("冒烟请求必须可识别");
        assert!(is_smoke_reply(&reply), "应答必须被 is_smoke_reply 认出");
        // 应答 dst/src 交换
        assert_eq!(&reply[12..16], &b.octets());
        assert_eq!(&reply[16..20], &a.octets());
        // 应答 IP 头校验和自洽
        assert_eq!(mesh_vnic::icmp_checksum(&reply[..20]), 0);
    }

    #[test]
    fn kernel_replies_to_any_echo_request() {
        let a = Ipv4Addr::new(10, 88, 7, 1);
        let b = Ipv4Addr::new(10, 88, 7, 2);
        // 用户 ping（非冒烟 id）在 Mock 内核语义下同样应答（真实栈行为）
        let mut user = echo_request(a, b);
        user[24..26].copy_from_slice(&0x0102u16.to_be_bytes());
        let icmp_sum = mesh_vnic::icmp_checksum(&user[20..]);
        user[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
        let reply = kernel_echo_reply_for(&user).expect("内核语义：任意 echo request 都应答");
        assert!(!is_smoke_reply(&reply), "用户 ping 的应答不带冒烟标识");
        assert_eq!(mesh_vnic::icmp_checksum(&reply[..20]), 0, "应答 IP 头校验和自洽");
        // 应答（type 0）不再触发应答——无无限循环
        assert!(kernel_echo_reply_for(&reply).is_none());
        // 非 echo request（type 0 之外，如 TCP）不应答
        let mut tcp = echo_request(a, b);
        tcp[9] = 6;
        assert!(kernel_echo_reply_for(&tcp).is_none());
    }

    #[test]
    fn non_matching_packets_rejected() {
        let a = Ipv4Addr::new(10, 88, 7, 1);
        let b = Ipv4Addr::new(10, 88, 7, 2);
        let req = echo_request(a, b);
        // 用户的普通 ping（id 不同）不得触发冒烟应答
        let mut user_ping = req.clone();
        user_ping[24..26].copy_from_slice(&0x0102u16.to_be_bytes());
        // 重算 ICMP 校验和（改了 id）——不重算也行，本判定不依赖校验和
        assert!(smoke_reply_for(&user_ping).is_none(), "非冒烟 id 不得应答");
        assert!(!is_smoke_reply(&user_ping));
        // 短包 / 非 ICMP / 非 IPv4
        assert!(smoke_reply_for(&[0u8; 10]).is_none());
        assert!(!is_smoke_reply(&[0u8; 10]));
        let mut tcp = echo_request(a, b);
        tcp[9] = 6; // TCP
        assert!(smoke_reply_for(&tcp).is_none());
    }
}
