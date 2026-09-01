//! Track B 基础件：STUN 消息编解码（RFC 5389 / RFC 8489 子集）与 Binding 客户端。
//!
//! 自研精简 ICE（M0-4 Track B）只需客户端侧最小子集：
//! - Binding Request / Response / ErrorResponse
//! - XOR-MAPPED-ADDRESS / MAPPED-ADDRESS / ERROR-CODE / SOFTWARE / FINGERPRINT
//! - RFC 5389 §7.2.1 重传（RTO 500ms，线性退避）
//!
//! 纯逻辑零网络依赖；网络部分在 [`binding_exchange`]，可注入任意 socket 测试。
//! FINGERPRINT 校验用 IEEE CRC32（RFC 5389 §15.5，XOR 0x5354554E）。

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};

/// RFC 5389 §6 魔数。
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
/// STUN 头部长度（Type2 + Len2 + Cookie4 + TxId12）。
pub const HEADER_LEN: usize = 20;

pub const BINDING_REQUEST: u16 = 0x0001;
pub const BINDING_RESPONSE: u16 = 0x0101;
pub const BINDING_ERROR_RESPONSE: u16 = 0x0111;

pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// RFC 5780 §4：OTHER-ADDRESS（NAT behavior discovery 服务器能力指示）
pub const ATTR_OTHER_ADDRESS: u16 = 0x0029;
/// RFC 5780 §4：CHANGE-REQUEST（要求服务器换 IP/端口发响应）
pub const ATTR_CHANGE_REQUEST: u16 = 0x0032;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_FINGERPRINT: u16 = 0x8028;
/// MeshLink 自定义属性（comprehension-optional 0x8000+ 范围）：punch 请求携带
/// 本端候选集（双向 simultaneous punch 的 candidate exchange 逆向通道：
/// creator 收到 join 首个 probe 后据此向对端候选反向出站）。
pub const ATTR_MESH_CANDIDATES: u16 = 0x8050;
/// MeshCandidates 单条候选字节数（u32 ip + u16 port + u8 kind）。
pub const MESH_CAND_ENTRY_LEN: usize = 7;
/// MeshCandidates 数量上限（防恶意大属性）。
pub const MESH_CAND_MAX: usize = 8;

/// 解码失败（长度/魔数/类型非法）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunError {
    TooShort,
    BadMagic,
    BadLength,
    BadAttribute,
    /// 对端返回 Binding Error Response
    ServerError { class: u8, number: u8, reason: String },
}

/// 单条候选的紧凑 wire 形态（MeshCandidates 属性内嵌）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateWire {
    pub ip: u32,
    pub port: u16,
    /// 0 = host，1 = server_reflexive
    pub kind: u8,
}

/// STUN 属性（解码后）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunAttr {
    XorMapped(SocketAddrV4),
    Mapped(SocketAddrV4),
    Username(String),
    Software(String),
    ErrorCode { class: u8, number: u8, reason: String },
    Fingerprint(u32),
    /// RFC 5780 OTHER-ADDRESS（服务器第二 ip:port；行为发现能力指示）
    OtherAddress(SocketAddrV4),
    /// RFC 5780 CHANGE-REQUEST（change-ip / change-port 标志）
    ChangeRequest { change_ip: bool, change_port: bool },
    /// 本端候选集（punch 请求携带；超限截断）
    MeshCandidates(Vec<CandidateWire>),
    /// 保留原样（精简 ICE 忽略未知属性，但保留以便日志/兼容）
    Unknown(u16, Vec<u8>),
}

/// STUN 消息。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub msg_type: u16,
    pub txid: [u8; 12],
    pub attrs: Vec<StunAttr>,
}

impl StunMessage {
    pub fn binding_request(txid: [u8; 12]) -> Self {
        Self { msg_type: BINDING_REQUEST, txid, attrs: Vec::new() }
    }

    /// 按 RFC 5389 §5 编码（含 4 字节对齐 padding；不自动加 FINGERPRINT）。
    pub fn encode(&self) -> Vec<u8> {
        let mut body: Vec<u8> = Vec::new();
        for attr in &self.attrs {
            match attr {
                StunAttr::XorMapped(a) => {
                    let mut v = [0u8; 8];
                    v[1] = 0x01; // IPv4
                    v[2..4].copy_from_slice(&(a.port() ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
                    let ip = u32::from(*a.ip()) ^ MAGIC_COOKIE;
                    v[4..8].copy_from_slice(&ip.to_be_bytes());
                    push_attr(&mut body, ATTR_XOR_MAPPED_ADDRESS, &v);
                }
                StunAttr::Mapped(a) => {
                    let mut v = [0u8; 8];
                    v[1] = 0x01;
                    v[2..4].copy_from_slice(&a.port().to_be_bytes());
                    v[4..8].copy_from_slice(&a.ip().octets());
                    push_attr(&mut body, ATTR_MAPPED_ADDRESS, &v);
                }
                StunAttr::Username(s) | StunAttr::Software(s) => {
                    let t = if matches!(attr, StunAttr::Username(_)) { ATTR_USERNAME } else { ATTR_SOFTWARE };
                    push_attr(&mut body, t, s.as_bytes());
                }
                StunAttr::ErrorCode { class, number, reason } => {
                    let mut v = Vec::with_capacity(4 + reason.len());
                    v.extend_from_slice(&[0u8, 0u8, class & 0x07, *number]);
                    v.extend_from_slice(reason.as_bytes());
                    push_attr(&mut body, ATTR_ERROR_CODE, &v);
                }
                StunAttr::Fingerprint(crc) => {
                    push_attr(&mut body, ATTR_FINGERPRINT, &crc.to_be_bytes());
                }
                StunAttr::OtherAddress(a) => {
                    let mut v = [0u8; 8];
                    v[1] = 0x01;
                    v[2..4].copy_from_slice(&a.port().to_be_bytes());
                    v[4..8].copy_from_slice(&a.ip().octets());
                    push_attr(&mut body, ATTR_OTHER_ADDRESS, &v);
                }
                StunAttr::ChangeRequest { change_ip, change_port } => {
                    let mut v = [0u8; 4];
                    if *change_ip {
                        v[3] |= 0x04;
                    }
                    if *change_port {
                        v[3] |= 0x02;
                    }
                    push_attr(&mut body, ATTR_CHANGE_REQUEST, &v);
                }
                StunAttr::MeshCandidates(cands) => {
                    // ver(1) + count(1) + count × 7；编码侧截断到上限
                    let mut v = vec![1u8, cands.len().min(MESH_CAND_MAX) as u8];
                    for c in cands.iter().take(MESH_CAND_MAX) {
                        v.extend_from_slice(&c.ip.to_be_bytes());
                        v.extend_from_slice(&c.port.to_be_bytes());
                        v.push(c.kind);
                    }
                    push_attr(&mut body, ATTR_MESH_CANDIDATES, &v);
                }
                StunAttr::Unknown(t, v) => push_attr(&mut body, *t, v),
            }
        }

        let mut out = Vec::with_capacity(HEADER_LEN + body.len());
        out.extend_from_slice(&self.msg_type.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&body);
        out
    }

    /// 按 RFC 5389 §7.3 解码。`verify_fingerprint` 时对已解出的 FINGERPRINT 做 CRC 校验
    /// （FINGERPRINT 必须是最后一个属性；校验失败按非法消息处理）。
    pub fn decode(buf: &[u8]) -> Result<Self, StunError> {
        if buf.len() < HEADER_LEN {
            return Err(StunError::TooShort);
        }
        let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
        let body_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::BadMagic);
        }
        if buf.len() != HEADER_LEN + body_len {
            return Err(StunError::BadLength);
        }
        let mut txid = [0u8; 12];
        txid.copy_from_slice(&buf[8..20]);

        let mut attrs = Vec::new();
        let mut off = HEADER_LEN;
        let end = HEADER_LEN + body_len;
        while off < end {
            if end - off < 4 {
                return Err(StunError::BadAttribute);
            }
            let t = u16::from_be_bytes([buf[off], buf[off + 1]]);
            let l = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
            let padded = (l + 3) & !3;
            if end - off < 4 + padded {
                return Err(StunError::BadAttribute);
            }
            let v = &buf[off + 4..off + 4 + l];
            let attr = parse_attr(t, v, &txid)?;
            // FINGERPRINT 必须是最后一个属性（RFC 5389 §15.5）
            if t == ATTR_FINGERPRINT && off + 4 + padded != end {
                return Err(StunError::BadAttribute);
            }
            attrs.push(attr);
            off += 4 + padded;
        }
        Ok(Self { msg_type, txid, attrs })
    }

    pub fn get_xor_mapped(&self) -> Option<SocketAddrV4> {
        self.attrs.iter().find_map(|a| match a {
            StunAttr::XorMapped(a) => Some(*a),
            _ => None,
        })
    }
}

fn parse_attr(t: u16, v: &[u8], _txid: &[u8; 12]) -> Result<StunAttr, StunError> {
    // RFC 5389 §15.2：XOR-MAPPED 只 XOR magic cookie（不含 txid），故 _txid 未用
    match t {
        ATTR_XOR_MAPPED_ADDRESS | ATTR_MAPPED_ADDRESS => {
            if v.len() < 8 || v[1] != 0x01 {
                return Err(StunError::BadAttribute);
            }
            let port = u16::from_be_bytes([v[2], v[3]]);
            let raw = u32::from_be_bytes([v[4], v[5], v[6], v[7]]);
            let (ip, port) = if t == ATTR_XOR_MAPPED_ADDRESS {
                (Ipv4Addr::from(raw ^ MAGIC_COOKIE), port ^ (MAGIC_COOKIE >> 16) as u16)
            } else {
                (Ipv4Addr::from(raw), port)
            };
            Ok(if t == ATTR_XOR_MAPPED_ADDRESS {
                StunAttr::XorMapped(SocketAddrV4::new(ip, port))
            } else {
                StunAttr::Mapped(SocketAddrV4::new(ip, port))
            })
        }
        ATTR_USERNAME | ATTR_SOFTWARE => {
            let s = String::from_utf8_lossy(v).into_owned();
            Ok(if t == ATTR_USERNAME { StunAttr::Username(s) } else { StunAttr::Software(s) })
        }
        ATTR_ERROR_CODE => {
            if v.len() < 4 {
                return Err(StunError::BadAttribute);
            }
            Ok(StunAttr::ErrorCode {
                class: v[2] & 0x07,
                number: v[3],
                reason: String::from_utf8_lossy(&v[4..]).into_owned(),
            })
        }
        ATTR_FINGERPRINT => {
            if v.len() != 4 {
                return Err(StunError::BadAttribute);
            }
            Ok(StunAttr::Fingerprint(u32::from_be_bytes([v[0], v[1], v[2], v[3]])))
        }
        ATTR_OTHER_ADDRESS => {
            if v.len() < 8 || v[1] != 0x01 {
                return Err(StunError::BadAttribute);
            }
            Ok(StunAttr::OtherAddress(SocketAddrV4::new(
                Ipv4Addr::from(u32::from_be_bytes([v[4], v[5], v[6], v[7]])),
                u16::from_be_bytes([v[2], v[3]]),
            )))
        }
        ATTR_CHANGE_REQUEST => {
            if v.len() < 4 {
                return Err(StunError::BadAttribute);
            }
            Ok(StunAttr::ChangeRequest { change_ip: v[3] & 0x04 != 0, change_port: v[3] & 0x02 != 0 })
        }
        ATTR_MESH_CANDIDATES => {
            // ver(1)+count(1)，之后每条 7 字节；数量超上限拒绝
            if v.len() < 2 || v[0] != 1 {
                return Err(StunError::BadAttribute);
            }
            let count = v[1] as usize;
            if count > MESH_CAND_MAX || v.len() != 2 + count * MESH_CAND_ENTRY_LEN {
                return Err(StunError::BadAttribute);
            }
            let mut out = Vec::with_capacity(count);
            for i in 0..count {
                let o = 2 + i * MESH_CAND_ENTRY_LEN;
                out.push(CandidateWire {
                    ip: u32::from_be_bytes([v[o], v[o + 1], v[o + 2], v[o + 3]]),
                    port: u16::from_be_bytes([v[o + 4], v[o + 5]]),
                    kind: v[o + 6],
                });
            }
            Ok(StunAttr::MeshCandidates(out))
        }
        _ => Ok(StunAttr::Unknown(t, v.to_vec())),
    }
}

fn push_attr(body: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    body.extend_from_slice(&attr_type.to_be_bytes());
    body.extend_from_slice(&(value.len() as u16).to_be_bytes());
    body.extend_from_slice(value);
    let pad = (4 - value.len() % 4) % 4;
    body.extend(std::iter::repeat(0u8).take(pad));
}

/// IEEE CRC32（RFC 5389 §15.5 FINGERPRINT 用），位循环实现（PoC 帧率无关）。
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// 为消息追加 FINGERPRINT（FINGERPRINT = CRC32(前缀) ^ 0x5354554E，RFC 5389 §15.5）。
///
/// RFC 语义（RFC 5769 §2.2 官方向量验证）：CRC 输入 = 去掉 FINGERPRINT TLV
/// 的消息，但 header 的 message length **仍计入** FINGERPRINT 的 8 字节。
pub fn append_fingerprint(msg: &StunMessage) -> StunMessage {
    let mut m = msg.clone();
    let mut prefix = m.encode(); // 无 fingerprint 版本
    let len_with_fp = (prefix.len() - HEADER_LEN + 8) as u16;
    prefix[2..4].copy_from_slice(&len_with_fp.to_be_bytes());
    let crc = crc32(&prefix) ^ 0x5354_554E;
    m.attrs.push(StunAttr::Fingerprint(crc));
    m
}

/// 生成 Binding Request 事务 ID（xorshift64*，按纳秒时间播种；PoC 不需要 CSPRNG）。
pub fn new_txid() -> [u8; 12] {
    let mut seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E37_79B9_7F4A_7C15)
        ^ (std::process::id() as u64) << 32;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut txid = [0u8; 12];
    for chunk in txid.chunks_mut(8) {
        chunk.copy_from_slice(&next().to_be_bytes()[..chunk.len()]);
    }
    txid
}

/// Binding 交换结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingResult {
    /// 反射地址（XOR-MAPPED-ADDRESS 优先，回退 MAPPED-ADDRESS）
    pub mapped: SocketAddrV4,
    pub rtt: Duration,
}

/// 在给定 socket 上向 server 发起一次 Binding 交换（含 RFC 5389 §7.2.1 重传）。
///
/// `send`/`recv`（recvfrom 语义）由调用方注入：打洞 socket 与 STUN 共用同一本地端口
/// 是 NAT 打洞的关键；混入的非 STUN / 非本事务流量按噪音忽略。
/// 仅接受来源 == server 的响应（防反射干扰）。
/// 返回 `Err(StunError::ServerError)` 当对端返回 Binding Error Response。
pub fn binding_exchange_with<F, G>(
    txid: [u8; 12],
    server: SocketAddrV4,
    mut send: F,
    mut recv: G,
    rto: Duration,
    retries: u32,
) -> Result<BindingResult, StunError>
where
    F: FnMut(&[u8]) -> std::io::Result<usize>,
    G: FnMut(Duration) -> Option<(SocketAddrV4, Vec<u8>)>,
{
    let req = StunMessage::binding_request(txid).encode();
    let started = Instant::now();
    let mut wait = rto;
    for _ in 0..=retries {
        let _ = send(&req);
        let deadline = Instant::now() + wait;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if let Some((from, buf)) = recv(deadline - now) {
                if from != server {
                    continue; // 非 STUN server 来源——忽略
                }
                if let Ok(msg) = StunMessage::decode(&buf) {
                    if msg.txid != txid {
                        continue; // 非本事务（打洞流量/旧重传）——忽略
                    }
                    match msg.msg_type {
                        BINDING_RESPONSE => {
                            let mapped = msg
                                .get_xor_mapped()
                                .or_else(|| {
                                    msg.attrs.iter().find_map(|a| match a {
                                        StunAttr::Mapped(m) => Some(*m),
                                        _ => None,
                                    })
                                })
                                .ok_or(StunError::BadAttribute)?;
                            return Ok(BindingResult { mapped, rtt: started.elapsed() });
                        }
                        BINDING_ERROR_RESPONSE => {
                            if let Some((class, number, reason)) =
                                msg.attrs.iter().find_map(|a| match a {
                                    StunAttr::ErrorCode { class, number, reason } => {
                                        Some((*class, *number, reason.clone()))
                                    }
                                    _ => None,
                                })
                            {
                                return Err(StunError::ServerError { class, number, reason });
                            }
                            return Err(StunError::ServerError { class: 4, number: 0, reason: String::new() });
                        }
                        _ => continue,
                    }
                }
            }
        }
        wait = (wait * 2).min(Duration::from_secs(3)); // 线性指数退避，封顶 3s
    }
    Err(StunError::TooShort) // 语义：重传耗尽（调用方映射为 Timeout）
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;

    /// RFC 5769 §2.2 官方示例响应：txid 与 XOR-MAPPED-ADDRESS 192.0.2.1:32853。
    /// 用于校验解码、魔数、XOR 还原与 FINGERPRINT/CRC32 的正确性。
    const RFC_RESPONSE: &[u8] = &[
        0x01, 0x01, 0x00, 0x3c, // Binding Success, body 60
        0x21, 0x12, 0xa4, 0x42, // magic cookie
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, // txid
        0x80, 0x22, 0x00, 0x0b, b't', b'e', b's', b't', b' ', b'v', b'e', b'c', b't', b'o', b'r', b' ', // SOFTWARE "test vector"（官方向量补位字节为 0x20）
        0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, // XOR-MAPPED = 192.0.2.1:32853
        0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3,
        0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7, // MESSAGE-INTEGRITY (HMAC-SHA1)
        0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96, // FINGERPRINT (CRC32)
    ];

    #[test]
    fn decode_rfc5389_official_vector() {
        let msg = StunMessage::decode(RFC_RESPONSE).expect("RFC 官方向量必须可解码");
        assert_eq!(msg.msg_type, BINDING_RESPONSE);
        let mapped = msg.get_xor_mapped().expect("必须有 XOR-MAPPED-ADDRESS");
        assert_eq!(*mapped.ip(), Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(mapped.port(), 32853);
        // FINGERPRINT 0xC07D4C96 与 CRC32 实现一致性：CRC 输入 = 去掉 FP TLV 的
        // 消息，header length 保持 0x3c（RFC 5769 §2.2 语义：length 计入 FP）
        let prefix = &RFC_RESPONSE[..RFC_RESPONSE.len() - 8];
        let crc = crc32(prefix) ^ 0x5354_554E;
        assert_eq!(crc, 0xC07D_4C96, "CRC32 实现必须与 RFC 官方向量一致");
    }

    #[test]
    fn roundtrip_all_attrs() {
        let mut msg = StunMessage {
            msg_type: BINDING_RESPONSE,
            txid: new_txid(),
            attrs: vec![
                StunAttr::Software("meshlink-m0-4".into()),
                StunAttr::XorMapped(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 55555)),
                StunAttr::Mapped(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 55555)),
                StunAttr::ErrorCode { class: 4, number: 1, reason: "Try Alternate".into() },
                StunAttr::Username("peer:local".into()),
            ],
        };
        msg.attrs.retain(|a| !matches!(a, StunAttr::ErrorCode { .. }));
        let bytes = msg.encode();
        let back = StunMessage::decode(&bytes).unwrap();
        assert_eq!(back, msg);
    }

    #[test]
    fn fingerprint_roundtrip() {
        let msg = StunMessage::binding_request(new_txid());
        let with_fp = append_fingerprint(&msg);
        let bytes = with_fp.encode();
        let decoded = StunMessage::decode(&bytes).unwrap();
        let StunAttr::Fingerprint(fp) = decoded.attrs.last().expect("最后必须是 FINGERPRINT") else {
            panic!("最后属性必须是 FINGERPRINT");
        };
        // 按 RFC 5389 §15.5 复算：输入 = 去掉 FP TLV 的消息，header length 计入 FP 8 字节
        let mut prefix = bytes[..bytes.len() - 8].to_vec();
        let len_with_fp = (prefix.len() - HEADER_LEN + 8) as u16;
        prefix[2..4].copy_from_slice(&len_with_fp.to_be_bytes());
        assert_eq!(crc32(&prefix) ^ 0x5354_554E, *fp, "FINGERPRINT 必须可复算");
    }

    #[test]
    fn rejects_bad_magic_and_truncation() {
        let mut bytes = StunMessage::binding_request(new_txid()).encode();
        bytes[5] ^= 0xFF; // 破坏魔数
        assert_eq!(StunMessage::decode(&bytes), Err(StunError::BadMagic));
        assert_eq!(StunMessage::decode(&bytes[..15]), Err(StunError::TooShort));
        let mut bad_len = StunMessage::binding_request(new_txid()).encode();
        bad_len[3] = 0x7F;
        assert_eq!(StunMessage::decode(&bad_len), Err(StunError::BadLength));
    }

    #[test]
    fn error_response_surfaces_code() {
        let msg = StunMessage {
            msg_type: BINDING_ERROR_RESPONSE,
            txid: [9u8; 12],
            attrs: vec![StunAttr::ErrorCode { class: 4, number: 1, reason: "Try Alternate".into() }],
        };
        let bytes = msg.encode();
        let decoded = StunMessage::decode(&bytes).unwrap();
        match &decoded.attrs[0] {
            StunAttr::ErrorCode { class, number, reason } => {
                assert_eq!((*class, *number, reason.as_str()), (4, 1, "Try Alternate"));
            }
            other => panic!("期望 ErrorCode，得到 {other:?}"),
        }
    }

    /// binding_exchange_with 的注入式验证：假 server 回合法响应 / 超时重传耗尽。
    #[test]
    fn binding_exchange_over_injected_io() {
        let txid = new_txid();
        let server = SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 3478);

        // 假 server：收到请求后回 XOR-MAPPED = 8.8.8.8:40000（来源必须是 server）
        let resp = StunMessage {
            msg_type: BINDING_RESPONSE,
            txid,
            attrs: vec![StunAttr::XorMapped(SocketAddrV4::new(
                Ipv4Addr::new(8, 8, 8, 8),
                40000,
            ))],
        }
        .encode();
        let mut sent = 0usize;
        let result = binding_exchange_with(
            txid,
            server,
            |_| { sent += 1; Ok(resp.len()) },
            |timeout| {
                let _ = timeout;
                Some((server, resp.clone()))
            },
            Duration::from_millis(10),
            2,
        )
        .expect("交换必须成功");
        assert_eq!(result.mapped.port(), 40000);

        // 无响应 → 重传耗尽（3 次重传 + 首发 = 4 次 send）
        let mut sends = 0usize;
        let err = binding_exchange_with(
            txid,
            server,
            |_| { sends += 1; Ok(1) },
            |_| None,
            Duration::from_millis(1),
            3,
        )
        .unwrap_err();
        assert_eq!(sends, 4, "首播 + 3 次重传");
        assert_eq!(err, StunError::TooShort);
    }
}
