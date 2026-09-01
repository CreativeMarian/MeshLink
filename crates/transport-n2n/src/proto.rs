//! N2N 3.0 baseline 线协议（本仓库 Rust 实现，M1-2）。
//!
//! 结构对齐 n2n 3.0 stable：
//! - 公共头 `n2n_common_t` 语义（ttl / flags / version / packet_type / community）；
//! - 报文类型：REGISTER_SUPER / REGISTER_SUPER_ACK / QUERY_PEER / PUNCH /
//!   PACKET / REGISTER_SUPER_NACK；
//! - 社区模型：同一 community 的设备可互发现；
//! - 社区层加密：n2n 3.0 使用 AES-CCM；本实现以 **AES-256-GCM**（aes-gcm 0.10）
//!   承载社区密钥加密（协议语义一致，AEAD 强度等价），密钥由 network_id +
//!   community + 固定 salt 派生，**Supernode 不持有**——Supernode 只能路由
//!   密文帧，无法读到 MeshLink Noise 密文（更遑论明文 Overlay payload）。
//!
//! 边界硬性规则：
//! - 本 crate 是 N2N 符号的唯一宿主（与 transport-api lib.rs 约束一致）；
//! - 数据面：PACKET.payload = AES-GCM(社区密钥, nonce, MeshLink Noise 帧字节)；
//! - Supernode 仅按头部的 src/dst device_id 转发 PACKET，不解密不拆包。

use serde::{Deserialize, Serialize};

/// n2n 3.0 baseline 版本号（wire 头用）。
pub const N2N_VERSION: u16 = 0x0300;
/// community 名称最大长度（n2n 3.0 约定 32 字节）。
pub const COMMUNITY_MAX_LEN: usize = 32;
/// device_id 最大长度。
pub const DEVICE_ID_MAX_LEN: usize = 64;
/// 单个 UDP 帧最大长度（n2n PACKET 上限；MTU 暂不永久冻结，payload ≤ 65507-头部）。
pub const MAX_FRAME_LEN: usize = 65507;

/// 报文类型（对齐 n2n 3.0 common.h）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PacketType {
    /// 数据帧（社区层加密，载荷 = MeshLink Noise 帧）
    Packet = 0x00,
    /// 边缘 → 超节点：注册（带 device_id + cookie）
    RegisterSuper = 0x03,
    /// 超节点 → 边缘：注册应答 / QUERY_PEER 应答（携带对端端点）
    RegisterSuperAck = 0x04,
    /// 边缘 → 超节点：查询对端（target_device_id）
    QueryPeer = 0x05,
    /// 超节点 → 边缘 / 边缘 → 边缘：打洞（携带对端端点）
    Punch = 0x06,
    /// 超节点 → 边缘：注册/查询失败
    RegisterSuperNack = 0x07,
}

impl PacketType {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0x00 => Self::Packet,
            0x03 => Self::RegisterSuper,
            0x04 => Self::RegisterSuperAck,
            0x05 => Self::QueryPeer,
            0x06 => Self::Punch,
            0x07 => Self::RegisterSuperNack,
            _ => return None,
        })
    }
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// N2N 公共头（n2n_common_t 语义，big-endian wire）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct N2nHeader {
    pub ttl: u8,
    pub flags: u16,
    pub version: u16,
    pub packet_type: PacketType,
    pub community: String,
}

impl N2nHeader {
    pub fn new(community: impl Into<String>, packet_type: PacketType) -> Result<Self, String> {
        let community = community.into();
        if community.is_empty() || community.len() > COMMUNITY_MAX_LEN {
            return Err(format!("community 长度非法: {} 字节", community.len()));
        }
        Ok(Self { ttl: 15, flags: 0, version: N2N_VERSION, packet_type, community })
    }
}

/// REGISTER_SUPER 载荷：边缘告知超节点其 device_id。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSuper {
    pub device_id: String,
    pub cookie: u64,
}

/// REGISTER_SUPER_ACK / QUERY_PEER 应答载荷。
/// `peer_public`：QUERY_PEER 应答时为对端已注册端点；注册应答为 None。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSuperAck {
    pub sn_id: String,
    /// 本端点公网端点（打洞回执用）
    pub sn_public: String,
    /// 对端（被查询设备）已注册端点；无 = None
    pub peer_public: Option<String>,
    pub cookie: u64,
}

/// QUERY_PEER 载荷。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryPeer {
    pub target_device_id: String,
    pub cookie: u64,
}

/// PUNCH 载荷：Supernode 告知边缘对端端点。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Punch {
    pub target_device_id: String,
    /// 对端已注册端点
    pub peer_endpoint: String,
    pub cookie: u64,
}

/// NACK 载荷。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nack {
    pub reason: String,
    pub cookie: u64,
}

/// PACKET 载荷（数据面）：src/dst 设备 + 社区层加密的 Noise 帧。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Packet {
    pub src_device_id: String,
    pub dst_device_id: String,
    /// AES-256-GCM(社区密钥, nonce, Noise 帧字节)
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

/// 反序列化失败错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    Malformed(&'static str),
    UnknownType(u8),
    CommunityTooLong(usize),
}

impl std::fmt::Display for ProtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtoError::Malformed(why) => write!(f, "N2N 帧格式错误: {why}"),
            ProtoError::UnknownType(t) => write!(f, "未知 N2N 报文类型 0x{t:02x}"),
            ProtoError::CommunityTooLong(n) => write!(f, "community 过长: {n}"),
        }
    }
}

impl std::error::Error for ProtoError {}

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_be_bytes());
}
fn put_str(buf: &mut Vec<u8>, s: &str) {
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}
fn get_u16(b: &[u8], at: &mut usize) -> Result<u16, ProtoError> {
    if *at + 2 > b.len() {
        return Err(ProtoError::Malformed("u16 越界"));
    }
    let v = u16::from_be_bytes([b[*at], b[*at + 1]]);
    *at += 2;
    Ok(v)
}
fn get_u64(b: &[u8], at: &mut usize) -> Result<u64, ProtoError> {
    if *at + 8 > b.len() {
        return Err(ProtoError::Malformed("u64 越界"));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&b[*at..*at + 8]);
    *at += 8;
    Ok(u64::from_be_bytes(arr))
}
fn get_str(b: &[u8], at: &mut usize, max: usize) -> Result<String, ProtoError> {
    if *at + 1 > b.len() {
        return Err(ProtoError::Malformed("str 长度字节越界"));
    }
    let len = b[*at] as usize;
    *at += 1;
    if len > max || *at + len > b.len() {
        return Err(ProtoError::Malformed("str 越界"));
    }
    let s = String::from_utf8_lossy(&b[*at..*at + len]).into_owned();
    *at += len;
    Ok(s)
}

/// 编码：header + 载荷 → wire 帧。
pub fn encode(header: &N2nHeader, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + header.community.len() + payload.len());
    out.push(header.ttl);
    put_u16(&mut out, header.flags);
    put_u16(&mut out, header.version);
    out.push(header.packet_type.as_u8());
    put_str(&mut out, &header.community);
    out.extend_from_slice(payload);
    out
}

/// 解码：wire 帧 → (header, payload 区)。
pub fn decode(buf: &[u8]) -> Result<(N2nHeader, &[u8]), ProtoError> {
    if buf.len() < 7 {
        return Err(ProtoError::Malformed("头长度不足"));
    }
    let ttl = buf[0];
    let flags = u16::from_be_bytes([buf[1], buf[2]]);
    let version = u16::from_be_bytes([buf[3], buf[4]]);
    let ptype = PacketType::from_u8(buf[5]).ok_or(ProtoError::UnknownType(buf[5]))?;
    let mut at = 6;
    let community = get_str(buf, &mut at, COMMUNITY_MAX_LEN)?;
    Ok((
        N2nHeader { ttl, flags, version, packet_type: ptype, community },
        &buf[at..],
    ))
}

// ---------------------------------------------------------------------------
// 社区层加密（AES-256-GCM，n2n 3.0 社区加密语义）
// ---------------------------------------------------------------------------

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

/// 社区密钥派生 salt（仅用于派生，Supernode 侧不存在）。
const COMMUNITY_SALT: &[u8] = b"meshlink-n2n-community-v1";

/// 从 network_id + community 派生 32 字节社区密钥。
/// 说明：社区加密为纵深防御——MeshLink Noise 已是数据面的真正保密层；
/// 社区密钥即便泄露，Supernode 也只能看到 Noise 密文。
pub fn community_key(network_id: &str, community: &str) -> [u8; 32] {
    use blake2::digest::{Digest, FixedOutput};
    use blake2::Blake2s256;
    let mut hasher = Blake2s256::new();
    hasher.update(COMMUNITY_SALT);
    hasher.update(network_id.as_bytes());
    hasher.update(b"|");
    hasher.update(community.as_bytes());
    let out: [u8; 32] = hasher.finalize_fixed().into();
    out
}

/// 社区层加密：返回 ciphertext || tag（AES-256-GCM）。
pub fn community_seal(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥构建失败: {e}"))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|e| format!("社区加密失败: {e}"))
}

/// 社区层解密。
pub fn community_open(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| format!("密钥构建失败: {e}"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| format!("社区解密失败: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = N2nHeader::new("meshlink-net", PacketType::RegisterSuper).unwrap();
        let wire = encode(&h, b"payload");
        let (dh, dp) = decode(&wire).unwrap();
        assert_eq!(dh, h);
        assert_eq!(dp, b"payload");
        assert_eq!(dh.version, N2N_VERSION);
    }

    #[test]
    fn packet_payload_roundtrip() {
        let p = Packet {
            src_device_id: "dev_a".into(),
            dst_device_id: "dev_b".into(),
            ciphertext: vec![1, 2, 3],
            nonce: [7u8; 12],
        };
        let body = serde_json::to_vec(&p).unwrap();
        let h = N2nHeader::new("net", PacketType::Packet).unwrap();
        let wire = encode(&h, &body);
        let (_, dp) = decode(&wire).unwrap();
        let dp: Packet = serde_json::from_slice(dp).unwrap();
        assert_eq!(dp, p);
    }

    #[test]
    fn community_seal_open_roundtrip() {
        let key = community_key("net-1", "meshlink-net");
        let nonce = [9u8; 12];
        let ct = community_seal(&key, &nonce, b"noise-frame-bytes").unwrap();
        assert_ne!(&ct[..], b"noise-frame-bytes");
        let pt = community_open(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, b"noise-frame-bytes");

        // 错误密钥/篡改 → 解密失败
        let wrong = community_key("net-2", "meshlink-net");
        assert!(community_open(&wrong, &nonce, &ct).is_err());
        let mut tampered = ct.clone();
        if !tampered.is_empty() {
            tampered[0] ^= 0xFF;
        }
        assert!(community_open(&key, &nonce, &tampered).is_err());
    }

    #[test]
    fn malformed_rejected() {
        assert!(decode(&[0; 3]).is_err());
        assert!(decode(&[15, 0, 0, 3, 0, 0x05, 40]).is_err()); // community 长度越界
    }

    #[test]
    fn community_len_boundary() {
        assert!(N2nHeader::new("", PacketType::Packet).is_err());
        let long = "x".repeat(COMMUNITY_MAX_LEN + 1);
        assert!(N2nHeader::new(long, PacketType::Packet).is_err());
        let ok = "x".repeat(COMMUNITY_MAX_LEN);
        assert!(N2nHeader::new(ok, PacketType::Packet).is_ok());
    }
}
