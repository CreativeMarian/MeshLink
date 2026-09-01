//! DirectLink 会话帧 v1 编解码（schemas/frame/directlink_frame_v1.md）。
//!
//! ```text
//! 偏移  大小  字段
//! 0     2    magic      = 0x4D44（'MD'，Mesh Direct）[u16 BE]
//! 2     1    version    = 1                          [u8]
//! 3     1    flags      bit0 加密会话帧 / bit1 keepalive(保留) /
//!                       bit2 Noise 握手消息 / bit3 握手 intro（M0-5）
//! 4     16   session_id 加密会话 16 字节随机标识        [bytes]
//! 20    4    epoch_id   密钥纪元（初始握手=1，重握手+1） [u32 BE]
//! 24    8    seq        方向内单调递增，从 0 开始        [u64 BE]
//! 32    n    body       密文 / 握手消息 / intro+握手消息
//! ```
//!
//! flags bit2/bit3（M0-5 实现补充）：
//! - bit2 置位 = Noise IK 握手消息（epoch 1 初始握手或 epoch n+1 重握手）；
//! - bit3 置位 = initiator → responder 方向的 msg1，body 头部带**明文** intro
//!   `[u16 BE dev_len][dev bytes]`（responder 据此构造 prologue 的
//!   initiator_device_id；responder 的 msg2 不带 intro）。
//!   intro 明文不泄露秘密（device_id 本就随 Session Code / Controller 公开），
//!   且被 prologue 绑定——篡改会使握手解密失败。

/// 帧魔数 'MD'（Mesh Direct）。与 MTU echo（0x4D54）区分于第二字节；
/// 与 STUN 不冲突（STUN 消息类型首 2 bit 必为 00，首字节 < 0x40）。
pub const FRAME_MAGIC: [u8; 2] = [0x4D, 0x44];
pub const FRAME_VERSION: u8 = 1;
/// 固定头部长度：magic(2) + version(1) + flags(1) + session_id(16) + epoch(4) + seq(8)。
pub const FRAME_HEADER_LEN: usize = 32;

/// bit0：加密会话数据帧。
pub const FLAG_ENCRYPTED: u8 = 0b0000_0001;
/// bit1：keepalive（保留，未启用——NAT 映射保活仍走 STUN meshlink-keepalive）。
pub const FLAG_KEEPALIVE: u8 = 0b0000_0010;
/// bit2：Noise 握手消息。
pub const FLAG_HANDSHAKE: u8 = 0b0000_0100;
/// bit3：握手 intro（明文 initiator device_id 前缀）。
pub const FLAG_INTRO: u8 = 0b0000_1000;
/// 已定义 flag 位全集（未知位 = 版本演进问题，直接拒绝）。
const KNOWN_FLAGS: u8 = FLAG_ENCRYPTED | FLAG_KEEPALIVE | FLAG_HANDSHAKE | FLAG_INTRO;

/// 帧解码错误（不可信输入：只拒绝、不 panic）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    BadMagic,
    BadVersion,
    UnknownFlags(u8),
    BadIntro,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::TooShort => write!(f, "frame_too_short"),
            FrameError::BadMagic => write!(f, "frame_bad_magic"),
            FrameError::BadVersion => write!(f, "frame_bad_version"),
            FrameError::UnknownFlags(v) => write!(f, "frame_unknown_flags({v:#x})"),
            FrameError::BadIntro => write!(f, "frame_bad_intro"),
        }
    }
}

/// 解码后的帧视图（零拷贝借用原始 UDP payload）。
#[derive(Debug, PartialEq, Eq)]
pub struct FrameView<'a> {
    pub flags: u8,
    pub session_id: [u8; 16],
    pub epoch_id: u32,
    pub seq: u64,
    /// 头部之后的全部字节（密文 / 握手消息 / intro+握手消息）
    pub body: &'a [u8],
}

impl FrameView<'_> {
    pub fn is_handshake(&self) -> bool {
        self.flags & FLAG_HANDSHAKE != 0
    }
    pub fn has_intro(&self) -> bool {
        self.flags & FLAG_INTRO != 0
    }

    /// 解析 intro：`[u16 BE len][dev bytes]` + 剩余为 Noise 握手消息。
    /// 仅 bit3 置位的帧调用。
    pub fn intro(&self) -> Result<(&str, &[u8]), FrameError> {
        if !self.has_intro() {
            return Err(FrameError::BadIntro);
        }
        if self.body.len() < 2 {
            return Err(FrameError::BadIntro);
        }
        let dev_len = u16::from_be_bytes([self.body[0], self.body[1]]) as usize;
        if self.body.len() < 2 + dev_len || dev_len == 0 || dev_len > 64 {
            return Err(FrameError::BadIntro);
        }
        let dev = std::str::from_utf8(&self.body[2..2 + dev_len]).map_err(|_| FrameError::BadIntro)?;
        Ok((dev, &self.body[2 + dev_len..]))
    }
}

/// 解码（严格：长度/魔数/版本/已知 flag 位）。
pub fn decode(buf: &[u8]) -> Result<FrameView<'_>, FrameError> {
    if buf.len() < FRAME_HEADER_LEN {
        return Err(FrameError::TooShort);
    }
    if buf[0..2] != FRAME_MAGIC {
        return Err(FrameError::BadMagic);
    }
    if buf[2] != FRAME_VERSION {
        return Err(FrameError::BadVersion);
    }
    let flags = buf[3];
    if flags & !KNOWN_FLAGS != 0 {
        return Err(FrameError::UnknownFlags(flags & !KNOWN_FLAGS));
    }
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&buf[4..20]);
    let epoch_id = u32::from_be_bytes([buf[20], buf[21], buf[22], buf[23]]);
    let seq = u64::from_be_bytes(buf[24..32].try_into().unwrap());
    Ok(FrameView { flags, session_id, epoch_id, seq, body: &buf[FRAME_HEADER_LEN..] })
}

/// 编码：把 header + body 写入 `out`（清空后追加）。
pub fn encode(flags: u8, session_id: &[u8; 16], epoch_id: u32, seq: u64, body: &[u8], out: &mut Vec<u8>) {
    out.clear();
    out.reserve(FRAME_HEADER_LEN + body.len());
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.push(flags);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&epoch_id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(body);
}

/// 编码握手 msg1 帧（bit2|bit3，body = intro 前缀 + Noise 消息）。
pub fn encode_handshake_msg1(
    session_id: &[u8; 16],
    epoch_id: u32,
    initiator_device_id: &str,
    noise_msg: &[u8],
    out: &mut Vec<u8>,
) {
    let mut body = Vec::with_capacity(2 + initiator_device_id.len() + noise_msg.len());
    body.extend_from_slice(&(initiator_device_id.len() as u16).to_be_bytes());
    body.extend_from_slice(initiator_device_id.as_bytes());
    body.extend_from_slice(noise_msg);
    encode(FLAG_HANDSHAKE | FLAG_INTRO, session_id, epoch_id, 0, &body, out);
}

/// 编码握手 msg2 帧（bit2，无 intro）。
pub fn encode_handshake_msg2(session_id: &[u8; 16], epoch_id: u32, noise_msg: &[u8], out: &mut Vec<u8>) {
    encode(FLAG_HANDSHAKE, session_id, epoch_id, 0, noise_msg, out);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> [u8; 16] {
        let mut s = [0u8; 16];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    #[test]
    fn roundtrip_data_frame() {
        let s = sid();
        let mut buf = Vec::new();
        encode(FLAG_ENCRYPTED, &s, 7, 12345, b"ciphertext-bytes", &mut buf);
        assert_eq!(buf.len(), FRAME_HEADER_LEN + 16);
        let f = decode(&buf).expect("decode");
        assert_eq!(f.flags, FLAG_ENCRYPTED);
        assert_eq!(f.session_id, s);
        assert_eq!(f.epoch_id, 7);
        assert_eq!(f.seq, 12345);
        assert_eq!(f.body, b"ciphertext-bytes");
        assert!(!f.is_handshake());
    }

    #[test]
    fn roundtrip_handshake_with_intro() {
        let s = sid();
        let mut buf = Vec::new();
        encode_handshake_msg1(&s, 1, "join-dev-01", b"NOISE-MSG1", &mut buf);
        let f = decode(&buf).expect("decode");
        assert!(f.is_handshake());
        assert!(f.has_intro());
        let (dev, msg) = f.intro().expect("intro");
        assert_eq!(dev, "join-dev-01");
        assert_eq!(msg, b"NOISE-MSG1");
    }

    #[test]
    fn rejects_malformed() {
        let s = sid();
        let mut buf = Vec::new();
        encode(FLAG_ENCRYPTED, &s, 1, 0, b"payload", &mut buf);
        // 过短
        assert_eq!(decode(&buf[..31]), Err(FrameError::TooShort));
        // 魔数错误
        let mut bad = buf.clone();
        bad[1] = 0x54;
        assert_eq!(decode(&bad), Err(FrameError::BadMagic));
        // 版本错误
        let mut bad = buf.clone();
        bad[2] = 2;
        assert_eq!(decode(&bad), Err(FrameError::BadVersion));
        // 未知 flag 位
        let mut bad = buf.clone();
        bad[3] |= 0x80;
        assert_eq!(decode(&bad), Err(FrameError::UnknownFlags(0x80)));
    }

    #[test]
    fn rejects_bad_intro() {
        let s = sid();
        // 声称 intro 但 body 只有 1 字节
        let mut body = vec![0u8; 1];
        body.extend_from_slice(b"x");
        let mut buf = Vec::new();
        encode(FLAG_HANDSHAKE | FLAG_INTRO, &s, 1, 0, &body, &mut buf);
        assert_eq!(decode(&buf).expect("decode").intro(), Err(FrameError::BadIntro));
        // dev_len 超出 body 实长
        let body = [0u8, 9, b'a'];
        let mut buf = Vec::new();
        encode(FLAG_HANDSHAKE | FLAG_INTRO, &s, 1, 0, &body, &mut buf);
        assert_eq!(decode(&buf).expect("decode").intro(), Err(FrameError::BadIntro));
    }

    /// MD44 帧不得被误判为 STUN/MTU：帧首字节的类型前缀互斥（文档断言）。
    #[test]
    fn magic_disjoint_from_stun_and_mtu() {
        // STUN：msg_type 首 2 bit = 00 → 首字节 < 0x40；MD/MT 首字节 0x4D
        assert!(FRAME_MAGIC[0] >= 0x40);
        assert_eq!(FRAME_MAGIC[1], 0x44);
        assert_eq!(crate::transport::MTU_MAGIC, [0x4D, 0x54]);
        assert_ne!(FRAME_MAGIC, crate::transport::MTU_MAGIC);
    }
}
