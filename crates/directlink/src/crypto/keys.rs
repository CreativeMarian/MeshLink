//! 设备静态 X25519 密钥身份（M0-5）。
//!
//! - 私钥：`Zeroizing<[u8; 32]>`（Drop 即擦除——自持密钥显式清理，ADR NOISE_KEY_LIFECYCLE）；
//! - 公钥指纹：**完整公钥 hex（64 字符）**。PoC/Controller 早期阶段用全钥比对
//!   （零额外依赖、比对即精确）；Controller 注册表落地后可切换 BLAKE2s-128 摘要，
//!   比较语义不变；
//! - 生成：`snow::Builder::generate_keypair()`（默认 resolver 的 CSPRNG）。
//!
//! 注意：PoC 每次进程运行生成新身份；持久化（secure-store/DPAPI）在
//! Controller/Friend Invite 里程碑接入——届时注册表按 device_id 绑定指纹。

use mesh_common::{ErrorCode, MeshError};
use snow::Keypair;
use zeroize::Zeroizing;

/// X25519 静态公钥长度。
pub const STATIC_KEY_LEN: usize = 32;

/// 设备静态密钥身份。
pub struct StaticIdentity {
    device_id: String,
    /// 私钥（Drop 时 zeroize）
    private: Zeroizing<[u8; STATIC_KEY_LEN]>,
    public: [u8; STATIC_KEY_LEN],
}

impl StaticIdentity {
    /// 生成新身份（CSPRNG）。
    pub fn generate(device_id: &str) -> Result<Self, MeshError> {
        validate_device_id(device_id)?;
        let Keypair { private, public } = snow::Builder::new(crate::crypto::pattern())
            .generate_keypair()
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("X25519 keypair 生成失败: {e}")))?;
        let private = Zeroizing::new(private.try_into().map_err(|v: Vec<u8>| {
            MeshError::new(ErrorCode::Internal, format!("私钥长度 {} 非法", v.len()))
        })?);
        Ok(Self {
            device_id: device_id.to_string(),
            private,
            public: public.try_into().expect("snow 公钥恒为 32 字节"),
        })
    }

    /// 从已持久化的密钥对重建身份（secure-store/DPAPI 路径：设备重启后
    /// 保持相同公钥与 device_id——Controller 注册表绑定不变）。
    /// 公私钥一致性不在此处验证（X25519 公钥由私钥派生，握手层会暴露不一致）。
    pub fn from_parts(
        device_id: &str,
        private: [u8; STATIC_KEY_LEN],
        public: [u8; STATIC_KEY_LEN],
    ) -> Result<Self, MeshError> {
        validate_device_id(device_id)?;
        Ok(Self {
            device_id: device_id.to_string(),
            private: Zeroizing::new(private),
            public,
        })
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// 私钥引用（仅构造 snow Builder 时使用，禁止复制出去）。
    pub(crate) fn private(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.private
    }

    pub fn public(&self) -> &[u8; STATIC_KEY_LEN] {
        &self.public
    }

    /// 公钥指纹 = 完整公钥 hex（64 小写字符）。
    pub fn fingerprint(&self) -> String {
        hex::encode_lower(&self.public)
    }
}

/// device_id 约束：非空、≤64 字符、ASCII 可见字符（prologue/intro 长度前缀需要）。
fn validate_device_id(id: &str) -> Result<(), MeshError> {
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_graphic()) {
        return Err(MeshError::new(ErrorCode::ConfigInvalid, "device_id 非法（空/超长/含不可见字符）"));
    }
    Ok(())
}

/// 十六进制小写编解码（零依赖：32 字节 ↔ 64 字符）。
pub mod hex {
    pub fn encode_lower(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).expect("hex digit"));
            s.push(char::from_digit((b & 0xF) as u32, 16).expect("hex digit"));
        }
        s
    }

    /// 解析 64 字符 hex → 32 字节公钥（不可信输入：只拒绝不 panic）。
    pub fn decode_key32(s: &str) -> Option<[u8; 32]> {
        let s = s.trim();
        if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            let hi = s.as_bytes()[i * 2] as char;
            let lo = s.as_bytes()[i * 2 + 1] as char;
            *b = (hi.to_digit(16)? as u8) << 4 | (lo.to_digit(16)? as u8);
        }
        Some(out)
    }
}

/// 指纹字符串 → 比较用归一化（当前 = 原值小写 trim；将来摘要指纹同样收敛到字符串比对）。
pub fn fingerprint_matches(fingerprint: &str, public: &[u8; 32]) -> bool {
    fingerprint.trim().eq_ignore_ascii_case(&hex::encode_lower(public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_fingerprint_roundtrip() {
        let id = StaticIdentity::generate("dev-test-01").expect("generate");
        let fp = id.fingerprint();
        assert_eq!(fp.len(), 64);
        let key = hex::decode_key32(&fp).expect("parse fingerprint");
        assert_eq!(&key, id.public());
        assert!(fingerprint_matches(&fp, id.public()));
        assert!(!fingerprint_matches("00", id.public()));
    }

    #[test]
    fn fingerprint_is_case_insensitive() {
        let id = StaticIdentity::generate("dev-test-02").expect("generate");
        let fp_upper = id.fingerprint().to_uppercase();
        assert!(fingerprint_matches(&fp_upper, id.public()));
    }

    #[test]
    fn rejects_invalid_device_id() {
        assert!(StaticIdentity::generate("").is_err());
        assert!(StaticIdentity::generate(&"x".repeat(65)).is_err());
        assert!(StaticIdentity::generate("has space").is_err());
    }

    #[test]
    fn decode_key32_rejects_malformed() {
        assert!(hex::decode_key32("").is_none());
        assert!(hex::decode_key32("zz").is_none());
        assert!(hex::decode_key32(&"0".repeat(63)).is_none());
        assert!(hex::decode_key32(&"0".repeat(65)).is_none());
        assert!(hex::decode_key32(&"ab".repeat(32)).is_some());
    }

    /// 自持私钥 Drop 后必须擦除（ADR 验证方法论：断言缓冲区全零）。
    #[test]
    fn private_key_zeroed_on_drop() {
        // Box 保证 identity 地址稳定（栈上 drop 可能被编译器移动后再析构，
        // 悬垂指针会指向旧位置导致假失败）。
        let id = Box::new(StaticIdentity::generate("dev-zeroize").expect("generate"));
        let ptr: *const [u8; 32] = id.private().as_ptr() as *const [u8; 32];
        let before = unsafe { std::ptr::read(ptr) };
        assert!(before.iter().any(|&b| b != 0), "私钥不应全零");
        drop(id);
        let after = unsafe { std::ptr::read(ptr) };
        assert!(after.iter().all(|&b| b == 0), "Drop 后私钥缓冲必须全零");
    }
}
