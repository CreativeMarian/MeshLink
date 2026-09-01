//! 设备静态身份持久化（Controller MVP）。
//!
//! 职责：
//! - 设备第一次运行：生成一次 X25519 static keypair 后**稳定保存**；
//!   重启后公钥/device_id 不变（Controller 注册表绑定不漂移）；
//! - 私钥**禁止明文落盘**：DPAPI(CurrentUser) 加密后存储；
//! - 文件 ACL 收敛为「当前用户 + SYSTEM、PROTECTED」（无继承）；
//! - Controller credential（注册一次性下发）同样 DPAPI 加密保存。
//!
//! 详见 `docs/DEVICE_IDENTITY.md`（rotation / revocation / re-enrollment）。

pub mod acl;
pub mod dpapi;

use mesh_common::{ErrorCode, MeshError};
use serde::{Deserialize, Serialize};
use snow::Keypair;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// 与数据面一致的 Noise 模式（仅用于 keypair 生成的 CSPRNG 入口）。
fn noise_pattern() -> snow::params::NoiseParams {
    "Noise_IK_25519_ChaChaPoly_BLAKE2s".parse().expect("内置合法 Noise 参数")
}

/// 存储文件版本（将来格式演进时迁移判断）。
const FORMAT_VERSION: u32 = 1;

/// 默认目录：`%LOCALAPPDATA%\MeshLink`（用户级，权限天然收敛）。
fn default_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("MeshLink")
}

/// 落盘 JSON（私钥/credential 为 DPAPI 密文的 base64）。
#[derive(Serialize, Deserialize)]
struct StoredFile {
    version: u32,
    device_id: String,
    /// 公钥 hex 64（明文：本就注册到 Controller 公开）。
    public_key_hex: String,
    /// DPAPI(CurrentUser) 加密的私钥 32 字节（base64）。
    private_key_dpapi_b64: String,
    /// DPAPI 加密的 Controller credential（base64；可选——未注册时缺省）。
    controller_credential_dpapi_b64: Option<String>,
}

/// 内存形态的设备身份（私钥 Zeroizing；credential 为明文，仅本进程可见）。
pub struct DeviceIdentity {
    pub device_id: String,
    /// X25519 静态公钥（32 字节）。
    pub public_key: [u8; 32],
    /// X25519 私钥（Drop 即擦除；禁止明文序列化）。
    pub private_key: Zeroizing<[u8; 32]>,
    /// Controller bearer credential（注册响应一次性下发；DPAPI 落盘）。
    pub controller_credential: Option<String>,
}

/// 设备身份存储（目录级；文件名固定 `device-identity.json`）。
pub struct DeviceIdentityStore {
    dir: PathBuf,
}

impl DeviceIdentityStore {
    /// 指定目录打开（测试用）；目录不存在则惰性创建。
    pub fn open(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// 默认 `%LOCALAPPDATA%\MeshLink`。
    pub fn open_default() -> Self {
        Self::open(default_dir())
    }

    /// 首次运行：生成一次性 X25519 keypair + device_id 并持久化；之后：
    /// 永远返回同一身份（公钥/device_id 稳定，Controller 注册绑定不漂移）。
    ///
    /// device_id = `dev-` + 公钥前 8 字节 hex（无需额外熵源；持久化后与公钥
    /// 解耦——将来 key rotation 时 device_id 不变，见 DEVICE_IDENTITY.md）。
    /// 返回 (身份, 是否首次生成)。
    pub fn create_or_load(&self) -> Result<(DeviceIdentity, bool), MeshError> {
        if let Some(id) = self.load()? {
            return Ok((id, false));
        }
        let Keypair { private, public } = snow::Builder::new(noise_pattern())
            .generate_keypair()
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("X25519 keypair 生成失败: {e}")))?;
        let public: [u8; 32] = public.try_into().map_err(|v: Vec<u8>| {
            MeshError::new(ErrorCode::Internal, format!("公钥长度 {} 非法", v.len()))
        })?;
        let public_hex = encode_hex32(&public);
        let device_id = format!("dev-{}", &public_hex[..16]);
        let identity = DeviceIdentity {
            device_id,
            public_key: public,
            private_key: Zeroizing::new(
                private.try_into().map_err(|v: Vec<u8>| {
                    MeshError::new(ErrorCode::Internal, format!("私钥长度 {} 非法", v.len()))
                })?,
            ),
            controller_credential: None,
        };
        self.save(&identity)?;
        Ok((identity, true))
    }

    fn file_path(&self) -> PathBuf {
        self.dir.join("device-identity.json")
    }

    /// 读取身份；`Ok(None)` = 首次运行（尚无身份）。
    /// DPAPI 解密失败（跨用户复制/损坏）按损坏处理并报错——绝不静默重建
    /// （重建 = 新公钥 = Controller DEVICE_KEY_MISMATCH，必须显式走 re-enrollment）。
    pub fn load(&self) -> Result<Option<DeviceIdentity>, MeshError> {
        let path = self.file_path();
        let blob = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(MeshError::new(ErrorCode::Internal, format!("读取身份文件失败: {e}"))),
        };
        let stored: StoredFile = serde_json::from_slice(&blob)
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("身份文件格式非法: {e}")))?;
        if stored.version != FORMAT_VERSION {
            return Err(MeshError::new(ErrorCode::Internal,
                format!("身份文件版本 {} 不支持（当前 {}）", stored.version, FORMAT_VERSION)));
        }
        let public_key = decode_hex32(&stored.public_key_hex)?;
        let cipher = b64_decode(&stored.private_key_dpapi_b64)?;
        let plain = dpapi::unprotect(&cipher)?;
        let private_key = Zeroizing::new(
            plain.try_into().map_err(|v: Vec<u8>| {
                MeshError::new(ErrorCode::Internal, format!("DPAPI 明文私钥长度 {} 非法", v.len()))
            })?,
        );
        let controller_credential = stored
            .controller_credential_dpapi_b64
            .map(|b64| {
                let c = b64_decode(&b64)?;
                dpapi::unprotect(&c).map(|v| String::from_utf8(v).map_err(|_| {
                    MeshError::new(ErrorCode::Internal, "credential 非 UTF-8")
                }))
            })
            .transpose()?
            .transpose()?;
        Ok(Some(DeviceIdentity { device_id: stored.device_id, public_key, private_key, controller_credential }))
    }

    /// 保存身份（首次生成或 credential 更新）。写入 → 立即收紧 ACL →
    /// 原子替换（临时文件 + rename，防半写状态）。
    pub fn save(&self, identity: &DeviceIdentity) -> Result<(), MeshError> {
        std::fs::create_dir_all(&self.dir)
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("创建身份目录失败: {e}")))?;
        let private_cipher = dpapi::protect(identity.private_key.as_slice())?;
        let cred_cipher = identity
            .controller_credential
            .as_deref()
            .map(|c| dpapi::protect(c.as_bytes()))
            .transpose()?;
        let stored = StoredFile {
            version: FORMAT_VERSION,
            device_id: identity.device_id.clone(),
            public_key_hex: encode_hex32(&identity.public_key),
            private_key_dpapi_b64: b64_encode(&private_cipher),
            controller_credential_dpapi_b64: cred_cipher.map(|c| b64_encode(&c)),
        };
        let blob = serde_json::to_vec(&stored)
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("序列化身份失败: {e}")))?;

        let final_path = self.file_path();
        let tmp_path = self.dir.join("device-identity.json.tmp");
        std::fs::write(&tmp_path, &blob)
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("写入身份临时文件失败: {e}")))?;
        // 临时文件同样收紧 ACL（rename 携带 ACL）。
        acl::restrict_file_acl(&tmp_path)?;
        std::fs::rename(&tmp_path, &final_path)
            .map_err(|e| MeshError::new(ErrorCode::Internal, format!("身份文件原子替换失败: {e}")))?;
        Ok(())
    }

    /// 只更新 credential（注册完成后回填；其余字段不变）。
    pub fn update_credential(&self, device_id: &str, public_key: &[u8; 32],
        private_key: &[u8; 32], credential: &str) -> Result<(), MeshError> {
        let identity = DeviceIdentity {
            device_id: device_id.to_string(),
            public_key: *public_key,
            private_key: Zeroizing::new(*private_key),
            controller_credential: Some(credential.to_string()),
        };
        self.save(&identity)
    }
}

fn encode_hex32(key: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in key {
        s.push(char::from_digit((b >> 4) as u32, 16).expect("hex"));
        s.push(char::from_digit((b & 0xF) as u32, 16).expect("hex"));
    }
    s
}

fn decode_hex32(s: &str) -> Result<[u8; 32], MeshError> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(MeshError::new(ErrorCode::Internal, "公钥 hex 非法"));
    }
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = s.as_bytes()[i * 2] as char;
        let lo = s.as_bytes()[i * 2 + 1] as char;
        *b = (hi.to_digit(16).expect("hex") as u8) << 4 | (lo.to_digit(16).expect("hex") as u8);
    }
    Ok(out)
}

// base64（标准字母表，无依赖实现：DPAPI 密文 ≤ 数百字节）。
const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

fn b64_decode(s: &str) -> Result<Vec<u8>, MeshError> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 4 != 0 {
        return Err(MeshError::new(ErrorCode::Internal, "base64 长度非法"));
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.as_bytes().chunks(4) {
        let mut n: u32 = 0;
        let mut pad = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' {
                pad += 1;
                0
            } else {
                B64.iter().position(|&x| x == c).ok_or_else(|| {
                    MeshError::new(ErrorCode::Internal, "base64 字符非法")
                })? as u32
            };
            n |= v << (18 - i * 6);
        }
        if pad > 2 {
            return Err(MeshError::new(ErrorCode::Internal, "base64 padding 非法"));
        }
        out.push((n >> 16) as u8);
        if pad < 2 { out.push((n >> 8) as u8); }
        if pad < 1 { out.push(n as u8); }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(tag: &str) -> DeviceIdentityStore {
        let dir = std::env::temp_dir().join(format!("meshlink-id-store-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        DeviceIdentityStore::open(dir)
    }

    fn sample_identity() -> DeviceIdentity {
        let private = Zeroizing::new([42u8; 32]);
        DeviceIdentity {
            device_id: "dev-test-01".into(),
            public_key: [7u8; 32],
            private_key: private,
            controller_credential: Some("mlk_test_credential".into()),
        }
    }

    #[test]
    fn save_load_roundtrip_and_stable_identity() {
        let st = temp_store("roundtrip");
        assert!(st.load().expect("load empty").is_none(), "首次运行应无身份");
        st.save(&sample_identity()).expect("save");
        let id = st.load().expect("load").expect("stored");
        assert_eq!(id.device_id, "dev-test-01");
        assert_eq!(id.public_key, [7u8; 32]);
        assert_eq!(id.private_key.as_slice(), [42u8; 32]);
        assert_eq!(id.controller_credential.as_deref(), Some("mlk_test_credential"));

        // 重启语义：再次 load = 相同身份（公钥稳定）。
        let id2 = st.load().expect("load2").expect("stored");
        assert_eq!(id2.public_key, id.public_key);
        assert_eq!(id2.private_key.as_slice(), id.private_key.as_slice());
    }

    #[test]
    fn private_key_never_plaintext_on_disk() {
        let st = temp_store("plaintext");
        st.save(&sample_identity()).expect("save");
        let blob = std::fs::read(st.file_path()).expect("read file");
        let text = String::from_utf8_lossy(&blob);
        assert!(!text.contains("mlk_test_credential"), "credential 明文不得落盘");
        // 私钥 [42;32] 的 hex 与 DPAPI 密文 base64 均非明文——直接断言 hex 串不存在。
        assert!(!text.contains("2a2a2a2a"), "私钥 hex 明文不得落盘");
        assert!(!text.contains(&"*".repeat(32)), "私钥明文不得落盘");
    }

    #[test]
    fn update_credential_keeps_identity() {
        let st = temp_store("updatecred");
        st.save(&sample_identity()).expect("save");
        st.update_credential("dev-test-01", &[7u8; 32], &[42u8; 32], "mlk_new_cred")
            .expect("update");
        let id = st.load().expect("load").expect("stored");
        assert_eq!(id.public_key, [7u8; 32]);
        assert_eq!(id.controller_credential.as_deref(), Some("mlk_new_cred"));
    }

    #[test]
    fn tampered_file_rejected_not_regenerated() {
        let st = temp_store("tampered");
        st.save(&sample_identity()).expect("save");
        // 篡改私钥 DPAPI 密文 → 解密失败 → 报错（绝不静默重建新身份）。
        let bad = serde_json::json!({
            "version": 1,
            "device_id": "dev-test-01",
            "public_key_hex": encode_hex32(&[7u8; 32]),
            "private_key_dpapi_b64": "AAAA",
            "controller_credential_dpapi_b64": serde_json::Value::Null,
        });
        std::fs::write(st.file_path(), serde_json::to_vec(&bad).unwrap()).unwrap();
        let result = st.load();
        assert!(result.is_err(), "篡改必须报错（绝不静默重建新身份）");
        let err = result.err().unwrap();
        assert!(err.details.contains("DPAPI"), "错误应来自 DPAPI 解密: {}", err.details);
    }

    #[test]
    fn create_or_load_generates_once_and_is_stable() {
        let st = temp_store("createorload");
        let (id1, first) = st.create_or_load().expect("first run");
        assert!(first, "首次运行应生成新身份");
        assert!(id1.device_id.starts_with("dev-") && id1.device_id.len() == 20,
            "device_id 形如 dev-<16hex>: {}", id1.device_id);
        assert!(id1.controller_credential.is_none(), "注册前无 credential");

        // 「重启」：重新打开同一目录 → 同一身份（公钥/device_id 不漂移）。
        let (id2, first2) = st.create_or_load().expect("second run");
        assert!(!first2, "第二次运行不应重新生成");
        assert_eq!(id2.device_id, id1.device_id);
        assert_eq!(id2.public_key, id1.public_key);
        assert_eq!(id2.private_key.as_slice(), id1.private_key.as_slice());
    }

    #[test]
    fn b64_roundtrip() {
        for data in [b"".to_vec(), b"x".to_vec(), b"xy".to_vec(), b"xyz".to_vec(), (0u8..=255).collect()] {
            let enc = b64_encode(&data);
            let dec = b64_decode(&enc).expect("decode");
            assert_eq!(dec, data, "b64 往返失败");
        }
        assert!(b64_decode("!!!!").is_err());
        assert!(b64_decode("AAA").is_err());
    }

    /// 用户规格五：`unauthorized_user_cannot_read_identity`。
    ///
    /// 身份文件 DACL 必须把受托人收敛为「当前用户（服务运行身份）+ SYSTEM」：
    /// Everyone / Authenticated Users / BUILTIN\Users 等组账户零授权。
    /// （真实第二用户进程打开文件 = PENDING_REAL_WORLD_VALIDATION，需第二账户环境；
    /// 本测试以 DACL 受托人穷举为自动化等价验证。）
    #[test]
    fn unauthorized_user_cannot_read_identity() {
        let st = temp_store("unauth");
        st.save(&sample_identity()).expect("save identity");

        let aces = acl::file_dacl_aces(&st.file_path()).expect("读取 DACL");
        assert!(!aces.is_empty(), "NULL DACL = Everyone 全权，绝对不允许出现");

        // 非授权账户 SID 黑名单（组账户——一旦出现即等于其它本地用户可解密身份）。
        let deny_list: Vec<(&str, Vec<u8>)> = [
            "S-1-1-0",      // Everyone
            "S-1-5-11",     // Authenticated Users
            "S-1-5-32-545", // BUILTIN\Users
        ]
        .iter()
        .map(|s| (*s, acl::sid_from_string(s).expect("deny sid")))
        .collect();

        let allowed: Vec<_> = aces.iter().filter(|(t, _, _)| *t == 0).collect(); // ACCESS_ALLOWED_ACE
        for (ace_type, mask, sid) in &aces {
            for (name, deny_sid) in &deny_list {
                assert_ne!(
                    sid, deny_sid,
                    "DACL 不得授权给非授权账户组 {name}（AceType={ace_type}）"
                );
            }
            assert_eq!(ace_type, &0u8, "只允许 ALLOWED ACE（出现 DENY ACE = 配置漂移）");
            assert_eq!(*mask, 0x001F_01FF, "授权掩码应为 FILE_ALL_ACCESS: 0x{mask:08X}");
        }

        // 恰好两个 ALLOWED ACE：当前用户（服务运行身份）+ SYSTEM。
        assert_eq!(allowed.len(), 2, "受托人必须恰好 = 当前用户 + SYSTEM");
        let me = acl::current_user_sid().expect("当前用户 SID");
        let sys = acl::sid_from_string("S-1-5-18").expect("SYSTEM SID");
        assert!(
            allowed.iter().any(|(_, _, s)| *s == me),
            "必须包含当前用户（服务运行身份）ACE"
        );
        assert!(allowed.iter().any(|(_, _, s)| *s == sys), "必须包含 SYSTEM ACE");
    }
}
