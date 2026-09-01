//! M0-5 DirectLink Security：Noise_IK 加密数据面。
//!
//! - 模式：`Noise_IK_25519_ChaChaPoly_BLAKE2s`（snow 0.10，
//!   `HandshakeState::into_stateless_transport_mode()` → 显式 nonce 的
//!   `StatelessTransportState`，匹配 UDP 无可靠有序底座——帧规范修正一）；
//! - 角色：join = initiator（知道 creator 静态公钥，来自 Session Code v4 `k`
//!   字段）；creator = responder（从 msg1 学习 initiator 静态公钥）；
//! - prologue 绑定（修正一 + M0-5 收尾）：protocol_version + network_id +
//!   双方 device_id + session_id + epoch，防跨网络/跨版本/跨会话/跨纪元重放
//!   （帧头明文字段被篡改 → prologue 不匹配 → 握手解密失败）；
//! - 防重放（修正一）：2048 滑动窗口，**预检查 → 解密 → 成功才提交**；
//! - 重握手：每 10min / 1GB 触发完整 IK 重握手，epoch+1，旧 epoch ≤5s 宽限
//!   （仅接收），宽限过期即丢弃（Drop 即释放 CipherState）。为避免双方同时
//!   发起重握手冲突，M0-5 约定：**只有初始 initiator（join）发起 rekey**，
//!   responder 跟随切换发送纪元。
//!
//! 自持密钥 zeroize：`StaticIdentity` 私钥 `Zeroizing`（Drop 擦除，有单测）。
//! snow 0.10 内部 CipherState **无** zeroize 保障（源码审计结论，ADR
//! NOISE_KEY_LIFECYCLE 方案 C 记录为 Known Security Risk）。

pub mod frame;
pub mod keys;
pub mod replay;

pub use frame::{
    decode as decode_frame, encode as encode_frame, FrameView, FRAME_HEADER_LEN, FRAME_MAGIC,
    FRAME_VERSION,
};
pub use keys::StaticIdentity;
pub use replay::ReplayWindow;

use frame::{
    encode_handshake_msg1, encode_handshake_msg2, FLAG_ENCRYPTED, FLAG_HANDSHAKE,
};
use mesh_common::{ErrorCode, MeshError};
use std::time::{Duration, Instant};

/// Noise 协议参数（IK：initiator 预知 responder 静态公钥）。
pub const PATTERN_STR: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2s";

/// prologue 中的协议版本（跨版本重放防护）。
pub const PROTOCOL_VERSION: u16 = 1;

/// 会话握手/重握手策略。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct CryptoPolicy {
    /// msg1 重发次数（UDP 丢包重传；重复 msg1 由 responder 幂等重发 msg2）
    pub handshake_retries: u32,
    /// msg1 重发间隔
    pub handshake_rto_ms: u64,
    /// rekey 时间阈值（帧规范：10 分钟）
    pub rekey_after_ms: u64,
    /// rekey 流量阈值（帧规范：1 GB）
    pub rekey_after_bytes: u64,
    /// 旧 epoch 接收宽限（帧规范：≤5s，切换零丢包）
    pub rekey_grace_ms: u64,
}

impl Default for CryptoPolicy {
    fn default() -> Self {
        Self {
            handshake_retries: 5,
            handshake_rto_ms: 400,
            rekey_after_ms: 10 * 60 * 1000,
            rekey_after_bytes: 1024 * 1024 * 1024,
            rekey_grace_ms: 5000,
        }
    }
}

fn handshake_err(reason: impl Into<String>) -> MeshError {
    MeshError::new(ErrorCode::CryptoHandshakeFailed, reason)
}

fn pattern() -> snow::params::NoiseParams {
    PATTERN_STR.parse().expect("内置合法 Noise 参数")
}

/// prologue = protocol_version(u16 BE) || len+network_id || len+initiator_devid
/// || len+responder_devid || session_id(16) || epoch_id(u32 BE)。
/// session_id/epoch 也在帧头明文出现——prologue 绑定后，**篡改帧头的
/// session_id/epoch 字段必然导致 AEAD 解密失败**（transcript 绑定）。
pub fn build_prologue(
    network_id: &str,
    initiator_device_id: &str,
    responder_device_id: &str,
    session_id: &[u8; 16],
    epoch: u32,
) -> Vec<u8> {
    fn put(out: &mut Vec<u8>, s: &str) {
        out.extend_from_slice(&(s.len() as u16).to_be_bytes());
        out.extend_from_slice(s.as_bytes());
    }
    let mut p = Vec::new();
    p.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
    put(&mut p, network_id);
    put(&mut p, initiator_device_id);
    put(&mut p, responder_device_id);
    p.extend_from_slice(session_id);
    p.extend_from_slice(&epoch.to_be_bytes());
    p
}

/// 加密会话 16 字节标识（帧头明文字段，仅 demux 用，不承载安全属性——
/// 安全性来自 AEAD）。双 FNV-1a（不同种子）拼 16 字节保证本机内碰撞概率
/// 可忽略；种子混入随机公钥 + 纳秒时钟。
pub fn derive_session_id(seed: &[u8]) -> [u8; 16] {
    fn fnv1a(data: &[u8], mut h: u64) -> u64 {
        for &b in data {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        h
    }
    let a = fnv1a(seed, 0xcbf2_9ce4_8422_2325);
    let b = fnv1a(seed, 0x9e37_79b9_7f4a_7c15);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&a.to_be_bytes());
    out[8..].copy_from_slice(&b.to_be_bytes());
    out
}

/// 通道角色（谁发起握手/rekey）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

impl Role {
    pub fn as_str(&self) -> &'static str {
        match self {
            Role::Initiator => "initiator",
            Role::Responder => "responder",
        }
    }
}

/// 一个已完成的握手产物（一个密钥纪元）。
pub struct NewEpoch {
    pub epoch_id: u32,
    transport: snow::StatelessTransportState,
    /// 对端静态公钥（握手学习/校验结果）
    pub remote_static: [u8; 32],
    /// responder 侧缓存 msg2 wire 帧（重复 msg1 → 原样重发，幂等）
    pub msg2_cache: Option<Vec<u8>>,
}

impl std::fmt::Debug for NewEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewEpoch")
            .field("epoch_id", &self.epoch_id)
            .field("remote_static", &keys::hex::encode_lower(&self.remote_static))
            .field("has_msg2_cache", &self.msg2_cache.is_some())
            .finish()
    }
}

/// initiator（join）侧握手驱动：`initiate` → 发 msg1 → 收 msg2 → `complete`。
pub struct InitiatorHandshake {
    session_id: [u8; 16],
    target_epoch: u32,
    state: snow::HandshakeState,
    msg1_frame: Vec<u8>,
    expected_remote: [u8; 32],
}

/// 发起 IK 握手（初始握手 sid=None 自动派生；rekey 复用既有 sid）。
/// prologue 绑定 session_id + target_epoch（帧头同值——篡改帧头字段即解密失败）。
pub fn initiate(
    identity: &StaticIdentity,
    network_id: &str,
    remote_device_id: &str,
    expected_remote: &[u8; 32],
    target_epoch: u32,
    session_id: Option<[u8; 16]>,
) -> Result<InitiatorHandshake, MeshError> {
    let session_id = session_id.unwrap_or_else(|| {
        let seed = format!(
            "{}|{}|{:?}|{}",
            network_id,
            identity.device_id(),
            Instant::now(),
            keys::hex::encode_lower(identity.public())
        );
        derive_session_id(seed.as_bytes())
    });
    let prologue = build_prologue(network_id, identity.device_id(), remote_device_id, &session_id, target_epoch);
    let mut state = snow::Builder::new(pattern())
        .prologue(&prologue)
        .and_then(|b| b.local_private_key(identity.private()))
        .and_then(|b| b.remote_public_key(expected_remote))
        .and_then(|b| b.build_initiator())
        .map_err(|e| handshake_err(format!("IK initiator 构建失败: {e}")))?;
    let mut buf = vec![0u8; 1024];
    let len = state
        .write_message(&[], &mut buf)
        .map_err(|e| handshake_err(format!("IK msg1 写入失败: {e}")))?;
    let mut msg1_frame = Vec::new();
    encode_handshake_msg1(&session_id, target_epoch, identity.device_id(), &buf[..len], &mut msg1_frame);
    Ok(InitiatorHandshake { session_id, target_epoch, state, msg1_frame, expected_remote: *expected_remote })
}

impl InitiatorHandshake {
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
    pub fn target_epoch(&self) -> u32 {
        self.target_epoch
    }
    /// msg1 完整 wire 帧（幂等重发同一字节串——responder 侧重复 msg1 会重发缓存 msg2）
    pub fn msg1_frame(&self) -> &[u8] {
        &self.msg1_frame
    }

    /// 处理 msg2 wire 帧 → 完成握手 → 新纪元。
    pub fn complete(mut self, msg2_wire: &[u8]) -> Result<NewEpoch, MeshError> {
        let f = frame::decode(msg2_wire).map_err(|e| handshake_err(e.to_string()))?;
        if !f.is_handshake() || f.has_intro() || f.session_id != self.session_id || f.epoch_id != self.target_epoch {
            return Err(handshake_err("msg2 帧与本次握手不匹配"));
        }
        let mut out = vec![0u8; 1024];
        self.state
            .read_message(f.body, &mut out)
            .map_err(|e| handshake_err(format!("IK msg2 校验失败（密钥/prologue 不匹配或被篡改）: {e}")))?;
        let transport = self
            .state
            .into_stateless_transport_mode()
            .map_err(|e| handshake_err(format!("转入传输态失败: {e}")))?;
        let remote_static: [u8; 32] = transport
            .get_remote_static()
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| handshake_err("对端静态公钥缺失"))?;
        // 显式指纹校验（belt & braces：IK 协议层已把 responder 静态绑进密钥派生）
        if remote_static != self.expected_remote {
            return Err(MeshError::new(
                ErrorCode::CryptoKeyMismatch,
                "对端静态公钥与 Session Code 携带指纹不符",
            ));
        }
        Ok(NewEpoch { epoch_id: self.target_epoch, transport, remote_static, msg2_cache: None })
    }
}

/// responder（creator）侧处理 msg1 wire 帧 → (新纪元, 需回发的 msg2 wire 帧)。
/// 幂等性由调用方保证：重复 msg1 到达时原样重发缓存的 msg2（见
/// `NoiseChannel::msg2_cache`）。
///
/// `expected_initiator`（双向身份验证，用户规格二）：Some 时 responder 必须把
/// msg1 解出的 initiator 静态公钥与 Controller Device Registry 中该 device_id
/// 的公钥比对，不匹配 → CryptoKeyMismatch（DEVICE_KEY_MISMATCH），msg2 不会
/// 发出——禁止仅由 initiator 验证 responder。None = PoC 遗留路径（无注册表）。
pub fn respond(
    identity: &StaticIdentity,
    network_id: &str,
    msg1_wire: &[u8],
    expected_initiator: Option<&[u8; 32]>,
) -> Result<(NewEpoch, Vec<u8>), MeshError> {
    let f = frame::decode(msg1_wire).map_err(|e| handshake_err(e.to_string()))?;
    if !f.is_handshake() || !f.has_intro() {
        return Err(handshake_err("msg1 帧缺少 intro"));
    }
    let (initiator_device_id, noise_msg) = f.intro().map_err(|e| handshake_err(e.to_string()))?;
    let prologue =
        build_prologue(network_id, initiator_device_id, identity.device_id(), &f.session_id, f.epoch_id);
    let mut state = snow::Builder::new(pattern())
        .prologue(&prologue)
        .and_then(|b| b.local_private_key(identity.private()))
        .and_then(|b| b.build_responder())
        .map_err(|e| handshake_err(format!("IK responder 构建失败: {e}")))?;
    let mut out = vec![0u8; 1024];
    state
        .read_message(noise_msg, &mut out)
        .map_err(|e| handshake_err(format!("IK msg1 校验失败（对端持有的本端公钥不符/prologue 不匹配/被篡改）: {e}")))?;
    let mut buf = vec![0u8; 1024];
    let len = state
        .write_message(&[], &mut buf)
        .map_err(|e| handshake_err(format!("IK msg2 写入失败: {e}")))?;
    let transport = state
        .into_stateless_transport_mode()
        .map_err(|e| handshake_err(format!("转入传输态失败: {e}")))?;
    let remote_static: [u8; 32] = transport
        .get_remote_static()
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| handshake_err("对端静态公钥缺失"))?;
    if let Some(expected) = expected_initiator {
        if remote_static != *expected {
            return Err(MeshError::new(
                ErrorCode::CryptoKeyMismatch,
                format!(
                    "initiator 静态公钥与 Controller 注册表不符（device_id={initiator_device_id}）"
                ),
            ));
        }
    }
    let mut msg2_wire = Vec::new();
    encode_handshake_msg2(&f.session_id, f.epoch_id, &buf[..len], &mut msg2_wire);
    let new_epoch = NewEpoch {
        epoch_id: f.epoch_id,
        transport,
        remote_static,
        msg2_cache: Some(msg2_wire.clone()),
    };
    Ok((new_epoch, msg2_wire))
}

// ---------- NoiseChannel：双向加密通道（当前 + 宽限期旧纪元） ----------

struct Epoch {
    epoch_id: u32,
    transport: snow::StatelessTransportState,
    send_seq: u64,
    replay: ReplayWindow,
    established_at: Instant,
}

/// 诊断统计（crypto_report 输出）。
#[derive(Debug, Default, Clone)]
pub struct ChannelStats {
    pub frames_tx: u64,
    pub frames_rx: u64,
    pub bytes_encrypted: u64,
    pub replay_rejected: u64,
    pub decrypt_failed: u64,
    pub epoch_invalid: u64,
    pub rekey_count: u64,
}

/// 数据帧接收结果（dispatcher 丢弃路径用，不走 MeshError）。
#[derive(Debug, PartialEq, Eq)]
pub enum RecvOutcome {
    Accepted(Vec<u8>),
    Rejected(&'static str),
}

/// 一条已建立的加密会话通道（transport 层每 peer 一条，Mutex 共享）。
pub struct NoiseChannel {
    session_id: [u8; 16],
    role: Role,
    own_device_id: String,
    remote_device_id: String,
    remote_static: [u8; 32],
    current: Epoch,
    previous: Option<Epoch>,
    /// 当前纪元 msg2 wire 帧缓存（responder 幂等重发）
    msg2_cache: Option<Vec<u8>>,
    policy: CryptoPolicy,
    /// 当前纪元发送字节数（rekey 流量阈值输入）
    epoch_bytes_sent: u64,
    rekey_in_flight: bool,
    pub stats: ChannelStats,
}

impl NoiseChannel {
    pub fn from_epoch(
        e: NewEpoch,
        role: Role,
        own_device_id: impl Into<String>,
        remote_device_id: impl Into<String>,
        policy: CryptoPolicy,
    ) -> Self {
        let msg2_cache = e.msg2_cache;
        Self {
            session_id: derive_placeholder_sid(e.epoch_id),
            role,
            own_device_id: own_device_id.into(),
            remote_device_id: remote_device_id.into(),
            remote_static: e.remote_static,
            current: Epoch {
                epoch_id: e.epoch_id,
                transport: e.transport,
                send_seq: 0,
                replay: ReplayWindow::default(),
                established_at: Instant::now(),
            },
            previous: None,
            msg2_cache,
            policy,
            epoch_bytes_sent: 0,
            rekey_in_flight: false,
            stats: ChannelStats::default(),
        }
    }

    pub fn with_session_id(mut self, session_id: [u8; 16]) -> Self {
        self.session_id = session_id;
        self
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }
    pub fn role(&self) -> Role {
        self.role
    }
    pub fn current_epoch_id(&self) -> u32 {
        self.current.epoch_id
    }
    pub fn remote_device_id(&self) -> &str {
        &self.remote_device_id
    }
    pub fn own_device_id(&self) -> &str {
        &self.own_device_id
    }
    pub fn remote_static(&self) -> [u8; 32] {
        self.remote_static
    }
    /// 当前纪元 msg2 缓存（重复 msg1 → 原样重发）
    pub fn msg2_cache(&self) -> Option<&[u8]> {
        self.msg2_cache.as_deref()
    }
    pub fn set_rekey_in_flight(&mut self, v: bool) {
        self.rekey_in_flight = v;
    }

    /// 对端静态公钥指纹（报告/注册比对用）。
    pub fn remote_fingerprint(&self) -> String {
        keys::hex::encode_lower(&self.remote_static)
    }

    /// 加密发送：seq 递增、帧编码。`out` 为完整 wire 帧。
    pub fn send(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), MeshError> {
        let seq = self.current.send_seq;
        let mut ct = vec![0u8; payload.len() + 16];
        let n = self
            .current
            .transport
            .write_message(seq, payload, &mut ct)
            .map_err(|e| MeshError::new(ErrorCode::CryptoDecryptFailed, format!("加密失败: {e}")))?;
        frame::encode(FLAG_ENCRYPTED, &self.session_id, self.current.epoch_id, seq, &ct[..n], out);
        self.current.send_seq += 1;
        self.epoch_bytes_sent += out.len() as u64;
        self.stats.frames_tx += 1;
        self.stats.bytes_encrypted += payload.len() as u64;
        self.expire_previous_if_due();
        Ok(())
    }

    /// 接收数据帧（严格顺序：sid → epoch → replay 预检 → 解密 → 提交）。
    pub fn recv(&mut self, f: &FrameView) -> RecvOutcome {
        if f.session_id != self.session_id {
            return RecvOutcome::Rejected("session_mismatch");
        }
        self.expire_previous_if_due();
        if f.flags & FLAG_HANDSHAKE != 0 {
            return RecvOutcome::Rejected("handshake_frame_on_data_path");
        }
        if f.epoch_id == self.current.epoch_id {
            recv_into_epoch(&mut self.current, f, &mut self.stats)
        } else if self.previous.as_ref().is_some_and(|p| p.epoch_id == f.epoch_id) {
            // 宽限期内旧纪元仍可解密（切换零丢包）
            let prev = self.previous.as_mut().expect("checked above");
            recv_into_epoch(prev, f, &mut self.stats)
        } else {
            self.stats.epoch_invalid += 1;
            RecvOutcome::Rejected("epoch_invalid")
        }
    }

    /// rekey 触发判定（仅初始 initiator；避免双方同时重握手冲突——模块头注释）。
    pub fn should_rekey(&self) -> bool {
        self.role == Role::Initiator
            && !self.rekey_in_flight
            && (self.epoch_bytes_sent >= self.policy.rekey_after_bytes
                || self.current.established_at.elapsed() >= Duration::from_millis(self.policy.rekey_after_ms))
    }

    /// 采纳新纪元（rekey 完成）：旧纪元降级为宽限期接收、纪元计数归零。
    pub fn apply_new_epoch(&mut self, e: NewEpoch) {
        let old = std::mem::replace(
            &mut self.current,
            Epoch {
                epoch_id: e.epoch_id,
                transport: e.transport,
                send_seq: 0,
                replay: ReplayWindow::default(),
                established_at: Instant::now(),
            },
        );
        self.remote_static = e.remote_static;
        self.msg2_cache = e.msg2_cache;
        self.previous = Some(old); // Drop 时释放旧 CipherState
        self.epoch_bytes_sent = 0;
        self.rekey_in_flight = false;
        self.stats.rekey_count += 1;
    }

    /// 宽限期已过的旧纪元直接丢弃。
    fn expire_previous_if_due(&mut self) {
        if let Some(p) = &self.previous {
            if p.established_at.elapsed() >= Duration::from_millis(self.policy.rekey_grace_ms) {
                self.previous = None;
            }
        }
    }

    /// 诊断报告 JSON。
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "established": true,
            "session_id": keys::hex::encode_lower(&self.session_id),
            "role": self.role.as_str(),
            "epoch_id": self.current.epoch_id,
            "previous_epoch_alive": self.previous.is_some(),
            "remote_device_id": self.remote_device_id,
            "remote_static_fingerprint": self.remote_fingerprint(),
            "frames_tx": self.stats.frames_tx,
            "frames_rx": self.stats.frames_rx,
            "bytes_encrypted": self.stats.bytes_encrypted,
            "replay_rejected": self.stats.replay_rejected,
            "decrypt_failed": self.stats.decrypt_failed,
            "epoch_invalid": self.stats.epoch_invalid,
            "rekey_count": self.stats.rekey_count,
        })
    }
}

fn recv_into_epoch(epoch: &mut Epoch, f: &FrameView, stats: &mut ChannelStats) -> RecvOutcome {
    if f.body.len() < 16 {
        stats.decrypt_failed += 1;
        return RecvOutcome::Rejected("decrypt_failed");
    }
    if !epoch.replay.precheck(f.seq) {
        stats.replay_rejected += 1;
        return RecvOutcome::Rejected("replay_rejected");
    }
    let mut out = vec![0u8; f.body.len()];
    match epoch.transport.read_message(f.seq, f.body, &mut out) {
        Ok(n) => {
            epoch.replay.commit(f.seq);
            stats.frames_rx += 1;
            RecvOutcome::Accepted(out[..n].to_vec())
        }
        Err(_) => {
            // AEAD 失败：不提交 replay window（伪造包不得污染窗口——帧规范修正一）
            stats.decrypt_failed += 1;
            RecvOutcome::Rejected("decrypt_failed")
        }
    }
}

/// from_epoch 占位（with_session_id 必须随后调用——transport 建立时一定持有 sid）。
fn derive_placeholder_sid(epoch_id: u32) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[..4].copy_from_slice(&epoch_id.to_be_bytes());
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "meshlink-poc:test-session";

    fn channel_pair() -> (NoiseChannel, NoiseChannel) {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let hs = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let sid = hs.session_id();
        let (resp_epoch, msg2) = respond(&creator, NET, hs.msg1_frame(), None).unwrap();
        let init_epoch = hs.complete(&msg2).unwrap();
        let a = NoiseChannel::from_epoch(init_epoch, Role::Initiator, "joiner-dev", "creator-dev", CryptoPolicy::default()).with_session_id(sid);
        let b = NoiseChannel::from_epoch(resp_epoch, Role::Responder, "creator-dev", "joiner-dev", CryptoPolicy::default()).with_session_id(sid);
        (a, b)
    }

    #[test]
    fn handshake_success_and_key_agreement() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let hs = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let (resp_epoch, msg2) = respond(&creator, NET, hs.msg1_frame(), None).unwrap();
        let init_epoch = hs.complete(&msg2).unwrap();
        assert_eq!(init_epoch.epoch_id, 1);
        assert_eq!(resp_epoch.epoch_id, 1);
        // initiator 学到 responder 静态 = creator 公钥；responder 学到 initiator 静态 = joiner 公钥
        assert_eq!(init_epoch.remote_static, *creator.public());
        assert_eq!(resp_epoch.remote_static, *joiner.public());
        assert_ne!(init_epoch.remote_static, resp_epoch.remote_static);
    }

    #[test]
    fn encrypted_roundtrip() {
        let (mut a, mut b) = channel_pair();
        let mut wire = Vec::new();
        a.send(b"hello-noise", &mut wire).unwrap();
        assert_ne!(&wire[32..], b"hello-noise", "线上字节必须是密文");
        let f = frame::decode(&wire).unwrap();
        match b.recv(&f) {
            RecvOutcome::Accepted(pt) => assert_eq!(pt, b"hello-noise"),
            other => panic!("recv 应成功: {other:?}"),
        }
        // 双向
        let mut wire2 = Vec::new();
        b.send(b"pong", &mut wire2).unwrap();
        let f2 = frame::decode(&wire2).unwrap();
        assert!(matches!(a.recv(&f2), RecvOutcome::Accepted(p) if p == b"pong"));
    }

    #[test]
    fn wrong_expected_static_rejected() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let wrong = StaticIdentity::generate("impostor").unwrap();
        // initiator 指向错误公钥：responder 解不开 msg1 → respond 失败
        let hs = initiate(&joiner, NET, "creator-dev", wrong.public(), 1, None).unwrap();
        let err = respond(&creator, NET, hs.msg1_frame(), None).unwrap_err();
        assert!(format!("{err:?}").contains("CryptoHandshakeFailed"));
        // 反向：responder 身份不对（initiator 持有真公钥，impostor 应答）
        let hs2 = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let (_, msg2) = respond(&creator, NET, hs2.msg1_frame(), None).unwrap();
        // 篡改 msg2 → initiator complete 失败
        let mut bad = msg2.clone();
        let n = bad.len();
        bad[n - 1] ^= 0xFF;
        let err = hs2.complete(&bad).unwrap_err();
        assert!(format!("{err:?}").contains("CryptoHandshakeFailed"));
    }

    /// prologue 不匹配（network_id 不同）→ 握手失败（跨会话/跨网络重放防护）。
    #[test]
    fn prologue_mismatch_rejected() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let hs = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let err = respond(&creator, "meshlink-poc:OTHER-session", hs.msg1_frame(), None).unwrap_err();
        assert!(format!("{err:?}").contains("CryptoHandshakeFailed"));
    }

    /// replay：同一密文帧二次投递必须被拒。
    #[test]
    fn replayed_frame_rejected() {
        let (mut a, mut b) = channel_pair();
        let mut wire = Vec::new();
        a.send(b"once", &mut wire).unwrap();
        let f = frame::decode(&wire).unwrap();
        assert!(matches!(b.recv(&f), RecvOutcome::Accepted(_)));
        match b.recv(&f) {
            RecvOutcome::Rejected(r) => assert_eq!(r, "replay_rejected"),
            other => panic!("重复帧必须拒绝: {other:?}"),
        }
        assert_eq!(b.stats.replay_rejected, 1);
    }

    /// 乱序接收：发送 0..=9，乱序投递全部成功。
    #[test]
    fn out_of_order_frames_accepted() {
        let (mut a, mut b) = channel_pair();
        let mut wires = Vec::new();
        for i in 0..10u32 {
            let mut w = Vec::new();
            a.send(format!("pkt-{i}").as_bytes(), &mut w).unwrap();
            wires.push(w);
        }
        for i in [5usize, 0, 9, 3, 7, 1, 8, 2, 6, 4] {
            let f = frame::decode(&wires[i]).unwrap();
            assert!(
                matches!(b.recv(&f), RecvOutcome::Accepted(p) if p == format!("pkt-{i}").as_bytes()),
                "乱序 seq={i} 应接受"
            );
        }
    }

    /// 伪造帧不得污染窗口：攻击者无法解密，但窗口仍接受稍后的合法超前帧。
    #[test]
    fn forged_frame_does_not_block_legitimate() {
        let (mut a, mut b) = channel_pair();
        // 合法提交 seq 0..2
        for i in 0..3u32 {
            let mut w = Vec::new();
            a.send(format!("ok-{i}").as_bytes(), &mut w).unwrap();
            let f = frame::decode(&w).unwrap();
            assert!(matches!(b.recv(&f), RecvOutcome::Accepted(_)));
        }
        // 伪造 seq=100 帧（密文乱造，AEAD 必败，窗口不得提交）
        let mut forged = Vec::new();
        frame::encode(FLAG_ENCRYPTED, &a.session_id(), 1, 100, &[0xABu8; 32], &mut forged);
        let ff = frame::decode(&forged).unwrap();
        match b.recv(&ff) {
            RecvOutcome::Rejected(r) => assert_eq!(r, "decrypt_failed"),
            other => panic!("伪造帧必须解密失败: {other:?}"),
        }
        // 合法 seq=3、4 仍正常接收（窗口未被污染）
        for i in 3..5u32 {
            let mut w = Vec::new();
            a.send(format!("ok-{i}").as_bytes(), &mut w).unwrap();
            let f = frame::decode(&w).unwrap();
            assert!(matches!(b.recv(&f), RecvOutcome::Accepted(_)));
        }
    }

    /// 错误密钥帧（第三方密钥加密）→ 解密失败计数。
    #[test]
    fn wrong_key_frame_rejected() {
        let (_a, mut b) = channel_pair();
        // 第三方密钥加密的同 sid 帧
        let (fake_a, _fake_b) = channel_pair();
        let mut wire = Vec::new();
        let mut fake = fake_a;
        fake.send(b"evil", &mut wire).unwrap();
        let f = frame::decode(&wire).unwrap();
        // 重编码为 b 的 session_id（同 sid 不同密钥）
        let mut w2 = Vec::new();
        frame::encode(f.flags, &b.session_id(), f.epoch_id, f.seq, f.body, &mut w2);
        let f2 = frame::decode(&w2).unwrap();
        match b.recv(&f2) {
            RecvOutcome::Rejected(r) => assert_eq!(r, "decrypt_failed"),
            other => panic!("错误密钥帧必须拒绝: {other:?}"),
        }
    }

    /// epoch 不匹配（未知纪元）拒绝 + 计数。
    #[test]
    fn unknown_epoch_rejected() {
        let (mut a, mut b) = channel_pair();
        let mut w = Vec::new();
        a.send(b"x", &mut w).unwrap();
        let f = frame::decode(&w).unwrap();
        let mut w2 = Vec::new();
        frame::encode(f.flags, &f.session_id, 99, f.seq, f.body, &mut w2);
        let f2 = frame::decode(&w2).unwrap();
        match b.recv(&f2) {
            RecvOutcome::Rejected(r) => assert_eq!(r, "epoch_invalid"),
            other => panic!("未知纪元必须拒绝: {other:?}"),
        }
        assert_eq!(b.stats.epoch_invalid, 1);
    }

    /// rekey 全链路：epoch1 数据 → 触发 → 新握手 epoch2 → 旧纪元宽限内仍可收。
    #[test]
    fn rekey_switch_with_grace() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        // 极小阈值 + 极短宽限，测试可控
        let policy = CryptoPolicy { rekey_after_bytes: 10, rekey_grace_ms: 150, ..Default::default() };
        let hs = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let sid = hs.session_id();
        let (resp_epoch, msg2) = respond(&creator, NET, hs.msg1_frame(), None).unwrap();
        let init_epoch = hs.complete(&msg2).unwrap();
        let mut a = NoiseChannel::from_epoch(init_epoch, Role::Initiator, "joiner-dev", "creator-dev", policy.clone()).with_session_id(sid);
        let mut b = NoiseChannel::from_epoch(resp_epoch, Role::Responder, "creator-dev", "joiner-dev", policy.clone()).with_session_id(sid);

        // epoch 1 上的数据
        let mut w1 = Vec::new();
        a.send(b"epoch1-data", &mut w1).unwrap();
        let f1 = frame::decode(&w1).unwrap();
        assert!(matches!(b.recv(&f1), RecvOutcome::Accepted(_)));

        // 流量超阈值 → initiator 应触发 rekey
        assert!(a.should_rekey());
        a.set_rekey_in_flight(true);
        let hs2 = initiate(&joiner, NET, "creator-dev", &a.remote_static(), 2, Some(sid)).unwrap();
        assert_eq!(hs2.session_id(), sid, "rekey 复用会话标识");
        let (resp2, msg2b) = respond(&creator, NET, hs2.msg1_frame(), None).unwrap();
        let init2 = hs2.complete(&msg2b).unwrap();
        let epoch2_frame_before_switch = {
            // 切换前先发一个 epoch1 帧（模拟在途包），稍后验证宽限
            let mut w = Vec::new();
            a.send(b"in-flight-epoch1", &mut w).unwrap();
            w
        };
        a.apply_new_epoch(init2);
        b.apply_new_epoch(resp2);
        assert_eq!(a.current_epoch_id(), 2);
        assert_eq!(b.current_epoch_id(), 2);
        assert!(!a.should_rekey(), "纪元切换后阈值重置");

        // 切换后在途 epoch1 帧在宽限期内仍可解密（零丢包）
        let f_inflight = frame::decode(&epoch2_frame_before_switch).unwrap();
        assert!(
            matches!(b.recv(&f_inflight), RecvOutcome::Accepted(p) if p == b"in-flight-epoch1"),
            "宽限期内旧纪元在途帧必须接受"
        );
        // epoch2 双向数据
        let mut w2 = Vec::new();
        a.send(b"epoch2-data", &mut w2).unwrap();
        let f2 = frame::decode(&w2).unwrap();
        assert!(matches!(b.recv(&f2), RecvOutcome::Accepted(p) if p == b"epoch2-data"));

        // 宽限过期后旧纪元帧被拒
        std::thread::sleep(Duration::from_millis(200));
        let mut w3 = Vec::new();
        a.send(b"late-epoch2", &mut w3).unwrap(); // 触发 expire 检查
        let _ = frame::decode(&w3);
        // 重造一个旧纪元 seq 帧（此时 b.previous 已被过期清理）
        let mut late_w = Vec::new();
        frame::encode(FLAG_ENCRYPTED, &sid, 1, 3, &[0u8; 32], &mut late_w);
        let f_late = frame::decode(&late_w).unwrap();
        match b.recv(&f_late) {
            RecvOutcome::Rejected(r) => assert_eq!(r, "epoch_invalid"),
            other => panic!("宽限过期后旧纪元必须拒绝: {other:?}"),
        }
        assert_eq!(b.stats.rekey_count, 1);
    }

    /// responder 重复 msg1 → 重发缓存 msg2（幂等重传路径）。
    #[test]
    fn responder_resends_cached_msg2_on_duplicate_msg1() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let hs = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let (resp_epoch, msg2) = respond(&creator, NET, hs.msg1_frame(), None).unwrap();
        let b = NoiseChannel::from_epoch(resp_epoch, Role::Responder, "creator-dev", "joiner-dev", CryptoPolicy::default());
        assert_eq!(b.msg2_cache(), Some(msg2.as_slice()), "responder 必须缓存 msg2 供重复 msg1 重发");
    }

    /// 时间阈值触发 rekey。
    #[test]
    fn rekey_time_trigger() {
        let policy = CryptoPolicy { rekey_after_ms: 50, ..Default::default() };
        let (mut a, _b) = channel_pair();
        a.policy = policy;
        assert!(!a.should_rekey());
        std::thread::sleep(Duration::from_millis(80));
        assert!(a.should_rekey());
    }

    #[test]
    fn prologue_layout_matches_spec() {
        let sid = [7u8; 16];
        let p = build_prologue("net", "dev-i", "dev-r", &sid, 3);
        // 2(version) + 2+3 + 2+5 + 2+5 + 16(session_id) + 4(epoch) = 41
        assert_eq!(p.len(), 41);
        assert_eq!(&p[0..2], &PROTOCOL_VERSION.to_be_bytes());
        assert_eq!(p[2..4], 3u16.to_be_bytes());
        assert_eq!(&p[4..7], b"net");
        assert_eq!(&p[21..37], &sid, "session_id 必须原样进入 prologue");
        assert_eq!(p[37..41], 3u32.to_be_bytes(), "epoch 必须原样进入 prologue");
    }

    /// session_id/epoch 进 prologue 后：伪造帧头字段（session_id 或 epoch 改动）
    /// 必须令 responder 解密失败——transcript 绑定的直接验证。
    #[test]
    fn tampered_frame_header_fails_handshake() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let hs = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let msg1 = hs.msg1_frame().to_vec();

        // 篡改帧头 session_id（偏移 4..20，首个字节翻转）
        let mut bad_sid = msg1.clone();
        bad_sid[4] ^= 0xFF;
        assert!(respond(&creator, NET, &bad_sid, None).is_err(), "篡改 session_id 的 msg1 必须解密失败");

        // 篡改帧头 epoch（偏移 20..24：1 → 2）
        let mut bad_epoch = msg1.clone();
        bad_epoch[23] = 2;
        assert!(respond(&creator, NET, &bad_epoch, None).is_err(), "篡改 epoch 的 msg1 必须解密失败");
    }

    /// 双向身份验证（用户规格二）：responder（creator）持 Controller 注册表
    /// 公钥时校验通过，且学到的 remote_static 即注册表公钥。
    #[test]
    fn responder_verifies_initiator_key_from_registry() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let hs = initiate(&joiner, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let (resp_epoch, msg2) = respond(&creator, NET, hs.msg1_frame(), Some(joiner.public()))
            .expect("注册表公钥匹配必须放行");
        assert_eq!(resp_epoch.remote_static, *joiner.public());
        // initiator 侧同样校验 responder（expected_remote 已绑定 creator 公钥）
        let init_epoch = hs.complete(&msg2).unwrap();
        assert_eq!(init_epoch.remote_static, *creator.public());
    }

    /// 注册表公钥不匹配 → CryptoKeyMismatch（DEVICE_KEY_MISMATCH），
    /// msg2 不产出（调用方无从发出——冒名 initiator 拿不到任何应答）。
    #[test]
    fn responder_rejects_initiator_key_mismatch() {
        let creator = StaticIdentity::generate("creator-dev").unwrap();
        let joiner = StaticIdentity::generate("joiner-dev").unwrap();
        let impostor = StaticIdentity::generate("impostor-dev").unwrap();
        // 攻击者用自己的密钥发 msg1；creator 依据 Controller 注册表中
        // joiner-dev 的公钥校验 → 必不匹配（篡改 intro device_id 会先被
        // prologue 绑定拦截，此处验证的是密钥维度）。
        let hs = initiate(&impostor, NET, "creator-dev", creator.public(), 1, None).unwrap();
        let err = respond(&creator, NET, hs.msg1_frame(), Some(joiner.public())).unwrap_err();
        assert!(
            format!("{err:?}").contains("CryptoKeyMismatch"),
            "必须是 DEVICE_KEY_MISMATCH: {err:?}"
        );
        // 对照：无注册表（None）时同一 msg1 可应答——校验仅在提供密钥时生效
        assert!(respond(&creator, NET, hs.msg1_frame(), None).is_ok());
    }
}
