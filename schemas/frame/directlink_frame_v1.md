# DirectLink 会话帧格式 v1（UDP 数据面）

> 状态：已确认（用户修正一、三）；M0-5 实现已回填（2026-08-30）。
> 实现：`crates/directlink/src/crypto/frame.rs`（编解码）+
> `crates/directlink/src/crypto/mod.rs`（握手/加密/防重放/rekey）+
> `crates/directlink/src/transport.rs`（dispatcher MD44 分派）。

## UDP 载荷布局

```
偏移  大小  字段
0     2    magic        = 0x4D44 ('MD', Mesh Direct)  [u16 BE]
2     1    version      = 1                            [u8]
3     1    flags        见下表                          [u8]
4     16   session_id   会话随机标识（握手产物）          [16 bytes]
20    4    epoch_id     密钥纪元（初始握手=1，重握手+1）   [u32 BE]
24    8    seq          方向内单调递增序列号，从 0 开始    [u64 BE]
32    n    body         密文 / 握手消息 / intro+握手消息
```

### flags 位定义（M0-5 实现回填）

| bit | 名称                     | 含义                                                  |
| --- | ---------------------- | --------------------------------------------------- |
| 0   | FLAG\_ENCRYPTED (0x01) | 加密会话数据帧（body = 密文）                                  |
| 1   | FLAG\_KEEPALIVE (0x02) | 保留未启用（NAT 保活仍走 STUN meshlink-keepalive，不走 MD44）     |
| 2   | FLAG\_HANDSHAKE (0x04) | Noise IK 握手消息（初始握手 epoch 1 或重握手 epoch n+1）          |
| 3   | FLAG\_INTRO (0x08)     | 握手 intro：body 头部带明文 initiator device\_id（仅 msg1 方向） |

未知 flag 位（bit4-7 置位）→ 直接拒绝（`frame_unknown_flags`），不做前向兼容
猜测。魔数与 STUN（首 2 bit=00，首字节 <0x40）、MTU echo（0x4D54）首字节类型
前缀互斥，dispatcher 按 `payload[0..2] == MD44` 优先分派。

### session\_id 语义（实现补充）

16 字节，由 initiator 在首次 `initiate()` 时从随机种子（公钥 + 纳秒时钟等）
双 FNV-1a 派生；**仅用于本机多会话 demux，不承载任何安全属性**——帧的真实
认证来自 AEAD（ChaCha20Poly1305）。rekey 复用同一 session\_id（只进 epoch）。

## Nonce / 序列（修正一；已实现）

* **不使用**"随机初始偏移"。snow `CipherState` nonce 从 0 开始。

* 使用 `HandshakeState::into_stateless_transport_mode()` 得到
  `StatelessTransportState`（UDP 无可靠有序底座，不采用普通 TransportState）；
  snow 无状态模式密文 = `payload + 16 字节 Poly1305 tag`，**无长度前缀**。

* 每方向独立维护：

  * `send_seq: u64`（AEAD nonce = seq，写帧头）

  * `replay_window`（接收侧，每 epoch 独立窗口）

* 接收方以帧头 seq 作为解密 nonce；epoch 切换后双方 seq 均从 0 重启（窗口随
  新 epoch 重建，无跨纪元污染）。

## Anti-Replay（修正一；已实现）

接收流程（顺序不可颠倒，实现于 `NoiseChannel::recv`）：

```
读 magic/version/flags（非法 → frame 层拒绝）
→ 读 session_id → 与本通道比对（不匹配 → session_mismatch 丢帧）
→ 读 epoch_id → current 或宽限期内 previous（未知/过期 → epoch_invalid 计数丢弃）
→ 读 seq → replay window 预检查（重复/过旧 → replay_rejected，不解密）
→ 以 seq 为 nonce 解密
→ AEAD 校验成功 → 正式提交 replay window（2048 位滑动窗口）
→ 交付 overlay-router
```

**禁止**先标记 seq 再解密——伪造包不得污染 replay window（单测
`forged_frame_does_not_pollute_window` / `forged_frame_does_not_block_legitimate`
锁定该性质）。

窗口能力（单测覆盖）：乱序接受 / 重复拒绝 / 过旧拒绝 / 2048 window /
大跳变清空位图。

## 握手帧格式（M0-5 实现回填）

Noise 模式：`Noise_IK_25519_ChaChaPoly_BLAKE2s`（snow 0.10）。
角色：join = initiator（持 creator 静态公钥，来自 Session Code v4 `k` 字段）；
create = responder（从 msg1 学习 initiator 静态公钥）。

```
msg1（initiator → responder）:
  flags = FLAG_HANDSHAKE | FLAG_INTRO
  epoch_id = 目标纪元（初始=1；rekey=current+1）
  seq = 0
  body  = [u16 BE dev_len][initiator device_id UTF-8][Noise IK msg1 密文]
          （dev_len ∈ (0, 64]，ASCII 可见字符）

msg2（responder → initiator）:
  flags = FLAG_HANDSHAKE（无 intro）
  session_id / epoch_id 与 msg1 一致
  seq = 0
  body  = Noise IK msg2 密文
```

* intro 明文不泄露秘密（device\_id 本就随 Session Code / Controller 公开），且被
  prologue 绑定——篡改 intro 必导致握手解密失败。

* 不可信输入防护：帧层严格校验长度/魔数/版本/已知 flag/intro 范围，只拒绝不
  panic；`intro()` 解析失败 → `frame_bad_intro` 丢弃。

* msg1 丢失重传：initiator 按 `handshake_retries × handshake_rto_ms`（默认
  5×400ms）重发**同一字节串**；responder 收到与当前通道同 session+epoch 的
  重复 msg1 → 原样重发缓存 msg2（幂等，`msg2_cache`）。

* 指纹校验：initiator 侧 `complete()` 显式断言 `get_remote_static()` ==
  Session Code 携带公钥（belt & braces——IK 协议层已把 responder 静态绑进密钥
  派生）；不匹配 → `CryptoKeyMismatch`。
* 公钥真实性边界：见下节「公钥真实性边界」——握手可检测 expected-key
  mismatch，但公钥真实性必须由 Controller 身份系统提供。

### 公钥真实性边界（禁止过度声称）

篡改已预期的 responder static public key 会导致 Noise IK handshake failure，
证明**握手能够检测 expected-key mismatch**。

但**禁止声称**：仅靠 Noise IK 已解决 signaling 公钥替换 / MITM。原因：Noise IK
的安全性依赖 initiator **已经可信获得** responder static public key——IK 把
"expected key" 绑进密钥派生，但 expected key 本身的真实性属于 signaling 通道
的职责。PoC 阶段该信任来自人工转述 Session Code；Controller MVP 起必须来自
authenticated Controller response（设备注册表绑定 device_id → public key，
公钥变化返回 DEVICE_KEY_MISMATCH）。若 legacy code 携带的 k 与 Controller
注册公钥不一致 → 立即 DEVICE_KEY_MISMATCH，禁止连接。

## 握手 Prologue 绑定（修正一；已实现）

Noise handshake prologue 绑定协议上下文，防跨网络/跨版本重放：

```
prologue = protocol_version(u16 BE = 1)
        || network_id_len(u16 BE) || network_id_utf8
        || initiator_device_id_len(u16 BE) || initiator_device_id_utf8
        || responder_device_id_len(u16 BE) || responder_device_id_utf8
```

（`build_prologue`，布局单测 `prologue_layout_matches_spec`；prologue 不匹配
（如 network\_id 不同）→ 握手必然失败，单测 `prologue_mismatch_rejected`。）

Controller 注册表落地后：对端静态公钥指纹 == 注册表中该 device\_id 的
`static_key_fingerprint`，不匹配 → 断开（CryptoKeyMismatch）。M0-5 PoC 阶段
以 Session Code v4 `k` 字段（creator 公钥，64 hex）承担同一职责。

## 密钥轮换（已实现）

* 触发：`rekey_after_ms`（默认 10 分钟）或 `rekey_after_bytes`（默认 1GB）
  ——仅\*\*初始 initiator（join 侧）\*\*判定并发起（`should_rekey`），responder
  跟随切换，避免双方同时重握手冲突；

* 方式：重新完整 IK 握手（同 session\_id，`epoch_id` = current + 1），双方
  `apply_new_epoch`：旧纪元降级为 `previous`（仅接收），宽限期
  `rekey_grace_ms`（默认 5s）内旧纪元在途帧仍可解密（切换零丢包，单测
  `rekey_switch_with_grace`）；

* 宽限过期（任意后续 send/recv 触发检查）→ `previous = None` → 旧
  `StatelessTransportState` Drop，此后旧纪元帧 → `epoch_invalid` 拒绝；

* 旧 epoch 密钥 zeroize 状态：Drop 释放但不擦除——见
  `docs/adr/NOISE_KEY_LIFECYCLE.md`（方案 C Known Security Risk）。

## MTU 预算（M0-5 计算回填）

Wintun MTU 1400 起步。每帧线上开销：

```
32（帧头）+ 16（Poly1305 tag；snow 无状态模式无长度前缀）
+ 28（IPv4 20 + UDP 8）
= 76 字节/帧固定开销
```

1400 字节 overlay payload → 物理 IP 包 = 1400 + 32 + 16 + 28 = **1476 ≤ 1500**
（标准以太网 MTU），余量 24 字节。实测定值待 overlay-router（Wintun ↔
DirectLink）链路真实吞吐验证后回填。

## 相关文档

* `docs/adr/NOISE_KEY_LIFECYCLE.md`（密钥生命周期 / zeroize 语义）

* Session Code v4：`k` 字段（creator 静态公钥 64 hex；Track A 为空——Track A
  不做 Noise 加密）

* `crates/directlink/tests/crypto_transport_loopback.rs`（双 transport 集成：
  握手/加密往返/错误公钥/rekey）

* `crates/directlink/tests/poc_e2e.rs`（双进程 E2E：create/join 加密 + 篡改 k
  反向验证）

