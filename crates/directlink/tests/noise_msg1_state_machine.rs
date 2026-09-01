//! M0-5 收尾：responder msg1 状态机硬化验证（真实 UDP dispatcher 全路径）。
//!
//! 用原始 `std::UdpSocket` 扮演 initiator（B）：先发 STUN probe（tag 精确匹配）
//! 让 responder（A）建立 accept 会话，随后注入 `crypto::initiate` 产生的
//! **密码学合法** msg1 帧（密钥/prologue 全部正确，仅帧头 session_id/epoch
//! 受控），验证 transport 状态机：
//! - `old_epoch_replay_rejected`：epoch 回退（旧纪元 msg1 重放）→ 拒绝；
//! - `future_epoch_skipped_rejected`：epoch 跳变（> current+1）→ 拒绝；
//! - `wrong_session_id_rejected`：未知 session_id → 拒绝（先于 crypto 层）；
//! - `duplicate_msg1_idempotent`：重复合法 rekey msg1 → 幂等重发缓存 msg2，
//!   不重装纪元、不推进 epoch；
//! - `epoch_bound_handshake_success`：prologue 绑定 session_id+epoch 后，
//!   初始握手（epoch 1）成功 + 双向加密数据往返。

use directlink::crypto::{self, CryptoPolicy, NoiseChannel, RecvOutcome, Role, StaticIdentity};
use directlink::ice::stun::{new_txid, StunAttr, StunMessage};
use directlink::transport::DirectLinkTransport;
use std::net::UdpSocket;
use std::sync::Arc;
use std::time::{Duration, Instant};
use transport_api::{Ipv4Packet, PeerId, TransportConfig, TransportProvider};

fn peer() -> PeerId {
    PeerId("remote".into())
}

async fn start_transport(mut extra: serde_json::Value) -> DirectLinkTransport {
    let dl = DirectLinkTransport::new();
    let mut params = serde_json::json!({ "listen_port": 0, "stun_servers": [] });
    if let Some(map) = extra.as_object_mut() {
        for (k, v) in map {
            params[k.as_str()] = v.clone();
        }
    }
    dl.start(TransportConfig { name: "directlink-itest".into(), params }).await
        .expect("transport start");
    dl
}

struct Responder {
    transport: DirectLinkTransport,
    identity: Arc<StaticIdentity>,
    network_id: String,
    /// responder 第一个 host 候选（注入目标地址）
    addr: std::net::SocketAddrV4,
}

async fn responder_setup(tag_suffix: &str) -> Responder {
    let network_id = format!("meshlink-poc:itest:msg1sm:{tag_suffix}");
    let ta = start_transport(serde_json::json!({})).await;
    let id = Arc::new(StaticIdentity::generate("creator-dev").expect("identity A"));
    ta.configure_noise(id.clone(), network_id.clone());
    ta.start_accepting(peer(), network_id.clone());
    let addr = ta
        .local_candidates()
        .first()
        .map(|c| c.addr)
        .expect("本机需至少一个可用 host candidate");
    Responder { transport: ta, identity: id, network_id, addr }
}

/// 原始 socket 扮演 initiator：发 tag 精确匹配的 STUN probe → responder 建立
/// accept 会话（remote = 本 socket 源地址）。之后注入的 msg1 才会被状态机处理。
fn punch(raw: &UdpSocket, to: std::net::SocketAddrV4, tag: &str) {
    let mut req = StunMessage::binding_request(new_txid());
    req.attrs.push(StunAttr::Username(tag.to_string()));
    req.attrs.push(StunAttr::MeshCandidates(vec![]));
    raw.send_to(&req.encode(), to).expect("send probe");
    // 等待 responder 建会话（含其 STUN 响应/反向 probe 噪声期）
    std::thread::sleep(Duration::from_millis(300));
}

/// 从 raw 收下一个 MD44 帧（丢弃 STUN 响应/反向 probe 噪声），超时返回 None。
fn recv_frame(raw: &UdpSocket, timeout: Duration) -> Option<Vec<u8>> {
    raw.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        match raw.recv_from(&mut buf) {
            Ok((n, _)) if n >= crypto::FRAME_HEADER_LEN && buf[0..2] == crypto::FRAME_MAGIC => {
                return Some(buf[..n].to_vec());
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

/// 建立初始加密通道（epoch 1）：返回 initiator 侧通道 + 初始 msg1 字节（重放素材）。
fn establish_epoch1(
    raw: &UdpSocket,
    r: &Responder,
    joiner: &StaticIdentity,
) -> (NoiseChannel, Vec<u8>) {
    let hs = crypto::initiate(joiner, &r.network_id, "creator-dev", r.identity.public(), 1, None)
        .expect("initiate epoch1");
    let sid = hs.session_id();
    let msg1 = hs.msg1_frame().to_vec();
    raw.send_to(&msg1, r.addr).expect("send msg1");
    let msg2 = recv_frame(raw, Duration::from_secs(3)).expect("responder 应回 msg2");
    let epoch = hs.complete(&msg2).expect("initiator complete");
    let ch = NoiseChannel::from_epoch(epoch, Role::Initiator, "joiner-dev", "creator-dev", CryptoPolicy::default())
        .with_session_id(sid);
    (ch, msg1)
}

/// prologue 绑定 session_id + epoch 后：初始握手成功 + 双向加密数据往返
/// （initiator 侧为原始 socket + NoiseChannel，responder 侧走真实 dispatcher）。
#[tokio::test]
async fn epoch_bound_handshake_success() {
    let r = responder_setup("bound-success").await;
    let raw = UdpSocket::bind("0.0.0.0:0").expect("raw socket");
    punch(&raw, r.addr, &r.network_id);

    let joiner = StaticIdentity::generate("joiner-dev").expect("identity B");
    let (mut b_ch, _) = establish_epoch1(&raw, &r, &joiner);
    let ra = r.transport.crypto_report(&peer());
    assert_eq!(ra["established"], serde_json::json!(true));
    assert_eq!(ra["epoch_id"], serde_json::json!(1));
    assert_eq!(ra["msg1_rejected"], serde_json::json!(0));

    // B → A 加密数据
    let mut wire = Vec::new();
    b_ch.send(b"epoch-bound-data", &mut wire).expect("B send");
    raw.send_to(&wire, r.addr).expect("send data frame");
    let mut rx = r.transport.packet_rx(&peer()).expect("A packet_rx");
    let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("等待解密数据超时")
        .expect("通道已关闭");
    assert_eq!(got, b"epoch-bound-data".to_vec());

    // A → B 反向加密（A 的 session remote = raw 源地址）
    r.transport
        .send_packet(peer(), Ipv4Packet { bytes: b"pong-epoch1".to_vec() })
        .await
        .expect("A send");
    let frame = recv_frame(&raw, Duration::from_secs(3)).expect("A 应回加密帧");
    let f = crypto::decode_frame(&frame).expect("decode");
    assert!(
        matches!(b_ch.recv(&f), RecvOutcome::Accepted(p) if p == b"pong-epoch1"),
        "B 必须解密 A 的回包"
    );
}

/// 重复同一合法 rekey msg1 → 幂等重发缓存 msg2；不重装纪元、不推进 epoch、
/// 不计数拒绝；通道在重复冲击后数据仍可用。
#[tokio::test]
async fn duplicate_msg1_idempotent() {
    let r = responder_setup("dup-idempotent").await;
    let raw = UdpSocket::bind("0.0.0.0:0").expect("raw socket");
    punch(&raw, r.addr, &r.network_id);

    let joiner = StaticIdentity::generate("joiner-dev").expect("identity B");
    let (mut b_ch, _) = establish_epoch1(&raw, &r, &joiner);
    let sid = b_ch.session_id();

    // 合法 rekey：epoch 2（密码学上完全合法——仅状态机语义受控）
    let hs2 = crypto::initiate(&joiner, &r.network_id, "creator-dev", r.identity.public(), 2, Some(sid))
        .expect("initiate epoch2");
    let msg1_ep2 = hs2.msg1_frame().to_vec();
    raw.send_to(&msg1_ep2, r.addr).expect("send rekey msg1");
    let msg2b = recv_frame(&raw, Duration::from_secs(3)).expect("rekey msg2");
    let e2 = hs2.complete(&msg2b).expect("rekey complete");
    b_ch.apply_new_epoch(e2);
    let ra = r.transport.crypto_report(&peer());
    assert_eq!(ra["epoch_id"], serde_json::json!(2), "responder 应进 epoch 2");
    assert_eq!(ra["rekey_count"], serde_json::json!(1));

    // 重发**同一字节串** → 幂等：重发缓存 msg2，epoch/rekey_count 不变
    raw.send_to(&msg1_ep2, r.addr).expect("resend rekey msg1");
    let msg2_dup = recv_frame(&raw, Duration::from_secs(3))
        .expect("重复 msg1 必须重发缓存 msg2（initiator 重传依赖）");
    assert_eq!(msg2_dup, msg2b, "幂等重发必须是同一 msg2 字节串");
    let ra = r.transport.crypto_report(&peer());
    assert_eq!(ra["epoch_id"], serde_json::json!(2), "不得重复推进 epoch");
    assert_eq!(ra["rekey_count"], serde_json::json!(1), "不得重复安装纪元");
    assert_eq!(ra["msg1_rejected"], serde_json::json!(0));

    // 重复冲击后数据面仍可用
    let mut wire = Vec::new();
    b_ch.send(b"after-dup", &mut wire).expect("B send after dup");
    raw.send_to(&wire, r.addr).expect("send data");
    let mut rx = r.transport.packet_rx(&peer()).expect("A packet_rx");
    let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("等待解密数据超时")
        .expect("通道已关闭");
    assert_eq!(got, b"after-dup".to_vec());
}

/// epoch 回退：已到 epoch 2 后重放 epoch 1 的合法 msg1 → 拒绝（无 msg2、
/// 不降级、不重装旧纪元）。
#[tokio::test]
async fn old_epoch_replay_rejected() {
    let r = responder_setup("old-epoch-replay").await;
    let raw = UdpSocket::bind("0.0.0.0:0").expect("raw socket");
    punch(&raw, r.addr, &r.network_id);

    let joiner = StaticIdentity::generate("joiner-dev").expect("identity B");
    let (b_ch, msg1_ep1) = establish_epoch1(&raw, &r, &joiner);
    let sid = b_ch.session_id();

    // 推进到 epoch 2
    let hs2 = crypto::initiate(&joiner, &r.network_id, "creator-dev", r.identity.public(), 2, Some(sid))
        .expect("initiate epoch2");
    raw.send_to(hs2.msg1_frame(), r.addr).expect("send rekey msg1");
    let msg2b = recv_frame(&raw, Duration::from_secs(3)).expect("rekey msg2");
    hs2.complete(&msg2b).expect("rekey complete");
    assert_eq!(r.transport.crypto_report(&peer())["epoch_id"], serde_json::json!(2));

    // 重放 epoch 1 msg1（密码学合法：密钥/prologue 均正确，仅 epoch 过期）
    raw.send_to(&msg1_ep1, r.addr).expect("replay old msg1");
    assert!(
        recv_frame(&raw, Duration::from_millis(800)).is_none(),
        "回退 msg1 不得回 msg2"
    );
    let ra = r.transport.crypto_report(&peer());
    assert_eq!(ra["msg1_rejected"].as_u64().unwrap(), 1, "必须计数拒绝");
    assert_eq!(ra["epoch_id"], serde_json::json!(2), "不得回退 epoch");
    assert_eq!(ra["rekey_count"], serde_json::json!(1), "不得重装旧纪元");
}

/// epoch 跳变：当前 epoch 1 时收到 epoch 3 的合法 msg1 → 拒绝。
#[tokio::test]
async fn future_epoch_skipped_rejected() {
    let r = responder_setup("future-epoch-skip").await;
    let raw = UdpSocket::bind("0.0.0.0:0").expect("raw socket");
    punch(&raw, r.addr, &r.network_id);

    let joiner = StaticIdentity::generate("joiner-dev").expect("identity B");
    let (b_ch, _) = establish_epoch1(&raw, &r, &joiner);
    let sid = b_ch.session_id();

    let hs3 = crypto::initiate(&joiner, &r.network_id, "creator-dev", r.identity.public(), 3, Some(sid))
        .expect("initiate epoch3");
    raw.send_to(hs3.msg1_frame(), r.addr).expect("send skipped msg1");
    assert!(
        recv_frame(&raw, Duration::from_millis(800)).is_none(),
        "跳变 msg1 不得回 msg2"
    );
    let ra = r.transport.crypto_report(&peer());
    assert_eq!(ra["msg1_rejected"].as_u64().unwrap(), 1, "必须计数拒绝");
    assert_eq!(ra["epoch_id"], serde_json::json!(1), "不得跳变 epoch");
    assert_eq!(ra["rekey_count"], serde_json::json!(0));
}

/// 未知 session_id：已建立通道后，携带其他 session_id 的合法 msg1 → 拒绝
/// （状态机先于 crypto::respond——即便其密码学上可应答也不得新建/覆盖通道）。
#[tokio::test]
async fn wrong_session_id_rejected() {
    let r = responder_setup("wrong-sid").await;
    let raw = UdpSocket::bind("0.0.0.0:0").expect("raw socket");
    punch(&raw, r.addr, &r.network_id);

    let joiner = StaticIdentity::generate("joiner-dev").expect("identity B");
    let (_, _) = establish_epoch1(&raw, &r, &joiner);

    // 其他 session_id + epoch 1：密码学合法（prologue 用帧内值构造），
    // 但已建立通道的会话不得接受未知 sid
    let other_sid = [0x42u8; 16];
    let hs = crypto::initiate(&joiner, &r.network_id, "creator-dev", r.identity.public(), 1, Some(other_sid))
        .expect("initiate other sid");
    raw.send_to(hs.msg1_frame(), r.addr).expect("send wrong-sid msg1");
    assert!(
        recv_frame(&raw, Duration::from_millis(800)).is_none(),
        "未知 session_id 的 msg1 不得回 msg2"
    );
    let ra = r.transport.crypto_report(&peer());
    assert_eq!(ra["msg1_rejected"].as_u64().unwrap(), 1, "必须计数拒绝");
    assert_eq!(ra["epoch_id"], serde_json::json!(1), "不得新建通道");
    // 原通道继续可用
    assert_eq!(ra["established"], serde_json::json!(true));
    assert_eq!(ra["role"], serde_json::json!("responder"));
}
