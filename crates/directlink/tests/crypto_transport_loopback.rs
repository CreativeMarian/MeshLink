//! M0-5 双 transport 集成测试（同进程两实例 + 真实 UDP socket，无外网依赖）。
//!
//! 复刻 PoC create/join 流程：A（creator：accept + Noise responder）↔
//! B（joiner：punch + Noise initiator），验证 transport.rs 的完整 M0-5 链路：
//! dispatcher MD44 分派 → IK 握手（msg1/msg2）→ send_packet 加密 → 接收解密
//! → crypto_report 统计 → rekey（时间阈值触发，数据不中断）。

use directlink::crypto::StaticIdentity;
use directlink::transport::DirectLinkTransport;
use std::sync::Arc;
use std::time::Duration;
use transport_api::{Endpoint, Ipv4Packet, PeerHints, PeerId, TransportConfig, TransportProvider};

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

fn host_endpoints(dl: &DirectLinkTransport) -> Vec<Endpoint> {
    dl.local_candidates()
        .iter()
        .map(|c| Endpoint { ip: c.addr.ip().to_string(), port: c.addr.port(), kind: "host".into() })
        .collect()
}

async fn recv_expect(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    want: &[u8],
) {
    // 10s：workspace 全量并行时 dispatcher 线程可能被其它测试进程饿到 >3s，
    // 3s 会在高负载下假失败（本超时只保活性，不测时延）
    let got = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("等待解密数据超时")
        .expect("通道已关闭");
    assert_eq!(got, want.to_vec(), "解密后明文必须与发送一致");
}

/// 完整链路：punch → IK 握手 → 加密双向数据 → 报告统计。
#[tokio::test]
async fn noise_handshake_and_encrypted_roundtrip() {
    let network_id = "meshlink-poc:itest:handshake";
    let id_a = Arc::new(StaticIdentity::generate("creator-dev").expect("identity A"));
    let id_b = Arc::new(StaticIdentity::generate("joiner-dev").expect("identity B"));

    // creator 侧：accept 模式 + Noise responder 配置（msg1 到达前）
    let ta = start_transport(serde_json::json!({})).await;
    ta.configure_noise(id_a.clone(), network_id.to_string());
    ta.start_accepting(peer(), network_id.to_string());

    // joiner 侧：punch（session tag = network_id，与 PoC 一致）
    let tb = start_transport(serde_json::json!({})).await;
    tb.set_punch_session(network_id.to_string(), tb.punch_candidates_wire());
    let eps = host_endpoints(&ta);
    assert!(!eps.is_empty(), "本机需至少一个可用 host candidate");
    tb.connect_peer(peer(), PeerHints { endpoints: eps, static_key_fingerprint: None, overlay_mac: None })
        .await
        .expect("punch（同机 host 直连）");

    // joiner 发起 IK 握手（expected_remote = creator 公钥）
    let _sid = tb
        .start_noise_initiator(&peer(), id_b.clone(), network_id, "creator-dev", id_a.public())
        .await
        .expect("Noise IK 握手");

    // B → A：加密发送，A 收到解密明文
    let mut rx_a = ta.packet_rx(&peer()).expect("A packet_rx");
    tb.send_packet(peer(), Ipv4Packet { bytes: b"PING-encrypted-1".to_vec() }).await.expect("B send");
    recv_expect(&mut rx_a, b"PING-encrypted-1").await;

    // A → B：反向加密
    let mut rx_b = tb.packet_rx(&peer()).expect("B packet_rx");
    ta.send_packet(peer(), Ipv4Packet { bytes: b"PONG-encrypted-1".to_vec() }).await.expect("A send");
    recv_expect(&mut rx_b, b"PONG-encrypted-1").await;

    // 连发多包（seq 递增 + replay 窗口正常推进）
    for i in 0..5u32 {
        tb.send_packet(peer(), Ipv4Packet { bytes: format!("burst-{i}").into_bytes() }).await.expect("burst send");
        recv_expect(&mut rx_a, format!("burst-{i}").as_bytes()).await;
    }

    // 双端报告：established + 帧统计 + 对端指纹
    let ra = ta.crypto_report(&peer());
    let rb = tb.crypto_report(&peer());
    assert_eq!(ra["established"], serde_json::json!(true));
    assert_eq!(rb["established"], serde_json::json!(true));
    assert_eq!(ra["frames_rx"], serde_json::json!(6), "A 应收到 6 个解密帧");
    assert_eq!(rb["frames_rx"], serde_json::json!(1), "B 应收到 1 个解密帧");
    assert_eq!(rb["frames_tx"], serde_json::json!(6));
    // 指纹一致性：B 学到的对端指纹 = A 公钥；A 学到的 = B 公钥
    assert_eq!(ra["remote_static_fingerprint"], serde_json::json!(id_b.fingerprint()));
    assert_eq!(rb["remote_static_fingerprint"], serde_json::json!(id_a.fingerprint()));
    assert_eq!(ra["role"], serde_json::json!("responder"));
    assert_eq!(rb["role"], serde_json::json!("initiator"));
    // 双端 session_id 一致（demux 标识）
    assert_eq!(ra["session_id"], rb["session_id"]);
}

/// 握手失败路径：joiner 持错误公钥 → IK msg1 无法通过 responder 校验 → 握手超时。
#[tokio::test]
async fn wrong_key_handshake_times_out() {
    let network_id = "meshlink-poc:itest:wrongkey";
    let id_a = Arc::new(StaticIdentity::generate("creator-real").expect("identity A"));
    let id_impostor = Arc::new(StaticIdentity::generate("impostor").expect("impostor"));
    let id_b = Arc::new(StaticIdentity::generate("joiner-dev").expect("identity B"));

    let ta = start_transport(serde_json::json!({})).await;
    ta.configure_noise(id_a.clone(), network_id.to_string());
    ta.start_accepting(peer(), network_id.to_string());

    let tb = start_transport(serde_json::json!({})).await;
    tb.set_punch_session(network_id.to_string(), tb.punch_candidates_wire());
    let eps = host_endpoints(&ta);
    tb.connect_peer(peer(), PeerHints { endpoints: eps, static_key_fingerprint: None, overlay_mac: None })
        .await
        .expect("punch 与密钥无关，应成功");

    // B 指向 impostor 公钥：A（持 id_a 私钥）解不开 msg1 → 不回 msg2 → 握手超时
    let result = tb
        .start_noise_initiator(&peer(), id_b.clone(), network_id, "creator-real", id_impostor.public())
        .await;
    assert!(result.is_err(), "错误公钥必须握手失败");
    let err = format!("{:?}", result.unwrap_err());
    assert!(err.contains("CryptoHandshakeFailed"), "错误码应含 CryptoHandshakeFailed: {err}");
}

/// rekey 端到端：时间阈值触发 → 双端 epoch 前进 → 数据继续不中断。
#[tokio::test]
async fn rekey_keeps_data_flowing() {
    let network_id = "meshlink-poc:itest:rekey";
    let id_a = Arc::new(StaticIdentity::generate("creator-dev").expect("identity A"));
    let id_b = Arc::new(StaticIdentity::generate("joiner-dev").expect("identity B"));
    // 3s 触发 rekey；宽限 1.5s；握手重试快（loopback 不会用到重试）
    let policy = serde_json::json!({
        "crypto": { "rekey_after_ms": 3000, "rekey_grace_ms": 1500, "handshake_rto_ms": 300, "handshake_retries": 6 }
    });

    let ta = start_transport(policy.clone()).await;
    ta.configure_noise(id_a.clone(), network_id.to_string());
    ta.start_accepting(peer(), network_id.to_string());

    let tb = start_transport(policy).await;
    tb.set_punch_session(network_id.to_string(), tb.punch_candidates_wire());
    let eps = host_endpoints(&ta);
    tb.connect_peer(peer(), PeerHints { endpoints: eps, static_key_fingerprint: None, overlay_mac: None })
        .await
        .expect("punch");
    let _sid = tb
        .start_noise_initiator(&peer(), id_b.clone(), network_id, "creator-dev", id_a.public())
        .await
        .expect("初始握手");

    let mut rx_a = ta.packet_rx(&peer()).expect("A packet_rx");
    tb.send_packet(peer(), Ipv4Packet { bytes: b"before-rekey".to_vec() }).await.expect("send before");
    recv_expect(&mut rx_a, b"before-rekey").await;

    // 等 rekey 触发（监视线程 1s 轮询 + 3s 阈值 + 握手耗时）
    tokio::time::sleep(Duration::from_millis(6000)).await;
    let rb = tb.crypto_report(&peer());
    let ra = ta.crypto_report(&peer());
    assert!(
        rb["rekey_count"].as_u64().unwrap_or(0) >= 1,
        "initiator 侧应完成至少一次 rekey（实际 {}）",
        rb["rekey_count"]
    );
    assert_eq!(ra["rekey_count"], rb["rekey_count"], "responder 应跟随同一纪元");
    assert_eq!(ra["epoch_id"], rb["epoch_id"], "双端 epoch 应一致");
    assert_eq!(ra["epoch_id"], serde_json::json!(2), "应已进入 epoch 2");

    // rekey 后数据照常（新纪元密钥）
    tb.send_packet(peer(), Ipv4Packet { bytes: b"after-rekey".to_vec() }).await.expect("send after");
    recv_expect(&mut rx_a, b"after-rekey").await;
    // rekey 后反向也正常
    let mut rx_b = tb.packet_rx(&peer()).expect("B packet_rx");
    ta.send_packet(peer(), Ipv4Packet { bytes: b"after-rekey-pong".to_vec() }).await.expect("A send after");
    recv_expect(&mut rx_b, b"after-rekey-pong").await;
}
