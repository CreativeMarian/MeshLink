//! N2NTransport 端到端测试（M1-2）：
//! 真实 N2NSupernode（进程内）+ 双 N2NTransport（A creator / B joiner）
//! → 社区注册 → QUERY_PEER 发现 → Supernode 中继 → Noise IK 握手 → 数据面。
//!
//! 覆盖：
//! - 无第二 TAP：N2NTransport 不创建任何网卡（结构上由 trait/内存通道承载）；
//! - Noise encrypted 数据经 relay 往返（64B）；
//! - 每 Supernode 独立熔断：kill → OPEN；restart → HALF_OPEN probe → CLOSED。

use directlink::crypto::StaticIdentity;
use std::sync::Arc;
use transport_api::{Ipv4Packet, PeerHints, PeerId};
use transport_n2n::{N2NParams, N2NSupernode, N2NTransport, SupernodeConfig};

fn params(sn_addr: std::net::SocketAddr, community: &str) -> N2NParams {
    N2NParams {
        supernodes: vec![transport_n2n::SupernodeEndpoint {
            id: "sn-test".into(),
            host: "127.0.0.1".into(),
            port: sn_addr.port(),
            priority: 0,
        }],
        community: community.into(),
        network_id: "net1".into(),
        health_interval_ms: 120,
        request_timeout_ms: 800,
        failure_threshold: 3,
        open_cooldown_secs: 1,
        half_open_success_threshold: 2,
    }
}

fn breaker_state(t: &N2NTransport, sn_id: &str) -> String {
    t.breaker_states()
        .iter()
        .find(|v| v["sn_id"] == sn_id)
        .map(|v| v["state"].as_str().unwrap_or("?").to_string())
        .unwrap_or("missing".into())
}

#[tokio::test(flavor = "multi_thread")]
async fn n2n_relay_noise_ping_roundtrip() {
    let sn = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-test".into(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();
    let sn_addr = sn.local_addr();

    let id_a = Arc::new(StaticIdentity::generate("dev_a").unwrap());
    let id_b = Arc::new(StaticIdentity::generate("dev_b").unwrap());
    let key_a = *id_a.public();
    let key_b = *id_b.public();
    let peer_a = PeerId("dev_a".into());
    let peer_b = PeerId("dev_b".into());

    // creator（A）：接受模式
    let t_a = N2NTransport::new(params(sn_addr, "testnet")).unwrap();
    t_a.configure_noise(Arc::clone(&id_a), "net1".into());
    t_a.start_accepting(peer_b.clone(), "session".into());
    t_a.set_expected_initiator(&peer_b, key_b);
    t_a.require_initiator_identity(&peer_b);

    // joiner（B）：发现 + Noise 握手
    let t_b = N2NTransport::new(params(sn_addr, "testnet")).unwrap();
    t_b.configure_noise(Arc::clone(&id_b), "net1".into());
    t_b.connect_peer(peer_a.clone(), PeerHints::default()).expect("B 应经 SN 发现 A");
    t_b.start_noise_initiator(&peer_a, Arc::clone(&id_b), "net1", "dev_a", &key_a)
        .await
        .expect("Noise IK 握手应成功");

    // 数据面：B → A（64B 明文 IPv4 包）
    let mut rx_a = t_a.packet_rx(&peer_b).expect("A 应有对端 rx 通道");
    let payload: Vec<u8> = {
        let mut v = vec![0u8; 64];
        v[0] = 0x45; // IPv4
        v[9] = 17; // UDP
        v[20..24].copy_from_slice(&[10, 0, 0, 1]);
        v
    };
    t_b.send_packet(peer_a.clone(), Ipv4Packet { bytes: payload.clone() }).await.expect("B 发送应成功");

    // A 收到明文
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx_a.recv())
        .await
        .expect("A 应收到 B 的明文包")
        .expect("通道未关闭");
    assert_eq!(got, payload, "relay + Noise 解密后应还原原包");

    // A → B 反向
    let mut rx_b = t_b.packet_rx(&peer_a).expect("B 应有对端 rx 通道");
    let payload2: Vec<u8> = {
        let mut v = vec![0xABu8; 64];
        v[0] = 0x45;
        v
    };
    t_a.send_packet(peer_b.clone(), Ipv4Packet { bytes: payload2.clone() }).await.expect("A 发送应成功");
    let got2 = tokio::time::timeout(std::time::Duration::from_secs(5), rx_b.recv())
        .await
        .expect("B 应收到 A 的明文包")
        .expect("通道未关闭");
    assert_eq!(got2, payload2, "反向 relay + Noise 解密应还原");

    // 身份：双方 channel 的 remote_fingerprint 应分别为对方公钥
    let report_a = t_a.crypto_report(&peer_b);
    assert_eq!(
        report_a["remote_fingerprint"].as_str().unwrap(),
        &hex(&key_b),
        "A 应验证 B 的身份指纹"
    );
    let report_b = t_b.crypto_report(&peer_a);
    assert_eq!(
        report_b["remote_fingerprint"].as_str().unwrap(),
        &hex(&key_a),
        "B 应验证 A 的身份指纹"
    );

    // 熔断初始 CLOSED
    assert_eq!(breaker_state(&t_a, "sn-test"), "closed");
    assert_eq!(breaker_state(&t_b, "sn-test"), "closed");

    drop(sn);
}

#[tokio::test(flavor = "multi_thread")]
async fn supernode_kill_opens_breaker_and_restart_recovers() {
    let sn = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-test".into(),
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        ..SupernodeConfig::default()
    })
    .unwrap();
    let sn_addr = sn.local_addr();

    let id_a = Arc::new(StaticIdentity::generate("dev_a").unwrap());
    let id_b = Arc::new(StaticIdentity::generate("dev_b").unwrap());
    let key_a = *id_a.public();
    let key_b = *id_b.public();
    let peer_a = PeerId("dev_a".into());
    let peer_b = PeerId("dev_b".into());

    let t_a = N2NTransport::new(params(sn_addr, "testnet")).unwrap();
    t_a.configure_noise(Arc::clone(&id_a), "net1".into());
    t_a.start_accepting(peer_b.clone(), "s".into());
    t_a.set_expected_initiator(&peer_b, key_b);
    t_a.require_initiator_identity(&peer_b);

    let t_b = N2NTransport::new(params(sn_addr, "testnet")).unwrap();
    t_b.configure_noise(Arc::clone(&id_b), "net1".into());
    t_b.connect_peer(peer_a.clone(), PeerHints::default()).expect("B 应发现 A");
    t_b.start_noise_initiator(&peer_a, Arc::clone(&id_b), "net1", "dev_a", &key_a)
        .await
        .expect("握手应成功");

    assert_eq!(breaker_state(&t_b, "sn-test"), "closed");

    // 杀死 Supernode → 健康探测失败累计 → OPEN（failure_threshold=3，间隔 120ms）
    sn.stop();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if breaker_state(&t_b, "sn-test") == "open" {
            break;
        }
        assert!(std::time::Instant::now() < deadline, "Supernode 被杀后熔断器应 OPEN");
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    }

    // 释放旧实例（join 线程 + 释放端口），重启同端口
    drop(sn);
    std::thread::sleep(std::time::Duration::from_millis(50));

    // 重启 Supernode（同端口）→ 健康成功 → HALF_OPEN probe → CLOSED
    let sn2 = N2NSupernode::bind(SupernodeConfig {
        sn_id: "sn-test".into(),
        bind_addr: sn_addr,
        ..SupernodeConfig::default()
    })
    .unwrap();
    let deadline2 = std::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if breaker_state(&t_b, "sn-test") == "closed" {
            break;
        }
        assert!(std::time::Instant::now() < deadline2, "Supernode 重启后熔断器应恢复 CLOSED");
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    }
    assert_eq!(breaker_state(&t_a, "sn-test"), "closed", "A 侧同样恢复");

    drop(sn2);
}

fn hex(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(b.len() * 2);
    for &x in b {
        out.push(HEX[(x >> 4) as usize] as char);
        out.push(HEX[(x & 0xF) as usize] as char);
    }
    out
}

/// 真实 N2N Supernode 独立进程（M1-2 Gate：真实 N2N Supernode process PASS）。
/// 通过 CARGO_BIN_EXE_n2n-supernode 拉起真实二进制，A/B transport 经该进程
/// 完成注册→中继→Noise 握手→明文往返，验证 Supernode 不作为数据面明文瓶颈。
#[tokio::test(flavor = "multi_thread")]
async fn real_supernode_process_relay() {
    let bin = env!("CARGO_BIN_EXE_n2n-supernode");
    let mut child = std::process::Command::new(bin)
        .arg("--id").arg("sn-proc")
        .arg("--listen").arg("127.0.0.1:0")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn n2n-supernode");
    let mut stdout = std::io::BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    use std::io::BufRead;
    let ready = std::io::BufRead::read_line(&mut stdout, &mut line);
    assert!(ready.is_ok() && line.starts_with("N2N_SUPERNODE_READY"), "就绪行: {line}");
    let parts: Vec<&str> = line.split_whitespace().collect();
    assert_eq!(parts[1], "sn-proc");
    let sn_addr: std::net::SocketAddr = parts[2].parse().expect("bind addr");

    let id_a = Arc::new(StaticIdentity::generate("dev_a").unwrap());
    let id_b = Arc::new(StaticIdentity::generate("dev_b").unwrap());
    let key_b = *id_b.public();
    let key_a = *id_a.public();
    let peer_a = PeerId("dev_a".into());
    let peer_b = PeerId("dev_b".into());

    let t_a = N2NTransport::new(params(sn_addr, "procnet")).unwrap();
    t_a.configure_noise(Arc::clone(&id_a), "net1".into());
    t_a.start_accepting(peer_b.clone(), "session".into());
    t_a.set_expected_initiator(&peer_b, key_b);
    t_a.require_initiator_identity(&peer_b);

    let t_b = N2NTransport::new(params(sn_addr, "procnet")).unwrap();
    t_b.configure_noise(Arc::clone(&id_b), "net1".into());
    t_b.connect_peer(peer_a.clone(), PeerHints::default()).expect("B 发现 A");
    t_b.start_noise_initiator(&peer_a, Arc::clone(&id_b), "net1", "dev_a", &key_a)
        .await
        .expect("Noise IK 握手应成功");

    let mut rx_a = t_a.packet_rx(&peer_b).expect("A rx");
    let payload: Vec<u8> = { let mut v = vec![0u8; 64]; v[0] = 0x45; v[9] = 17; v };
    t_b.send_packet(peer_a.clone(), Ipv4Packet { bytes: payload.clone() }).await.expect("B 发送");
    let got = tokio::time::timeout(std::time::Duration::from_secs(5), rx_a.recv())
        .await
        .expect("A 应收到明文包")
        .expect("通道未关闭");
    assert_eq!(got, payload, "经真实进程 Supernode 中继 + Noise 解密应还原");

    let _ = child.kill();
    let _ = child.wait();
}
