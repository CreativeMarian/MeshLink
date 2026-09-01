//! M0-4 双轨对比 harness（同机 loopback PoC）。
//!
//! 两轨同等条件：单 UDP socket、host-only candidate、无 signaling（凭据/候选
//! out-of-band 直接交换）。每轮 fresh 端点，共 3 轮，输出 connect / smoke-RTT /
//! STUN 包数对比表（`cargo test -- --nocapture` 可见）。
//!
//! - Track B（自研精简 ICE）：`agent::punch_with` + 真实 UdpSocket
//! - Track A（webrtc-rs）：`webrtc_track::WebRtcIceAgent`（rtc-ice 0.20.4 sans-io）
//!
//! 本测试是 WebRtcIceAgent 的首次实机运行验证（此前仅有编译级验证）。

use directlink::ice::agent::{punch_with, PunchConfig, PunchOutcome};
use directlink::ice::candidate::{gather_host_candidates, Candidate};
use directlink::ice::webrtc_track::WebRtcIceAgent;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const ROUNDS: usize = 3;
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);

fn recv_from(sock: &UdpSocket, timeout: Duration) -> Option<(SocketAddrV4, Vec<u8>)> {
    if timeout.is_zero() {
        return None;
    }
    sock.set_read_timeout(Some(timeout)).ok()?;
    let mut buf = [0u8; 2048];
    match sock.recv_from(&mut buf) {
        Ok((n, SocketAddr::V4(from))) => Some((from, buf[..n].to_vec())),
        _ => None,
    }
}

/// 过滤残留 STUN 噪音直到收到期望 payload（2s 超时）。
fn expect_payload(
    recv: &mut impl FnMut(Duration) -> Option<(SocketAddrV4, Vec<u8>)>,
    want: &str,
) -> SocketAddrV4 {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        assert!(Instant::now() < deadline, "smoke payload {want:?} 未收到");
        if let Some((from, buf)) = recv(Duration::from_millis(100)) {
            if buf == want.as_bytes() {
                return from;
            }
        }
    }
}

// ---------- Track B ----------

/// Track B 单轮：真实 socket simultaneous open → 连通 → 双向 smoke。
/// 返回 (connect 耗时, smoke RTT, A 侧 STUN 包数)。
fn track_b_round(round: usize) -> (Duration, Duration, u64) {
    let (sock_a, cands_a) = gather_host_candidates(0).expect("Track B gather A");
    let (sock_b, cands_b) = gather_host_candidates(0).expect("Track B gather B");
    let port_a = sock_a.local_addr().unwrap().port();
    let port_b = sock_b.local_addr().unwrap().port();
    let sa = Arc::new(sock_a);
    let sb = Arc::new(sock_b);

    let tx_a = Arc::new(AtomicU64::new(0));
    let tx_a2 = tx_a.clone();

    let started = Instant::now();

    // B 侧（独立线程 = simultaneous open）
    let peer_a: Vec<Candidate> = cands_a.clone();
    let sb_send = sb.clone();
    let sb_recv = sb.clone();
    let hb = std::thread::spawn(move || {
        let send = move |buf: &[u8], to: SocketAddrV4| sb_send.send_to(buf, SocketAddr::V4(to));
        let recv = move |t: Duration| recv_from(&sb_recv, t);
        punch_with(
            send,
            recv,
            SocketAddrV4::new(Ipv4Addr::LOCALHOST, port_b),
            &peer_a,
            None,
            &PunchConfig::default(),
            &format!("meshlink-poc:loopback:{round}"),
            &[],
        )
    });

    // A 侧（主线程；send 里计数）
    let sa_send = sa.clone();
    let send_a = move |buf: &[u8], to: SocketAddrV4| {
        let r = sa_send.send_to(buf, SocketAddr::V4(to));
        if r.is_ok() {
            tx_a2.fetch_add(1, Ordering::Relaxed);
        }
        r
    };
    let sa_recv = sa.clone();
    let recv_a = move |t: Duration| recv_from(&sa_recv, t);
    let out_a: PunchOutcome = punch_with(
        send_a,
        recv_a,
        SocketAddrV4::new(Ipv4Addr::LOCALHOST, port_a),
        &cands_b,
        None,
        &PunchConfig::default(),
        &format!("meshlink-poc:loopback:{round}"),
        &[],
    )
    .expect("Track B A 侧打洞");
    let out_b = hb.join().unwrap().expect("Track B B 侧打洞");
    let connect = started.elapsed();

    // 双向 smoke：A --ping--> B --pong--> A（同 socket 同端口 = 打洞路径复用）
    let ping = format!("meshlink-smoke-track-b-{round}-ping");
    let pong = format!("meshlink-smoke-track-b-{round}-pong");
    let mut recv_b = |t: Duration| recv_from(&sb, t);
    let mut recv_a2 = |t: Duration| recv_from(&sa, t);

    let t0 = Instant::now();
    sa.send_to(ping.as_bytes(), SocketAddr::V4(out_a.remote)).expect("smoke A→B send");
    let from = expect_payload(&mut recv_b, &ping);
    assert_eq!(from.port(), port_a, "ping 必须来自 A 的打洞端口");
    sb.send_to(pong.as_bytes(), SocketAddr::V4(from)).expect("smoke B→A send");
    let back = expect_payload(&mut recv_a2, &pong);
    assert_eq!(back.port(), port_b, "pong 必须来自 B 的打洞端口");
    assert_eq!(out_a.remote.port(), port_b);
    assert_eq!(out_b.remote.port(), port_a);
    let rtt = t0.elapsed();

    (connect, rtt, tx_a.load(Ordering::Relaxed))
}

// ---------- Track A ----------

/// Track A 单轮：rtc-ice sans-io 连通性检查 → 连通 → 选定路径双向 smoke。
/// 返回 (connect 耗时, smoke RTT, A 侧 (tx, rx))。
fn track_a_round(round: usize) -> (Duration, Duration, (u64, u64)) {
    let a = Arc::new(WebRtcIceAgent::new(0, Ipv4Addr::LOCALHOST).expect("Track A agent A"));
    let b = Arc::new(WebRtcIceAgent::new(0, Ipv4Addr::LOCALHOST).expect("Track A agent B"));
    let (ufrag_a, pwd_a) = a.credentials();
    let (ufrag_b, pwd_b) = b.credentials();
    let cands_a: Vec<SocketAddrV4> = a.local_candidates().iter().map(|c| c.addr).collect();
    let cands_b: Vec<SocketAddrV4> = b.local_candidates().iter().map(|c| c.addr).collect();

    let started = Instant::now();
    let b_side = b.clone();
    let hb = std::thread::spawn(move || b_side.accept(ufrag_a, pwd_a, &cands_a, CHECK_TIMEOUT));
    let remote_a = a.dial(ufrag_b, pwd_b, &cands_b, CHECK_TIMEOUT).expect("Track A dial");
    let remote_b = hb.join().unwrap().expect("Track A accept");
    let connect = started.elapsed();

    assert_eq!(remote_a.port(), b.local_base().port(), "A 选定对端必须是 B 的 base");
    assert_eq!(remote_b.port(), a.local_base().port(), "B 选定对端必须是 A 的 base");

    // 双向 smoke（裸数据走 ICE 选定路径）
    let ping = format!("meshlink-smoke-track-a-{round}-ping");
    let pong = format!("meshlink-smoke-track-a-{round}-pong");
    let t0 = Instant::now();
    a.raw_send(ping.as_bytes(), remote_a).expect("smoke A→B send");
    let from = expect_payload(&mut |t| b.raw_recv(t), &ping);
    assert_eq!(from.port(), a.local_base().port());
    b.raw_send(pong.as_bytes(), from).expect("smoke B→A send");
    let back = expect_payload(&mut |t| a.raw_recv(t), &pong);
    assert_eq!(back.port(), b.local_base().port());
    let rtt = t0.elapsed();

    (connect, rtt, a.stats())
}

fn median_ms(v: &mut [Duration]) -> f64 {
    v.sort();
    v[v.len() / 2].as_secs_f64() * 1000.0
}

#[test]
fn dual_track_loopback_comparison() {
    let mut tb_connect = Vec::new();
    let mut tb_rtt = Vec::new();
    let mut tb_tx = 0u64;
    for r in 0..ROUNDS {
        let (c, rtt, tx) = track_b_round(r);
        println!(
            "Track B round {r}: connect {:.1}ms, smoke-RTT {:.2}ms, stun_tx {tx}",
            c.as_secs_f64() * 1000.0,
            rtt.as_secs_f64() * 1000.0
        );
        tb_connect.push(c);
        tb_rtt.push(rtt);
        tb_tx += tx;
    }

    let mut ta_connect = Vec::new();
    let mut ta_rtt = Vec::new();
    let mut ta_tx = 0u64;
    let mut ta_rx = 0u64;
    for r in 0..ROUNDS {
        let (c, rtt, (tx, rx)) = track_a_round(r);
        println!(
            "Track A round {r}: connect {:.1}ms, smoke-RTT {:.2}ms, stun_tx {tx}, stun_rx {rx}",
            c.as_secs_f64() * 1000.0,
            rtt.as_secs_f64() * 1000.0
        );
        ta_connect.push(c);
        ta_rtt.push(rtt);
        ta_tx += tx;
        ta_rx += rx;
    }

    println!("== M0-4 双轨对比（loopback × {ROUNDS}） ==");
    println!(
        "Track B 自研 : connect P50 {:.1}ms | smoke-RTT P50 {:.2}ms | STUN tx/轮 {:.1}",
        median_ms(&mut tb_connect),
        median_ms(&mut tb_rtt),
        tb_tx as f64 / ROUNDS as f64
    );
    println!(
        "Track A rtc-ice: connect P50 {:.1}ms | smoke-RTT P50 {:.2}ms | STUN tx/轮 {:.1} rx/轮 {:.1}",
        median_ms(&mut ta_connect),
        median_ms(&mut ta_rtt),
        ta_tx as f64 / ROUNDS as f64,
        ta_rx as f64 / ROUNDS as f64
    );

    assert_eq!(tb_connect.len(), ROUNDS);
    assert_eq!(ta_connect.len(), ROUNDS);
}

/// Track B 打洞 socket 必须复用 gather 端口（NAT 映射按五元组的前提）。
#[test]
fn track_b_punch_reuses_gather_port() {
    let (sock, cands) = gather_host_candidates(0).expect("gather");
    let port = sock.local_addr().unwrap().port();
    assert!(cands.iter().all(|c| c.addr.port() == port));
    // M0-4R.1：loopback 候选必须被禁止（跨机假成功教训），只允许真实网卡 IP
    assert!(!cands.is_empty());
    assert!(cands.iter().all(|c| !c.addr.ip().is_loopback()));
    assert!(cands.iter().all(|c| !c.addr.ip().is_unspecified()));
}

/// recv_from 零超时防御：0 不能落到 set_read_timeout（Windows 语义 = 永久阻塞）。
#[test]
fn recv_from_zero_timeout_is_none() -> io::Result<()> {
    let s = UdpSocket::bind(("127.0.0.1", 0))?;
    assert!(recv_from(&s, Duration::ZERO).is_none());
    Ok(())
}
