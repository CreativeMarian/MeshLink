//! MinimalPunchAgent（Track B）：STUN-assisted UDP Hole Punching。
//!
//! **命名准确性（ADR-003 §Track B 结论）**：本模块**不是** RFC 8445 ICE Full Agent。
//! 它是一个以 simultaneous open 为核心的精简打洞引擎，未实现以下 ICE 全集要素：
//! Candidate Pair 打分/Checklist、Triggered Check、Controlling/Controlled 角色仲裁、
//! Tie Breaker、Nomination（USE-CANDIDATE）、ICE-CONTROLLING/ICE-CONTROLLED 属性、
//! USERNAME/MESSAGE-INTEGRITY 校验（完整性由 M0-5 Noise 层取代）。
//! 文档与对比报告中一律称 **MinimalPunchAgent / Purpose-built UDP Hole Punch
//! Engine**，禁止称 "Custom ICE" / "ICE 实现"。
//!
//! 实际能力（RFC 5389 客户端子集 + simultaneous open）：
//! - Binding Request/Response 交换（FINGERPRINT 防混淆）
//! - 双方同时互发 Binding（NAT 映射建立 + 双向可达确认）
//! - Keepalive（间隔/miss 可配，miss 超限回调 down）
//! - NAT Mapping 观测（两个独立 STUN server 的映射比较——保守二分类，
//!   **不做** RFC 5780 cone 分类，ADR 报告记 Observed Mapping 明细）
//! - 帧交换是同步 `send`/`recvfrom` 注入式闭包：生产侧用真实 UdpSocket，
//!   测试侧注入内存总线。
//! - M0-4 明确不做：TURN/Relay、消息完整性 HMAC、多网卡完整 gathering、
//!   RFC 5780 精确 NAT 行为分类。

use super::candidate::Candidate;
use super::stun::{append_fingerprint, binding_exchange_with, new_txid, StunAttr, StunError, StunMessage, BINDING_REQUEST, BINDING_RESPONSE};
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// 每对 candidate 的连通性检查配置。
#[derive(Debug, Clone)]
pub struct PunchConfig {
    /// 单次请求 RTO（RFC 5389 默认 500ms；PoC 收紧加速）
    pub rto: Duration,
    /// 每个 pair 内的重传次数
    pub retries: u32,
    /// 打洞总窗口（simultaneous open 双向注入需要时间）
    pub window: Duration,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self { rto: Duration::from_millis(200), retries: 1, window: Duration::from_secs(5) }
    }
}

/// 打洞/检查失败。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IceError {
    #[error("打洞窗口耗尽（尝试 {tried} 轮）")]
    PunchTimeout { tried: usize },
    #[error("连通性检查失败: {0:?}")]
    Check(StunError),
}

/// 成功建立的 pair。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PunchOutcome {
    /// 本地 socket 基地址
    pub local_base: SocketAddrV4,
    /// 对端可达地址（host 或 srflx）
    pub remote: SocketAddrV4,
    /// 检查往返时延
    pub rtt: Duration,
}

/// 构造连通性检查请求（USERNAME 承载角色/会话 tag；FINGERPRINT 防非 STUN 流量混淆）。
/// `extra` 为附加属性（如 MeshCandidates——双向 punch 的 candidate exchange 逆向通道），
/// 必须在 FINGERPRINT 之前注入。
pub fn check_request_attrs(tag: &str, extra: &[StunAttr]) -> StunMessage {
    let mut msg = StunMessage::binding_request(new_txid());
    msg.attrs.push(StunAttr::Username(tag.into()));
    msg.attrs.extend_from_slice(extra);
    append_fingerprint(&msg)
}

/// 无附加属性的检查请求（兼容旧调用点）。
pub fn check_request(tag: &str) -> StunMessage {
    check_request_attrs(tag, &[])
}

/// 对一条已收到的 Binding Request 生成响应：XOR-MAPPED = 观察到的来源地址。
pub fn check_response(req: &StunMessage, observed: SocketAddrV4) -> StunMessage {
    StunMessage { msg_type: BINDING_RESPONSE, txid: req.txid, attrs: vec![StunAttr::XorMapped(observed)] }
}

/// 注入式打洞：两端同时调用本函数即完成 simultaneous open。
///
/// - `send(buf, to)`：向任意地址发包（真实 `UdpSocket::send_to` / 测试注入）
/// - `recv(timeout) -> (from, buf)`：recvfrom 语义
/// - `local_base`：本端 socket 基地址（结果记录）
/// - `peer_candidates`：对端候选（host 优先可命中 LAN 直连；双 NAT 靠 srflx +
///   simultaneous open；内部按 priority 降序逐个尝试）
/// - `expected_self`：本端 srflx 反射地址（若已 gather）——响应 XOR-MAPPED 必须
///   等于它（证明 hole 建立在本端映射上）；None 跳过校验（host 直连场景）
/// - `punch_tag`：请求 USERNAME（M0-4R.1 升级为 session-scoped：
///   `meshlink-poc:{session_id}:{nonce}`，双端只接受当前 Session 的 probe）
/// - `extra_attrs`：附加到每个请求的属性（MeshCandidates 等）
pub fn punch_with<F, G>(
    mut send: F,
    mut recv: G,
    local_base: SocketAddrV4,
    peer_candidates: &[Candidate],
    expected_self: Option<SocketAddrV4>,
    cfg: &PunchConfig,
    punch_tag: &str,
    extra_attrs: &[StunAttr],
) -> Result<PunchOutcome, IceError>
where
    F: FnMut(&[u8], SocketAddrV4) -> std::io::Result<usize>,
    G: FnMut(Duration) -> Option<(SocketAddrV4, Vec<u8>)>,
{
    // 对端候选按优先级降序（host > srflx：LAN 直连优先命中）
    let mut remotes: Vec<(SocketAddrV4, u32)> = peer_candidates
        .iter()
        .map(|c| (c.addr, c.priority()))
        .collect();
    remotes.sort_by(|a, b| b.1.cmp(&a.1));
    remotes.dedup();

    let deadline = Instant::now() + cfg.window;
    let mut rounds = 0usize;
    'outer: loop {
        if Instant::now() >= deadline {
            return Err(IceError::PunchTimeout { tried: rounds });
        }
        for &(remote, _) in &remotes {
            rounds += 1;
            let req = check_request_attrs(punch_tag, extra_attrs);
            let txid = req.txid;
            let wire = req.encode();
            let sent_at = Instant::now();
            if send(&wire, remote).is_err() {
                continue;
            }
            // 等本检查响应；期间扮演 server 角色（立即回应对端请求——打洞关键动作）
            let pair_deadline = Instant::now() + (cfg.rto * (cfg.retries as u32 + 1));
            while Instant::now() < pair_deadline {
                let wait = pair_deadline.saturating_duration_since(Instant::now());
                let Some((from, buf)) = recv(wait.min(Duration::from_millis(50))) else {
                    continue;
                };
                let Ok(msg) = StunMessage::decode(&buf) else { continue };
                match msg.msg_type {
                    BINDING_REQUEST => {
                        let resp = check_response(&msg, from);
                        let _ = send(&resp.encode(), from);
                    }
                    BINDING_RESPONSE => {
                        if msg.txid != txid {
                            continue;
                        }
                        if let Some(self_mapped) = expected_self {
                            match msg.get_xor_mapped() {
                                Some(x) if x == self_mapped => {}
                                _ => continue, // 映射不匹配——非本端 hole 的响应
                            }
                        }
                        return Ok(PunchOutcome { local_base, remote, rtt: sent_at.elapsed() });
                    }
                    _ => {}
                }
            }
            if Instant::now() >= deadline {
                break 'outer;
            }
        }
    }
    Err(IceError::PunchTimeout { tried: rounds })
}

/// Keepalive：周期 Binding Request，统计 RTT；连续 miss 达阈值触发 on_down（health 事件）。
pub struct Keepalive {
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Keepalive {
    /// `send`/`recv` 注入（真实 socket send_to/recvfrom）；miss == miss_limit 时回调一次，之后每 miss_limit 次再回调。
    pub fn start<F, G>(
        mut send: F,
        mut recv: G,
        peer: SocketAddrV4,
        interval: Duration,
        miss_limit: u32,
        on_down: impl Fn(u32) + Send + 'static,
    ) -> (Self, Arc<Mutex<Option<Duration>>>)
    where
        F: FnMut(&[u8], SocketAddrV4) -> std::io::Result<usize> + Send + 'static,
        G: FnMut(Duration) -> Option<(SocketAddrV4, Vec<u8>)> + Send + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let last_rtt: Arc<Mutex<Option<Duration>>> = Arc::new(Mutex::new(None));
        let rtt_out = last_rtt.clone();
        let handle = std::thread::Builder::new()
            .name("ice-keepalive".into())
            .spawn(move || {
                let mut misses = 0u32;
                while !stop2.load(Ordering::Acquire) {
                    let req = check_request("meshlink-keepalive");
                    let txid = req.txid;
                    if send(&req.encode(), peer).is_ok() {
                        let started = Instant::now();
                        let budget = interval.min(Duration::from_secs(2));
                        let mut got = false;
                        while started.elapsed() < budget {
                            if stop2.load(Ordering::Acquire) {
                                return;
                            }
                            let wait = budget.saturating_sub(started.elapsed());
                            let Some((_, buf)) = recv(wait.min(Duration::from_millis(50))) else {
                                continue;
                            };
                            if let Ok(msg) = StunMessage::decode(&buf) {
                                if msg.msg_type == BINDING_RESPONSE && msg.txid == txid {
                                    *rtt_out.lock().unwrap() = Some(started.elapsed());
                                    got = true;
                                    break;
                                }
                            }
                        }
                        if got {
                            misses = 0;
                        } else {
                            misses += 1;
                            if misses % miss_limit == 0 {
                                on_down(misses);
                            }
                        }
                    }
                    std::thread::sleep(interval);
                }
            })
            .expect("keepalive 线程必须可创建");
        (Self { stop, handle: Some(handle) }, last_rtt)
    }
}

impl Drop for Keepalive {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// NAT Mapping 行为（RFC 4787 **映射行为**保守二分类——非 cone 类型，禁止宣称）。
///
/// ADR 报告必须同时给出 [`NatObservation::observed`] 明细（STUN-A → x, STUN-B → y）；
/// 若需 RFC 5780 Behavior Discovery（区分 ADM/SDM、filtering 行为）必须用支持
/// CHANGE-REQUEST 的 server——当前 PoC 记 `observed` 不做结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMapping {
    /// 端点无关映射：同一 socket 到两个独立 server 观察到同一公网映射
    EndpointIndependent,
    /// 两个 server 观察到不同映射（ADM/SDM 合并保守归类——PoC 无法区分）
    AddressDependent,
    /// 任一 server 查询失败
    Unknown,
}

/// NAT 映射观测结果：保守分类 + 每个 server 的 Observed Mapping 明细。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NatObservation {
    pub classification: NatMapping,
    /// (server, 本 socket 在该 server 观察到的公网映射)，按查询顺序
    pub observed: Vec<(SocketAddrV4, SocketAddrV4)>,
}

/// 用两个不同公网 IP 的 STUN server 观测映射行为（注入式，与 binding 交换同构）。
///
/// **send 必须带目的地址**：server-A/server-B 的请求必须真的发往各自 server
/// （曾经的 bug：send 固定发第一个 server，第二个观测永远超时 → Unknown）。
pub fn probe_nat_mapping_with<F, G>(
    servers: [SocketAddrV4; 2],
    mut send: F,
    mut recv: G,
    rto: Duration,
    retries: u32,
) -> NatObservation
where
    F: FnMut(&[u8], SocketAddrV4) -> std::io::Result<usize>,
    G: FnMut(Duration) -> Option<(SocketAddrV4, Vec<u8>)>,
{
    let mut observed = Vec::with_capacity(2);
    let mut mapped = Vec::with_capacity(2);
    for server in servers {
        // 每个事务独立闭包绑定目的 server（binding_exchange_with 的 send 无地址语义）
        let result = binding_exchange_with(
            new_txid(),
            server,
            |b| send(b, server),
            |t| recv(t),
            rto,
            retries,
        );
        match result {
            Ok(r) => {
                observed.push((server, r.mapped));
                mapped.push(r.mapped);
            }
            Err(_) => return NatObservation { classification: NatMapping::Unknown, observed },
        }
    }
    let classification = if mapped[0] == mapped[1] {
        NatMapping::EndpointIndependent
    } else {
        NatMapping::AddressDependent
    };
    NatObservation { classification, observed }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn v4(ip: [u8; 4], port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::from(ip), port)
    }

    /// 双端打洞闭环（纯内存总线，无真实 socket）：
    /// 双方互发 Binding Request、互回 Response，simultaneous open 全程可观测。
    #[test]
    fn two_sides_punch_over_injected_bus() {
        let bus: Arc<Mutex<Vec<(usize, Vec<u8>)>>> = Arc::new(Mutex::new(Vec::new())); // (dst 侧 id, 包)
        let base_a = v4([192, 168, 1, 10], 40001);
        let base_b = v4([192, 168, 2, 20], 40002);

        // move 闭包捕获 bus 的克隆（外层 bus 留作最终空队列断言）
        let bus_in = bus.clone();
        let run_side = move |id: usize, peer_cands: Vec<Candidate>| -> Result<PunchOutcome, IceError> {
            let bus_for_send = bus_in.clone();
            let bus_for_recv = bus_in.clone();
            let send = move |buf: &[u8], to: SocketAddrV4| {
                let dst = if to == base_a { 0 } else if to == base_b { 1 } else { usize::MAX };
                bus_for_send.lock().unwrap().push((dst, buf.to_vec()));
                Ok(buf.len())
            };
            // 忠实阻塞语义：总线空时按 timeout 等待（而非立即 None）。
            // 立即返回会让 punch_with 内层变成纯 CPU 空转——并行/AV 扫描等线程
            // 饥饿场景下窗口被空转烧尽而误判超时（真实 socket 是阻塞的）。
            let recv = move |timeout: Duration| -> Option<(SocketAddrV4, Vec<u8>)> {
                let deadline = Instant::now() + timeout;
                loop {
                    let pkt = {
                        let mut b = bus_for_recv.lock().unwrap();
                        b.iter().position(|(dst, _)| *dst == id).map(|i| b.remove(i))
                    };
                    if let Some((dst, buf)) = pkt {
                        // dst == 收件方 id：发给 A(0) 的包来自 B，发给 B(1) 的包来自 A
                        let from = if dst == 0 { base_b } else { base_a };
                        return Some((from, buf));
                    }
                    let now = Instant::now();
                    if now >= deadline {
                        return None;
                    }
                    std::thread::sleep((deadline - now).min(Duration::from_millis(2)));
                }
            };
            let local = if id == 0 { base_a } else { base_b };
            punch_with(
                send,
                recv,
                local,
                &peer_cands,
                None,
                &PunchConfig { rto: Duration::from_millis(5), retries: 1, window: Duration::from_secs(5) },
                "meshlink-poc",
                &[],
            )
        };

        // 两侧并发跑（对齐 simultaneous open 语义；对端候选只含对方）
        let run_b = run_side.clone();
        let b_side = std::thread::spawn(move || run_b(1, vec![Candidate::host(base_a)]));
        let a = run_side(0, vec![Candidate::host(base_b)]).expect("A 侧打洞必须成功");
        let b = b_side.join().unwrap().expect("B 侧打洞必须成功");
        assert_eq!(a.remote, base_b);
        assert_eq!(b.remote, base_a);
        assert!(bus.lock().unwrap().is_empty(), "全部包都应被两侧消费（双向互通证据）");
    }

    /// 映射校验：响应 XOR-MAPPED ≠ expected_self 时必须拒绝，不得误判成功。
    #[test]
    fn punch_rejects_wrong_mapped() {
        let base_a = v4([10, 0, 0, 1], 50001);
        let base_b = v4([10, 0, 0, 2], 50002);
        let expected_self = Some(v4([1, 2, 3, 4], 50001)); // 不可能匹配的反射地址

        let seen: Arc<Mutex<Vec<[u8; 12]>>> = Arc::new(Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        let send = move |buf: &[u8], _to: SocketAddrV4| {
            if let Ok(m) = StunMessage::decode(buf) {
                if m.msg_type == BINDING_REQUEST {
                    seen2.lock().unwrap().push(m.txid);
                }
            }
            Ok(buf.len())
        };
        let seen3 = seen.clone();
        let recv = move |t: Duration| -> Option<(SocketAddrV4, Vec<u8>)> {
            let _ = t;
            let txid = seen3.lock().unwrap().pop()?;
            // 假 B 立即回，但 XOR-MAPPED 是 base_a ≠ expected_self
            Some((
                base_b,
                StunMessage {
                    msg_type: BINDING_RESPONSE,
                    txid,
                    attrs: vec![StunAttr::XorMapped(base_a)],
                }
                .encode(),
            ))
        };
        let err = punch_with(
            send,
            recv,
            base_a,
            &[Candidate::host(base_b)],
            expected_self,
            &PunchConfig { rto: Duration::from_millis(5), retries: 0, window: Duration::from_millis(150) },
            "meshlink-poc",
            &[],
        )
        .unwrap_err();
        assert!(matches!(err, IceError::PunchTimeout { .. }), "错误映射必须被拒绝");
    }

    /// NAT mapping 探测（注入式）：两个 server 同映射 → EIM；不同 → AddressDependent。
    #[test]
    fn nat_mapping_probe_via_injected_io() {
        let s1 = v4([8, 8, 8, 8], 3478);
        let s2 = v4([1, 1, 1, 1], 3478);
        let same = v4([203, 0, 113, 9], 61000);

        let run = |x1: SocketAddrV4, x2: SocketAddrV4| -> NatMapping {
            // pending: (txid, 所属 server)——send 时按发送次数决定 server（每次交换恰好 1 发，retries=0）
            let pending: Arc<Mutex<Vec<([u8; 12], SocketAddrV4)>>> = Arc::new(Mutex::new(Vec::new()));
            let sends = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let p2 = pending.clone();
            let s3 = sends.clone();
            let send = move |buf: &[u8], _to: SocketAddrV4| {
                let msg = StunMessage::decode(buf).unwrap();
                let n = s3.fetch_add(1, Ordering::SeqCst);
                let server = if n == 0 { s1 } else { s2 };
                p2.lock().unwrap().push((msg.txid, server));
                Ok(buf.len())
            };
            let script = Arc::new(Mutex::new(vec![x1, x2]));
            let p3 = pending.clone();
            let script2 = script.clone();
            let recv = move |t: Duration| -> Option<(SocketAddrV4, Vec<u8>)> {
                let _ = t;
                let (txid, server) = p3.lock().unwrap().pop()?;
                let x = script2.lock().unwrap().pop()?;
                Some((
                    server,
                    StunMessage { msg_type: BINDING_RESPONSE, txid, attrs: vec![StunAttr::XorMapped(x)] }
                        .encode(),
                ))
            };
            probe_nat_mapping_with([s1, s2], send, recv, Duration::from_millis(5), 0).classification
        };

        assert_eq!(run(same, same), NatMapping::EndpointIndependent);
        let other = v4([203, 0, 113, 200], 55555);
        assert_eq!(run(same, other), NatMapping::AddressDependent);
    }

    /// Keepalive：正常路径 RTT 记录；对端沉默时 miss 计数触发 on_down。
    #[test]
    fn keepalive_tracks_rtt_and_misses() {
        let peer = v4([10, 0, 0, 9], 60000);
        let seen: Arc<Mutex<Vec<[u8; 12]>>> = Arc::new(Mutex::new(Vec::new()));
        let down_hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let seen2 = seen.clone();
        let send = move |buf: &[u8], _to: SocketAddrV4| {
            if let Ok(m) = StunMessage::decode(buf) {
                if m.msg_type == BINDING_REQUEST {
                    seen2.lock().unwrap().push(m.txid);
                }
            }
            Ok(buf.len())
        };
        // 前 2 个请求回响应（got），之后沉默（miss）
        let answered = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let a2 = answered.clone();
        let seen3 = seen.clone();
        let recv = move |t: Duration| -> Option<(SocketAddrV4, Vec<u8>)> {
            let _ = t;
            let n = a2.fetch_add(1, Ordering::SeqCst);
            // 取最后一次请求的 txid（send 刚推入）——保证 keepalive txid 匹配
            let txid = seen3.lock().unwrap().pop()?;
            if n < 2 {
                Some((
                    peer,
                    StunMessage { msg_type: BINDING_RESPONSE, txid, attrs: vec![] }.encode(),
                ))
            } else {
                None
            }
        };

        let hits = down_hits.clone();
        let (ka, rtt) = Keepalive::start(
            send,
            recv,
            peer,
            Duration::from_millis(30),
            2,
            move |_misses| { hits.fetch_add(1, Ordering::SeqCst); },
        );
        std::thread::sleep(Duration::from_millis(250));
        drop(ka); // 触发 stop + join
        assert!(rtt.lock().unwrap().is_some(), "正常路径必须记录 RTT");
        assert!(down_hits.load(Ordering::SeqCst) >= 1, "持续 miss 必须触发 on_down");
    }
}
