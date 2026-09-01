//! Track A：rtc-ice 0.20.x（webrtc-rs 拆分后的 ICE crate）Sans-I/O Agent 封装
//! （M0-4 双轨对比的 A 轨）。
//!
//! 边界硬性规则（transport-api lib.rs / ADR DIRECTLINK_ICE.md §webrtc 边界）：
//! **rtc-ice / rtc-shared / sansio crate 的符号只允许出现在本模块所在的
//! directlink crate 内**——对外只暴露本 crate 的 [`Candidate`] / 元组凭据 /
//! 地址结果，由 `tests/gate_webrtc_boundary.rs` 用 cargo tree 门禁强制。
//!
//! 关键差异（相对 webrtc-rs 旧版 async API）：
//! rtc-ice 0.20 是 **sans-io** 实现——`Agent` 不持有 socket、不驱动时钟，
//! 调用方负责把 I/O 与时间喂给协议核心（`handle_read` / `handle_timeout`），
//! 并排空输出（`poll_write` / `poll_event`）。本封装提供最小 I/O 驱动：
//! 自有 UDP socket + 阻塞驱动循环，与 Track B 的「一个 socket、同端口打洞」
//! 同等条件（对比才有意义）。
//!
//! PoC 限制（ADR DIRECTLINK_ICE.md §Track A）：
//! - 单 host candidate 注册进 Agent（一个 socket ↔ 一个 candidate ↔ 一个 local
//!   addr，这是 sans-io 帧分派的硬约束，见 `find_local_candidate` 精确匹配）；
//!   对端发往本端 srflx 的检查经 rtc-ice 的 peer-reflexive 路径处理（同一 socket，
//!   语义等价）；
//! - srflx gathering 与业务**同一 socket**（Final Gate 硬要求：STUN 查询/punch/
//!   data/keepalive 全走 `[self.socket]`），结果记入 offer，不注册为 Agent 本地候选；
//! - candidate 交换 out-of-band（无 signaling server）。

use super::candidate::{Candidate as MeshCandidate, CandidateKind};
use super::stun::{new_txid, StunMessage, BINDING_RESPONSE};
use bytes::BytesMut;
use rtc_ice::candidate::{candidate_host::CandidateHostConfig, CandidateConfig, CandidateType};
use rtc_ice::mdns::MulticastDnsMode;
use rtc_ice::network_type::NetworkType;
use rtc_ice::state::ConnectionState;
use rtc_ice::{Agent, AgentConfig};
use rtc_shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use sansio::Protocol as _;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// rtc-ice ICE Agent 的轻封装（不暴露任何 rtc-ice 类型）。
pub struct WebRtcIceAgent {
    agent: Arc<Mutex<Agent>>,
    socket: Arc<UdpSocket>,
    /// host candidate 地址（TransportContext.local_addr 必须精确匹配它）
    local_base: SocketAddrV4,
    /// srflx 公网映射（gather_srflx 填充；与业务同一 socket 的观测结果）
    srflx: Mutex<Option<SocketAddrV4>>,
    /// M0-4 §八：selected pair 证据 (local_type, local_addr, remote_type, remote_addr)
    /// （SelectedCandidatePairChange 事件捕获；connect 成功后可查）
    selected_pair: Mutex<Option<(String, String, String, String)>>,
    /// 驱动循环发包/收包计数（双轨对比指标）
    tx: AtomicU64,
    rx: AtomicU64,
}

impl WebRtcIceAgent {
    /// 创建 IPv4/UDP-only 的 ICE Agent（与 Track B 同等条件：固定端口、
    /// 单 socket、host-only candidate）。
    ///
    /// `host_ip`：对外通告的本机地址（同机 loopback PoC 传 127.0.0.1，
    /// 双机实测传主出口 IP）。socket 绑定 0.0.0.0:port 以复用打洞端口。
    pub fn new(port: u16, host_ip: Ipv4Addr) -> Result<Self, String> {
        let socket = UdpSocket::bind(("0.0.0.0", port)).map_err(|e| format!("bind: {e}"))?;
        socket.set_read_timeout(Some(Duration::from_millis(50))).map_err(|e| format!("read_timeout: {e}"))?;
        let local_base = SocketAddrV4::new(host_ip, socket.local_addr().map_err(|e| e.to_string())?.port());

        let config = Arc::new(AgentConfig {
            network_types: vec![NetworkType::Udp4],
            candidate_types: vec![CandidateType::Host],
            multicast_dns_mode: MulticastDnsMode::Disabled,
            ..Default::default()
        });
        let mut agent = Agent::new(config).map_err(|e| e.to_string())?;
        let cand = host_candidate(local_base)?;
        agent.add_local_candidate(cand).map_err(|e| e.to_string())?;
        let socket = Arc::new(socket);
        Ok(Self {
            agent: Arc::new(Mutex::new(agent)),
            socket,
            local_base,
            srflx: Mutex::new(None),
            selected_pair: Mutex::new(None),
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
        })
    }

    /// 本端 host candidate 基址（127.0.0.1 或主出口 IP:实际绑定端口）。
    pub fn local_base(&self) -> SocketAddrV4 {
        self.local_base
    }

    /// srflx gathering：**同一 socket** 发 STUN Binding 到 server（Final Gate 硬
    /// 要求——换 socket 会拿到不同 NAT 映射，srflx 通告失效）。
    ///
    /// RFC 5389 §7.2.1 重传（500ms × 3）；仅接受来源 == server 且 txid 匹配的
    /// 响应。成功后可用 [`Self::srflx_addr`] 读取，供 offer/Code 通告。
    pub fn gather_srflx(&self, server: SocketAddrV4) -> Result<SocketAddrV4, String> {
        // 断言：gathering 与 check/data 必须同 socket（若未来拆 socket 这里即失败）
        debug_assert_eq!(self.socket.local_addr().ok().and_then(as_v4).map(|a| a.port()), Some(self.local_base.port()));
        let txid = new_txid();
        let req = StunMessage::binding_request(txid).encode();
        let started = Instant::now();
        let mut wait = Duration::from_millis(500);
        let mut buf = [0u8; 2048];
        for _ in 0..3 {
            self.socket.send_to(&req, SocketAddr::V4(server)).map_err(|e| format!("srflx send: {e}"))?;
            let deadline = Instant::now() + wait;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                self.socket.set_read_timeout(Some(deadline - now)).map_err(|e| e.to_string())?;
                let (n, from) = match self.socket.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(_) => continue, // timeout → 回到 deadline 检查
                };
                let SocketAddr::V4(from) = from else { continue };
                if from != server {
                    continue; // 非 STUN server 来源
                }
                let Ok(msg) = StunMessage::decode(&buf[..n]) else { continue };
                if msg.txid != txid {
                    continue; // 非本事务
                }
                if msg.msg_type != BINDING_RESPONSE {
                    continue;
                }
                let mapped = msg
                    .get_xor_mapped()
                    .ok_or_else(|| "srflx 响应缺 XOR-MAPPED-ADDRESS".to_string())?;
                *self.srflx.lock().unwrap() = Some(mapped);
                return Ok(mapped);
            }
            wait *= 2;
        }
        Err(format!("srflx gathering 超时（server {server}，{:.1}s）", started.elapsed().as_secs_f64()))
    }

    /// 最近一次 [`Self::gather_srflx`] 得到的公网映射（未 gathering = None）。
    pub fn srflx_addr(&self) -> Option<SocketAddrV4> {
        *self.srflx.lock().unwrap()
    }

    /// 驱动循环累计的 (tx, rx) 包数（双轨对比指标）。
    pub fn stats(&self) -> (u64, u64) {
        (self.tx.load(Ordering::Relaxed), self.rx.load(Ordering::Relaxed))
    }

    /// ICE 选定路径上的裸数据发送（连通后数据面；与 Track B smoke 同语义）。
    pub fn raw_send(&self, buf: &[u8], to: SocketAddrV4) -> std::io::Result<usize> {
        self.socket.send_to(buf, SocketAddr::V4(to))
    }

    /// ICE 选定路径上的裸数据接收（非 STUN 流量由调用方过滤）。
    pub fn raw_recv(&self, timeout: Duration) -> Option<(SocketAddrV4, Vec<u8>)> {
        if timeout.is_zero() {
            return None;
        }
        self.socket.set_read_timeout(Some(timeout)).ok()?;
        let mut buf = [0u8; 2048];
        match self.socket.recv_from(&mut buf) {
            Ok((n, SocketAddr::V4(from))) => Some((from, buf[..n].to_vec())),
            _ => None,
        }
    }

    /// 本端 ICE 凭据（ufrag/pwd），用于 out-of-band 交换（PoC 无 signaling server）。
    pub fn credentials(&self) -> (String, String) {
        let agent = self.agent.lock().unwrap();
        let c = agent.get_local_credentials();
        (c.ufrag.clone(), c.pwd.clone())
    }

    /// 本端 candidate 列表（转换为本 crate 的 Candidate 类型）。
    pub fn local_candidates(&self) -> Vec<MeshCandidate> {
        let agent = self.agent.lock().unwrap();
        agent
            .get_local_candidates()
            .iter()
            .filter_map(|c| {
                let addr = as_v4(c.addr())?;
                let base = as_v4(c.base_addr()).unwrap_or(addr);
                let kind = match c.candidate_type() {
                    CandidateType::Host => CandidateKind::Host,
                    CandidateType::ServerReflexive => CandidateKind::ServerReflexive,
                    _ => CandidateKind::PeerReflexive,
                };
                // M0-4R.1 §六：host candidate 按真实接口补元数据（srflx/prflx 无本地接口语义）
                let info = if kind == CandidateKind::Host {
                    super::ifinfo::find_by_ipv4(*addr.ip())
                } else {
                    None
                };
                Some(MeshCandidate {
                    kind,
                    addr,
                    base,
                    if_index: info.as_ref().map(|i| i.index).unwrap_or(0),
                    if_name: info.as_ref().map(|i| i.descr.clone()).unwrap_or_default(),
                    iface_kind: info
                        .as_ref()
                        .map(|i| i.kind.as_str().to_string())
                        .unwrap_or_default(),
                    is_virtual: info.as_ref().map(|i| i.kind.is_virtual()).unwrap_or(false),
                })
            })
            .collect()
    }

    /// 主动侧连通性检查（阻塞到 Connected）。对应 Track B 的 punch。
    pub fn dial(
        &self,
        remote_ufrag: String,
        remote_pwd: String,
        remote_cands: &[SocketAddrV4],
        timeout: Duration,
    ) -> Result<SocketAddrV4, String> {
        self.run_checks(true, remote_ufrag, remote_pwd, remote_cands, timeout)
    }

    /// 被动侧连通性检查（阻塞到 Connected）。
    pub fn accept(
        &self,
        remote_ufrag: String,
        remote_pwd: String,
        remote_cands: &[SocketAddrV4],
        timeout: Duration,
    ) -> Result<SocketAddrV4, String> {
        self.run_checks(false, remote_ufrag, remote_pwd, remote_cands, timeout)
    }

    fn run_checks(
        &self,
        controlling: bool,
        remote_ufrag: String,
        remote_pwd: String,
        remote_cands: &[SocketAddrV4],
        timeout: Duration,
    ) -> Result<SocketAddrV4, String> {
        {
            let mut agent = self.agent.lock().unwrap();
            for &c in remote_cands {
                let cand = host_candidate(c)?;
                agent.add_remote_candidate(cand).map_err(|e| e.to_string())?;
            }
            agent
                .start_connectivity_checks(controlling, remote_ufrag, remote_pwd)
                .map_err(|e| e.to_string())?;
        }
        let deadline = Instant::now() + timeout;
        loop {
            {
                let agent = self.agent.lock().unwrap();
                match agent.state() {
                    ConnectionState::Connected | ConnectionState::Completed => {
                        return selected_remote(&agent).ok_or_else(|| "ICE 已连接但无可用 pair".into());
                    }
                    ConnectionState::Failed => return Err("ICE connectivity check 失败".into()),
                    ConnectionState::Closed => return Err("ICE agent 已关闭".into()),
                    _ => {}
                }
            }
            if Instant::now() >= deadline {
                return Err("ICE connectivity check 超时".into());
            }
            self.drive_step(deadline)?;
        }
    }

    /// 单步驱动：时间泵 → 排空输出 → 收包投递 → 排空事件。
    fn drive_step(&self, deadline: Instant) -> Result<(), String> {
        {
            let mut agent = self.agent.lock().unwrap();
            agent.handle_timeout(Instant::now()).map_err(|e| e.to_string())?;
            while let Some(out) = agent.poll_write() {
                if self.socket.send_to(&out.message, out.transport.peer_addr).is_ok() {
                    self.tx.fetch_add(1, Ordering::Relaxed);
                }
            }
            while let Some(ev) = agent.poll_event() {
                // M0-4 §八：捕获 selected pair 两侧候选类型（prflx/srflx/host 证据）
                if let rtc_ice::agent::Event::SelectedCandidatePairChange(local, remote) = ev {
                    *self.selected_pair.lock().unwrap() = Some((
                        format!("{:?}", local.candidate_type()),
                        local.addr().to_string(),
                        format!("{:?}", remote.candidate_type()),
                        remote.addr().to_string(),
                    ));
                }
            }
        } // 释放 agent 锁后再阻塞 recv

        let wait = deadline.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            return Ok(());
        }
        let wait = wait.min(Duration::from_millis(100)); // 保证 handle_timeout 泵频
        self.socket.set_read_timeout(Some(wait)).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 2048];
        match self.socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                self.rx.fetch_add(1, Ordering::Relaxed);
                let mut agent = self.agent.lock().unwrap();
                agent
                    .handle_read(TaggedBytesMut {
                        now: Instant::now(),
                        transport: TransportContext {
                            local_addr: SocketAddr::V4(self.local_base),
                            peer_addr: from,
                            transport_protocol: TransportProtocol::UDP,
                            ecn: None,
                        },
                        message: BytesMut::from(&buf[..n]),
                    })
                    .map_err(|e| e.to_string())?;
                // 立即排空响应（连通性检查延迟敏感性）
                while let Some(out) = agent.poll_write() {
                    if self.socket.send_to(&out.message, out.transport.peer_addr).is_ok() {
                        self.tx.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(format!("recv: {e}")),
        }
        Ok(())
    }

    /// M0-4 §八：selected pair 证据输出。
    /// 返回 (origin, prflx 候选地址列表)。origin 规则：任一侧 prflx → "prflx"；
    /// 否则任一侧 srflx → "srflx"；否则 "host"。Track A 无事件时 origin 为 None。
    pub fn selected_pair_evidence(&self) -> (Option<String>, Vec<String>) {
        let sp = self.selected_pair.lock().unwrap().clone();
        let Some((lt, la, rt, ra)) = sp else { return (None, vec![]) };
        let mut prflx = Vec::new();
        if lt.contains("PeerReflexive") {
            prflx.push(la.clone());
        }
        if rt.contains("PeerReflexive") {
            prflx.push(ra.clone());
        }
        let origin = if !prflx.is_empty() {
            "prflx"
        } else if lt.contains("ServerReflexive") || rt.contains("ServerReflexive") {
            "srflx"
        } else {
            "host"
        };
        (Some(origin.into()), prflx)
    }
}

/// 选定 pair 的对端地址（优先 nominated，退而求其次 best available）。
fn selected_remote(agent: &Agent) -> Option<SocketAddrV4> {
    let (local, remote) = agent.get_selected_candidate_pair().or_else(|| agent.get_best_available_candidate_pair())?;
    let _ = local;
    as_v4(remote.addr())
}

fn as_v4(a: SocketAddr) -> Option<SocketAddrV4> {
    match a {
        SocketAddr::V4(v4) => Some(v4),
        _ => None,
    }
}

/// 构造 rtc-ice host candidate（UDP/IPv4/component 1，优先级由 crate 计算）。
fn host_candidate(addr: SocketAddrV4) -> Result<rtc_ice::candidate::Candidate, String> {
    CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".into(),
            address: addr.ip().to_string(),
            port: addr.port(),
            component: 1,
            ..Default::default()
        },
        tcp_type: Default::default(),
    }
    .new_candidate_host()
    .map_err(|e| format!("host candidate({addr}): {e}"))
}

/// 将 `IpAddr::V4` 解出（PoC 只对比 IPv4）。
#[allow(dead_code)]
fn v4_of(ip: IpAddr) -> Option<Ipv4Addr> {
    match ip {
        IpAddr::V4(v4) => Some(v4),
        _ => None,
    }
}
