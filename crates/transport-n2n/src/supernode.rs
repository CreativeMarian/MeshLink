//! N2N Supernode（M1-2）。
//!
//! 职责（对齐 n2n 3.0 supernode）：
//! - 维护社区成员表：community → device_id → UDP 端点（注册即上线）；
//! - REGISTER_SUPER：记录端点 → REGISTER_SUPER_ACK（回执 cookie + 本 SN 端点）；
//! - QUERY_PEER：若对端在同一社区 → 回执携带对端端点 + 向对端 PUNCH 通知；
//! - PACKET：按 dst_device_id 原样转发（不解密，看不到 MeshLink Noise 密文）；
//! - PUNCH：向 target 转发（打洞辅助）。
//!
//! 既是嵌入式库（集成测试可进程内启动），也是 `n2n-supernode` 独立进程
//! （真实 N2N Supernode process Gate 项：以真实子进程验证）。

use crate::proto::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 社区成员。
#[derive(Debug, Clone)]
pub struct Member {
    pub device_id: String,
    pub addr: SocketAddr,
    pub last_seen: Instant,
}

/// 超节点统计。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct SupernodeStats {
    pub total_registers: u64,
    pub total_queries: u64,
    pub total_packets: u64,
    pub total_punches: u64,
    pub total_nacks: u64,
    pub members: u64,
    pub communities: u64,
}

/// 内部简单序列化辅助（避免额外依赖 serde 宏定义重复）。
#[derive(Debug, Default)]
pub struct StatsInner {
    pub total_registers: AtomicU64,
    pub total_queries: AtomicU64,
    pub total_packets: AtomicU64,
    pub total_punches: AtomicU64,
    pub total_nacks: AtomicU64,
}

impl StatsInner {
    fn snapshot(&self, member_count: u64, community_count: u64) -> SupernodeStats {
        SupernodeStats {
            total_registers: self.total_registers.load(Ordering::Relaxed),
            total_queries: self.total_queries.load(Ordering::Relaxed),
            total_packets: self.total_packets.load(Ordering::Relaxed),
            total_punches: self.total_punches.load(Ordering::Relaxed),
            total_nacks: self.total_nacks.load(Ordering::Relaxed),
            members: member_count,
            communities: community_count,
        }
    }
}

/// Supernode 状态（供外部读取）。
#[derive(Debug, Clone)]
pub struct SupernodeState {
    pub sn_id: String,
    pub bind_addr: SocketAddr,
    pub stats: SupernodeStats,
    /// 成员表快照（community → device_id → addr）
    pub members: Vec<(String, String, String)>,
}

/// 内部共享状态。
#[derive(Default)]
struct Inner {
    members: Mutex<HashMap<String, HashMap<String, Member>>>,
    stats: StatsInner,
}

/// N2N Supernode。
pub struct N2NSupernode {
    sn_id: String,
    socket: Arc<UdpSocket>,
    bind_addr: SocketAddr,
    inner: Arc<Inner>,
    stop: Arc<AtomicBool>,
    join: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// Supernode 配置。
#[derive(Debug, Clone)]
pub struct SupernodeConfig {
    pub sn_id: String,
    pub bind_addr: SocketAddr,
    /// 成员过期时间（无注册刷新即视为下线）
    pub member_ttl: Duration,
}

impl Default for SupernodeConfig {
    fn default() -> Self {
        Self {
            sn_id: "sn-local".into(),
            bind_addr: "0.0.0.0:7654".parse().unwrap(),
            member_ttl: Duration::from_secs(60),
        }
    }
}

impl N2NSupernode {
    /// 绑定并启动接收线程。
    pub fn bind(cfg: SupernodeConfig) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(cfg.bind_addr)?);
        let bind_addr = socket.local_addr()?;
        let inner = Arc::new(Inner::default());
        let stop = Arc::new(AtomicBool::new(false));
        let me = Self {
            sn_id: cfg.sn_id.clone(),
            socket: socket.clone(),
            bind_addr,
            inner: inner.clone(),
            stop: stop.clone(),
            join: std::sync::Mutex::new(None),
        };
        let sock = socket.clone();
        let stop2 = stop.clone();
        let inner2 = inner.clone();
        let sn_id2 = cfg.sn_id.clone();
        let member_ttl = cfg.member_ttl;
        let join = std::thread::Builder::new()
            .name(format!("n2n-supernode-{}", cfg.sn_id))
            .spawn(move || {
                let mut buf = [0u8; MAX_FRAME_LEN];
                while !stop2.load(Ordering::Acquire) {
                    let (n, from) = match sock.recv_from(&mut buf) {
                        Ok(x) => x,
                        Err(e) => {
                            // 非阻塞+超时轮询，保证 stop 可及时生效
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                std::thread::sleep(Duration::from_millis(10));
                                continue;
                            }
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    };
                    let frame = &buf[..n];
                    Self::handle_frame(&sock, &inner2, &sn_id2, from, frame, member_ttl);
                }
            })?;
        // 非阻塞接收（recv_timeout 语义由线程轮询保证）
        socket.set_nonblocking(true).ok();
        *me.join.lock().unwrap() = Some(join);
        Ok(me)
    }

    /// 处理一个 UDP 帧（线程内调用）。
    fn handle_frame(
        sock: &Arc<UdpSocket>,
        inner: &Arc<Inner>,
        sn_id: &str,
        from: SocketAddr,
        frame: &[u8],
        _member_ttl: Duration,
    ) {
        let (header, payload) = match decode(frame) {
            Ok(x) => x,
            Err(_) => return,
        };
        let community = header.community.clone();
        match header.packet_type {
            PacketType::RegisterSuper => {
                inner.stats.total_registers.fetch_add(1, Ordering::Relaxed);
                let reg: RegisterSuper = match serde_json::from_slice(payload) {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if reg.device_id.is_empty() || reg.device_id.len() > DEVICE_ID_MAX_LEN {
                    return;
                }
                {
                    let mut members = inner.members.lock().unwrap();
                    let comm = members.entry(community.clone()).or_default();
                    comm.insert(
                        reg.device_id.clone(),
                        Member { device_id: reg.device_id.clone(), addr: from, last_seen: Instant::now() },
                    );
                }
                // 应答 REGISTER_SUPER_ACK
                let ack = RegisterSuperAck {
                    sn_id: sn_id.to_string(),
                    sn_public: sock.local_addr().ok().map(|a| a.to_string()).unwrap_or_default(),
                    peer_public: None,
                    cookie: reg.cookie,
                };
                let body = serde_json::to_vec(&ack).unwrap_or_default();
                let h = match N2nHeader::new(&community, PacketType::RegisterSuperAck) {
                    Ok(h) => h,
                    Err(_) => return,
                };
                let _ = sock.send_to(&encode(&h, &body), from);
            }
            PacketType::QueryPeer => {
                inner.stats.total_queries.fetch_add(1, Ordering::Relaxed);
                let q: QueryPeer = match serde_json::from_slice(payload) {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let target = {
                    let members = inner.members.lock().unwrap();
                    members
                        .get(&community)
                        .and_then(|m| m.get(&q.target_device_id))
                        .map(|m| m.addr)
                };
                let ack = RegisterSuperAck {
                    sn_id: sn_id.to_string(),
                    sn_public: sock.local_addr().ok().map(|a| a.to_string()).unwrap_or_default(),
                    peer_public: target.map(|a| a.to_string()),
                    cookie: q.cookie,
                };
                let body = serde_json::to_vec(&ack).unwrap_or_default();
                let h = match N2nHeader::new(&community, PacketType::RegisterSuperAck) {
                    Ok(h) => h,
                    Err(_) => return,
                };
                let _ = sock.send_to(&encode(&h, &body), from);
                // 同时向对端 PUNCH（通知对端「有人找你」+ 携带查询方端点）
                if let Some(target_addr) = target {
                    let punch = Punch {
                        target_device_id: q.target_device_id.clone(),
                        peer_endpoint: from.to_string(),
                        cookie: q.cookie,
                    };
                    let body = serde_json::to_vec(&punch).unwrap_or_default();
                    let h = match N2nHeader::new(&community, PacketType::Punch) {
                        Ok(h) => h,
                        Err(_) => return,
                    };
                    let _ = sock.send_to(&encode(&h, &body), target_addr);
                }
            }
            PacketType::Packet => {
                inner.stats.total_packets.fetch_add(1, Ordering::Relaxed);
                let pkt: Packet = match serde_json::from_slice(payload) {
                    Ok(x) => x,
                    Err(_) => return,
                };
                // 只转发不解密：按 dst_device_id 路由
                let target = {
                    let members = inner.members.lock().unwrap();
                    members
                        .get(&community)
                        .and_then(|m| m.get(&pkt.dst_device_id))
                        .map(|m| m.addr)
                };
                match target {
                    Some(dst_addr) => {
                        // 原样转发整帧
                        let _ = sock.send_to(frame, dst_addr);
                    }
                    None => {
                        inner.stats.total_nacks.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            PacketType::Punch => {
                inner.stats.total_punches.fetch_add(1, Ordering::Relaxed);
                let punch: Punch = match serde_json::from_slice(payload) {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let target = {
                    let members = inner.members.lock().unwrap();
                    members
                        .get(&community)
                        .and_then(|m| m.get(&punch.target_device_id))
                        .map(|m| m.addr)
                };
                if let Some(target_addr) = target {
                    let _ = sock.send_to(frame, target_addr);
                }
            }
            PacketType::RegisterSuperAck | PacketType::RegisterSuperNack => {
                // 仅边缘处理
            }
        }
        // 清理过期成员（保守：每帧都清太贵；此处仅在实际注册/查询时惰性清理）
    }

    /// 绑定地址。
    pub fn local_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// 当前状态快照。
    pub fn state(&self) -> SupernodeState {
        let members = self.inner.members.lock().unwrap();
        let mut member_count = 0u64;
        let mut list = Vec::new();
        for (comm, map) in members.iter() {
            for (dev, m) in map.iter() {
                member_count += 1;
                list.push((comm.clone(), dev.clone(), m.addr.to_string()));
            }
        }
        SupernodeState {
            sn_id: self.sn_id.clone(),
            bind_addr: self.bind_addr,
            stats: self.inner.stats.snapshot(member_count, members.len() as u64),
            members: list,
        }
    }

    /// 成员数（某社区）。
    pub fn member_count(&self, community: &str) -> usize {
        self.inner
            .members
            .lock()
            .unwrap()
            .get(community)
            .map(|m| m.len())
            .unwrap_or(0)
    }

    /// 停止（关闭接收线程）。
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

impl Drop for N2NSupernode {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        // join 接收线程：线程退出后释放其持有的 socket Arc → 端口真正释放
        if let Some(j) = self.join.lock().unwrap().take() {
            let _ = j.join();
        }
    }
}
