//! MeshVnic 对外门面（M0-3 要求四/六/八/十/十八/十九/二十）。
//!
//! 上层（mesh-agent / overlay-router / directlink / transport-n2n）只看得到本模块的
//! `MeshVnic` 与 `PacketBuffer`，Wintun API 不外泄（要求四）。
//!
//! 所有权与释放顺序（要求六）——由 `shutdown_inner` 显式控制（take 置 None）：
//! ```text
//! workers JoinHandle（先 join）
//!   ↓
//! ShutdownEvent（CloseHandle）
//!   ↓
//! WintunSession Drop = WintunEndSession
//!   ↓
//! WintunAdapter Drop = WintunCloseAdapter
//!   ↓
//! WintunLibrary Drop = FreeLibrary（最后）
//! ```
//! 超时异常路径：受控泄漏 session/adapter/library，绝不 use-after-free。
//!
//! 线程安全（要求十九）：
//! - `send()`：&self，经有界 sync_channel 交 TX worker（Sender 实现 Sync）
//! - `recv_timeout()`：&self，单消费者语义（内部 Mutex 保护）
//! - `stop()`：&mut self，控制权归 MeshAgentService 独占
//! - 发送与接收路径完全独立，无全局锁。

use crate::adapter::{AdapterLock, WintunAdapter};
use crate::api::{
    win, Guid, Handle, NetLuid, WintunLibrary, INVALID_HANDLE_VALUE, INFINITE, WAIT_FAILED,
    WAIT_OBJECT_0,
};
use crate::error::VnicError;
use crate::packet::{
    classify, icmp_checksum, validate_ipv4, PacketBuffer, PacketDisposition, PacketRejectReason,
};
use crate::session::WintunSession;
use config_manager::VnicParams;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 最大发送包长（Wintun 单包上限；DWORD 长度上限约束）。
const MAX_TX_PACKET: usize = 0xFFFF;

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 启动前已校验的 VNIC 配置（来自 ConfigManager，见 `VnicConfig::from_params`）。
#[derive(Debug, Clone)]
pub struct VnicConfig {
    pub adapter_name: String,
    pub tunnel_type: String,
    pub ring_capacity: u32,
    pub virtual_ip: Ipv4Addr,
    /// 配置到本机地址的 on-link prefix
    pub prefix_len: u8,
    /// Overlay 测试网段（冲突检测；禁止 0.0.0.0/0）
    pub overlay_net: Ipv4Addr,
    pub overlay_prefix: u8,
    pub tx_queue_len: usize,
    pub shutdown_timeout: Duration,
    /// M0 GUID 模式 A（None）/ B（持久化），见 ADR/WINTUN_ADAPTER_IDENTITY.md
    pub requested_guid: Option<Guid>,
}

impl VnicConfig {
    /// 从统一配置解析并严格校验（非法值拒绝启动，不静默修正——要求七）。
    pub fn from_params(p: &VnicParams) -> Result<Self, VnicError> {
        WintunLibrary::validate_ring_capacity(p.ring_capacity)?;
        let virtual_ip: Ipv4Addr = p.virtual_ip.parse().map_err(|_| {
            VnicError::ConfigInvalid { field: "vnic.virtual_ip", reason: "非法 IPv4".into() }
        })?;
        let (net, mask) = p.overlay_cidr.split_once('/').ok_or(VnicError::ConfigInvalid {
            field: "vnic.overlay_cidr",
            reason: "必须是 a.b.c.d/mask".into(),
        })?;
        let overlay_net: Ipv4Addr = net.parse().map_err(|_| {
            VnicError::ConfigInvalid { field: "vnic.overlay_cidr", reason: "非法 IPv4".into() }
        })?;
        let overlay_prefix: u8 = mask.parse().map_err(|_| {
            VnicError::ConfigInvalid { field: "vnic.overlay_cidr", reason: "非法 mask".into() }
        })?;
        if overlay_prefix > 32 || p.prefix_length > 32 {
            return Err(VnicError::ConfigInvalid { field: "vnic prefix", reason: "mask > 32".into() });
        }
        if p.tx_queue_len == 0 {
            return Err(VnicError::ConfigInvalid { field: "vnic.tx_queue_len", reason: "必须 > 0".into() });
        }
        // 一致性：virtual_ip 必须落在 overlay 网段内
        let m = prefix_mask(overlay_prefix);
        if (u32::from(virtual_ip) & m) != (u32::from(overlay_net) & m) {
            return Err(VnicError::ConfigInvalid {
                field: "vnic.virtual_ip",
                reason: format!("不在 overlay 网段 {overlay_net}/{overlay_prefix} 内"),
            });
        }
        // 硬性禁止默认路由网段（M0 是 Overlay LAN 不是全局 VPN——要求十四）
        if overlay_prefix == 0 {
            return Err(VnicError::ConfigInvalid {
                field: "vnic.overlay_cidr",
                reason: "禁止 0.0.0.0/0（M0 不做全局 VPN）".into(),
            });
        }
        let requested_guid = match &p.requested_guid {
            None => None,
            Some(s) => Some(Guid::parse(s).ok_or(VnicError::ConfigInvalid {
                field: "vnic.requested_guid",
                reason: "非法 GUID 格式".into(),
            })?),
        };
        Ok(Self {
            adapter_name: p.adapter_name.clone(),
            tunnel_type: p.tunnel_type.clone(),
            ring_capacity: p.ring_capacity,
            virtual_ip,
            prefix_len: p.prefix_length,
            overlay_net,
            overlay_prefix,
            tx_queue_len: p.tx_queue_len as usize,
            shutdown_timeout: Duration::from_secs(p.shutdown_timeout_secs),
            requested_guid,
        })
    }
}

fn prefix_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix as u32) }
}

/// 规格八策略校验：peer 是否落在本 VNIC 的 overlay 网段内。
/// 只有 overlay 地址才允许被 /32 钉进 Wintun（用户正常互联网流量不受影响）。
fn peer_in_overlay(config: &VnicConfig, peer: Ipv4Addr) -> bool {
    let m = prefix_mask(config.overlay_prefix);
    (u32::from(peer) & m) == (u32::from(config.overlay_net) & m)
}

// ---------------------------------------------------------------------------
// 统计计数（metrics 模块未来直接接）
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub(crate) struct Counters {
    rx_packets: AtomicU64,
    rx_bytes: AtomicU64,
    // --- 按 M0-3.1-3 拆分 rx_dropped_*（原 rx_dropped_invalid 语义混合 → 废弃） ---
    rx_dropped_unsupported_ipv6: AtomicU64,
    rx_dropped_unsupported_multicast: AtomicU64,
    rx_dropped_malformed_ipv4: AtomicU64,
    rx_dropped_policy: AtomicU64,
    // --- RX backpressure / 真正错误 ---
    rx_dropped_backpressure: AtomicU64,
    rx_errors: AtomicU64,
    // --- TX ---
    tx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    tx_dropped_queue_full: AtomicU64,
    tx_dropped_ring_full: AtomicU64,
    tx_dropped_invalid: AtomicU64,
    tx_errors: AtomicU64,
}

/// 只读统计快照（M0-3.1-3：RX drop 四分类拆分，用于 Path Health/Metrics 无偏差聚合）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct VnicStats {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    /// v1 暂不支持 IPv6（合法流量，非错误）
    pub rx_dropped_unsupported_ipv6: u64,
    /// v1 暂不支持组播/广播（合法协议流量，非错误）
    pub rx_dropped_unsupported_multicast: u64,
    /// 真正格式损坏 IPv4（Path Health 计入损伤）
    pub rx_dropped_malformed_ipv4: u64,
    /// 策略丢弃（预留 ACL / 网段范围外 deny）
    pub rx_dropped_policy: u64,
    pub rx_dropped_backpressure: u64,
    pub rx_errors: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub tx_dropped_queue_full: u64,
    pub tx_dropped_ring_full: u64,
    pub tx_dropped_invalid: u64,
    pub tx_errors: u64,
}

impl VnicStats {
    /// 诊断用：返回被 RX 丢弃的总包数（用于对比"实际送到 ring 的包数"）。
    pub fn rx_dropped_total(&self) -> u64 {
        self.rx_dropped_unsupported_ipv6
            + self.rx_dropped_unsupported_multicast
            + self.rx_dropped_malformed_ipv4
            + self.rx_dropped_policy
            + self.rx_dropped_backpressure
    }
}

impl Counters {
    /// 根据 PacketDisposition 把 rx drop 分类落到对应 counter（Accept 不走本函数）。
    pub(crate) fn record_rx_drop(&self, d: &PacketDisposition) {
        use PacketDisposition::*;
        match d {
            AcceptIpv4Unicast(_) => {} // 不计数
            UnsupportedIpv6 => {
                self.rx_dropped_unsupported_ipv6.fetch_add(1, Ordering::Relaxed);
            }
            UnsupportedMulticast => {
                self.rx_dropped_unsupported_multicast.fetch_add(1, Ordering::Relaxed);
            }
            MalformedIpv4(_) => {
                self.rx_dropped_malformed_ipv4.fetch_add(1, Ordering::Relaxed);
            }
            PolicyDrop => {
                self.rx_dropped_policy.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn snapshot(&self) -> VnicStats {
        VnicStats {
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            rx_dropped_unsupported_ipv6: self.rx_dropped_unsupported_ipv6.load(Ordering::Relaxed),
            rx_dropped_unsupported_multicast: self.rx_dropped_unsupported_multicast.load(Ordering::Relaxed),
            rx_dropped_malformed_ipv4: self.rx_dropped_malformed_ipv4.load(Ordering::Relaxed),
            rx_dropped_policy: self.rx_dropped_policy.load(Ordering::Relaxed),
            rx_dropped_backpressure: self.rx_dropped_backpressure.load(Ordering::Relaxed),
            rx_errors: self.rx_errors.load(Ordering::Relaxed),
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            tx_dropped_queue_full: self.tx_dropped_queue_full.load(Ordering::Relaxed),
            tx_dropped_ring_full: self.tx_dropped_ring_full.load(Ordering::Relaxed),
            tx_dropped_invalid: self.tx_dropped_invalid.load(Ordering::Relaxed),
            tx_errors: self.tx_errors.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// ShutdownEvent RAII
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ShutdownEvent {
    handle: Handle,
}

impl ShutdownEvent {
    fn new() -> Result<Self, VnicError> {
        let h = unsafe { win::CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if h.is_null() || h == INVALID_HANDLE_VALUE {
            return Err(VnicError::ShutdownTimeout { waited_ms: 0 }); // 复用：创建失败极罕见
        }
        Ok(Self { handle: h })
    }

    fn set(&self) {
        unsafe { win::SetEvent(self.handle) };
    }
}

impl Drop for ShutdownEvent {
    fn drop(&mut self) {
        unsafe { win::CloseHandle(self.handle) };
    }
}

// SAFETY：事件为内核对象；SetEvent/等待跨线程安全，CloseHandle 仅由所有者
// Drop（worker 全部退出后）调用。MeshVnic 借此获得 Sync（&self 跨线程共享）。
unsafe impl Send for ShutdownEvent {}
unsafe impl Sync for ShutdownEvent {}

/// 可跨线程传递的事件句柄视图（仅用于 WaitForMultipleObjects 等待，绝不关闭；
/// 真正的所有权仍归 [`ShutdownEvent`]）。
#[derive(Debug, Clone, Copy)]
struct ShareableEvent(Handle);
// SAFETY：句柄只被用于等待（内核对象等待天然跨线程）；CloseHandle 仅由
// 所有者 ShutdownEvent 在 worker 全部退出后调用。
unsafe impl Send for ShareableEvent {}

impl ShareableEvent {
    /// 通过方法读取句柄：closure 捕获整个 `ShareableEvent`（Send），
    /// 而不是 edition 2021 精确捕获下的裸 `Handle` 字段（非 Send）。
    fn get(&self) -> Handle {
        self.0
    }
}

// ---------------------------------------------------------------------------
// MeshVnic
// ---------------------------------------------------------------------------

/// 生命周期阶段：RX/TX worker 句柄。
#[derive(Debug)]
struct Workers {
    rx: Option<std::thread::JoinHandle<()>>,
    tx: Option<std::thread::JoinHandle<()>>,
}

/// meshlink 虚拟网卡门面。由 MeshAgentService 独占持有（架构硬性规则）。
pub struct MeshVnic {
    /// 声明序 = Drop 逆序（见模块文档）：
    library: Option<Arc<WintunLibrary>>, // 最后 FreeLibrary
    adapter: Option<Arc<WintunAdapter>>, // 然后 CloseAdapter
    session: Option<Arc<WintunSession>>, // 然后 EndSession
    shutdown_event: Option<ShutdownEvent>,
    /// 与 RX worker 共享的退出标志（worker 内背压等待也检查它，保证可退出）
    shutdown_flag: Option<Arc<AtomicBool>>,
    rx: Mutex<mpsc::Receiver<PacketBuffer>>,
    tx: Option<mpsc::SyncSender<PacketBuffer>>,
    workers: Option<Workers>, // 最先 join
    counters: Arc<Counters>,
    config: VnicConfig,
    /// 接口 LUID（with_library 成功后填充）
    luid: Option<u64>,
    /// 本会话经 `add_peer_route` 安装的对端 Overlay IP /32 路由
    /// （stop 时统一回收——规格八：路由生命周期 = 会话生命周期）
    peer_routes: Mutex<Vec<Ipv4Addr>>,
    /// M0-3.1：Mutex 获取时是否观察到 WAIT_ABANDONED（前 Owner 崩溃 → 本进程接管）
    lock_recovered_from_abandoned: bool,
}

impl MeshVnic {
    /// 加载默认路径 DLL 并启动 VNIC（生产入口）。
    pub fn create(config: VnicConfig) -> Result<Self, VnicError> {
        let library = Arc::new(WintunLibrary::load_default()?);
        Self::with_library(library, config)
    }

    /// 显式注入 DLL 路径（测试/开发）。
    pub fn create_with_dll(dll: &std::path::Path, config: VnicConfig) -> Result<Self, VnicError> {
        let library = Arc::new(WintunLibrary::load(dll)?);
        Self::with_library(library, config)
    }

    fn with_library(library: Arc<WintunLibrary>, config: VnicConfig) -> Result<Self, VnicError> {
        // 0. M0-3.1-1 系统级单 Owner 互斥（V-04 事故前置防御）：
        //    在 **任何** WintunCreateAdapter 调用前先持锁。失败：立即返回 AdapterLockedByOtherProcess，
        //    绝不调用 Wintun DLL（防并发同名 Create → stale handle 段错误 → 内核全局损坏）。
        let adapter_lock = AdapterLock::acquire_for(&config.adapter_name)?;
        let lock_recovered_from_abandoned = adapter_lock.abandoned;

        // 1. Overlay 网段冲突检测（要求十四：检测报告，不自动避让）
        let conflicts = crate::ip_config::detect_subnet_conflicts(
            config.overlay_net,
            config.overlay_prefix,
            None,
        )?;
        if !conflicts.is_empty() {
            return Err(VnicError::OverlaySubnetConflict {
                overlay: format!("{}/{}", config.overlay_net, config.overlay_prefix),
                conflicting: conflicts,
            });
        }

        // 2. Adapter（同名复用 = crash recovery 基础）
        //    先持 lock 再 create：事故根因「并发 CreateAdapter」已被 lock 前置拦截。
        let adapter = Arc::new(WintunAdapter::create(
            adapter_lock,
            &library,
            &config.adapter_name,
            &config.tunnel_type,
            config.requested_guid.as_ref(),
        )?);
        let luid = adapter.luid()?;

        // 3. Session：必须在配 IP 之前 Start，Wintun 才会将 adapter 媒体状态
        //    置为 Connected，TCP/IP 栈才会为 set_ipv4 自动生成 on-link /{prefix} 子网路由
        //    （验收要求的 Overlay LAN on-link 路由）。
        let session = Arc::new(WintunSession::start(&adapter, config.ring_capacity)?);

        // 4. IPv4 配置（IP Helper API；重复 IP 幂等成功）
        match crate::ip_config::set_ipv4(luid, config.virtual_ip, config.prefix_len) {
            Ok(()) => {}
            Err(VnicError::IpAlreadyExists { ip }) => {
                tracing::info!(target: "vnic", "IP 已存在，幂等接受: {ip}");
            }
            Err(e) => return Err(e),
        }

        // 5. 通道 + ShutdownEvent + workers
        let (tx_send, tx_recv) = mpsc::sync_channel::<PacketBuffer>(config.tx_queue_len);
        let (rx_send, rx_recv) = mpsc::sync_channel::<PacketBuffer>(config.tx_queue_len);
        let shutdown_event = ShutdownEvent::new()?;
        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let counters = Arc::new(Counters::default());

        let rx_worker = spawn_rx_worker(
            Arc::clone(&session),
            ShareableEvent(shutdown_event.handle),
            Arc::clone(&shutdown_flag),
            rx_send,
            Arc::clone(&counters),
        );
        let tx_worker = spawn_tx_worker(Arc::clone(&session), tx_recv, Arc::clone(&counters));

        tracing::info!(
            target: "vnic",
            "MeshVnic 已启动: {} ip={}/{} ring=0x{:X} luid=0x{:X}",
            config.adapter_name, config.virtual_ip, config.prefix_len,
            config.ring_capacity, luid.0
        );

        Ok(Self {
            library: Some(library),
            adapter: Some(adapter),
            session: Some(session),
            shutdown_event: Some(shutdown_event),
            shutdown_flag: Some(Arc::clone(&shutdown_flag)),
            rx: Mutex::new(rx_recv),
            tx: Some(tx_send),
            workers: Some(Workers { rx: Some(rx_worker), tx: Some(tx_worker) }),
            counters,
            config,
            luid: Some(luid.0),
            peer_routes: Mutex::new(Vec::new()),
            lock_recovered_from_abandoned,
        })
    }

    /// M0-3.1：本次创建是否经由 `WAIT_ABANDONED` 接管（前 Owner 进程异常退出
    /// 未 ReleaseMutex，内核把 Mutex 遗弃转交给本进程）。
    /// 上层据此区分「正常启动」与「Crash Recovery」，并核对
    /// `MutexAbandonedRecovered` 结构化事件（tracing，event 字段）。
    pub fn lock_recovered_from_abandoned(&self) -> bool {
        self.lock_recovered_from_abandoned
    }

    pub fn config(&self) -> &VnicConfig {
        &self.config
    }

    pub fn is_running(&self) -> bool {
        self.session.is_some()
    }

    /// 驱动版本（证明加载的是真 Wintun DLL）。
    pub fn driver_version(&self) -> u32 {
        self.library.as_ref().map(|l| l.running_driver_version()).unwrap_or(0)
    }

    /// 本 VNIC 接口的 NET_LUID（identity 观测 / ADR WINTUN_ADAPTER_IDENTITY 用）。
    pub fn luid(&self) -> Option<u64> {
        self.luid
    }

    /// 进程当前 HANDLE 数（泄漏检查采样，要求二十三）。
    pub fn process_handle_count() -> u32 {
        win::process_handle_count()
    }

    /// 进程内存（Working Set, Private Bytes）（泄漏检查采样，要求二十三）。
    pub fn process_memory_usage() -> (u64, u64) {
        win::process_memory_usage()
    }

    /// 本机全部 IPv4 单播地址快照（诊断/验收"IP 不残留"用）。
    pub fn local_ipv4_addresses() -> Result<Vec<(Ipv4Addr, u8, u64)>, VnicError> {
        crate::ip_config::local_ipv4_addresses()
    }

    /// 本 VNIC 接口上的全部 IPv4 路由（验收 22：证明无 0.0.0.0/0 默认路由）。
    pub fn routes_via_self(&self) -> Result<Vec<(Ipv4Addr, u8)>, VnicError> {
        match self.luid {
            Some(l) => crate::ip_config::routes_via(l),
            None => Ok(Vec::new()),
        }
    }

    /// Overlay MVP 规格八（最小路由）：为对端 Overlay IP 安装 /32 主机路由。
    ///
    /// - 只装对端 IP 的 /32（绝不动默认路由 / DNS / 任何聚合前缀）；
    /// - peer 必须位于本 VNIC 的 overlay 网段内（策略校验：防止把非 overlay
    ///   目标钉进 Wintun，误伤用户正常网络）；
    /// - 幂等：重复安装同一 peer → `Ok(())`；
    /// - 路由在 `stop()`/Drop 时统一回收（生命周期 = 会话）。
    pub fn add_peer_route(&self, peer: Ipv4Addr) -> Result<(), VnicError> {
        if !peer_in_overlay(&self.config, peer) {
            return Err(VnicError::ConfigInvalid {
                field: "peer_overlay_ip",
                reason: format!(
                    "{peer} 不在 overlay 网段 {}/{} 内（规格八：仅允许对端 Overlay IP）",
                    self.config.overlay_net, self.config.overlay_prefix
                ),
            });
        }
        let luid = NetLuid(self.luid.ok_or(VnicError::ConfigInvalid {
            field: "vnic.luid",
            reason: "VNIC 未启动，无法安装路由".into(),
        })?);
        crate::ip_config::set_host_route(luid, peer)?;
        let mut routes = self.peer_routes.lock().expect("peer_routes 锁中毒");
        if !routes.contains(&peer) {
            routes.push(peer);
        }
        Ok(())
    }

    /// 删除对端 /32 路由（幂等：未安装 → `Ok(())`）。
    pub fn remove_peer_route(&self, peer: Ipv4Addr) -> Result<(), VnicError> {
        self.peer_routes.lock().expect("peer_routes 锁中毒").retain(|&p| p != peer);
        match self.luid {
            Some(l) => crate::ip_config::remove_host_route(NetLuid(l), peer),
            None => Ok(()),
        }
    }

    /// 当前已安装（且由本 VNIC 跟踪）的对端 /32 路由列表（诊断/GetDiagnostics 用）。
    pub fn installed_peer_routes(&self) -> Vec<Ipv4Addr> {
        self.peer_routes.lock().expect("peer_routes 锁中毒").clone()
    }

    /// 回收全部对端 /32 路由（shutdown 路径，best-effort：
    /// 失败只记录日志，绝不阻塞关停——路由随接口消失最终也会被系统回收）。
    fn remove_all_peer_routes(&mut self) {
        let peers: Vec<Ipv4Addr> =
            std::mem::take(&mut *self.peer_routes.lock().expect("peer_routes 锁中毒"));
        if peers.is_empty() {
            return;
        }
        if let Some(l) = self.luid {
            let luid = NetLuid(l);
            for peer in peers {
                if let Err(e) = crate::ip_config::remove_host_route(luid, peer) {
                    tracing::warn!(target: "vnic", "stop 回收对端 /32 路由失败: {peer} ({e})");
                }
            }
        }
    }

    /// 发送一个 L3 包（&self，线程安全）。
    ///
    /// Backpressure（要求十）：TX 队列满 → 立即 `SendRingFull` + drop 计数，
    /// 不阻塞调用方、不 panic、不无限扩容。非法包同样 drop + 计数。
    pub fn send(&self, packet: PacketBuffer) -> Result<(), VnicError> {
        if packet.len() > MAX_TX_PACKET {
            self.counters.tx_dropped_invalid.fetch_add(1, Ordering::Relaxed);
            return Err(VnicError::PacketInvalid { reason: PacketRejectReason::TooLong });
        }
        if let Err(reason) = validate_ipv4(&packet) {
            self.counters.tx_dropped_invalid.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(target: "vnic", "TX 非法包丢弃: {reason:?} len={}", packet.len());
            return Err(VnicError::PacketInvalid { reason });
        }
        let sender = self.tx.as_ref().ok_or(VnicError::SendOther { os: 0 })?;
        match sender.try_send(packet) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => {
                let n = self.counters.tx_dropped_queue_full.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n % 1000 == 0 {
                    tracing::warn!(target: "vnic", vnic_tx_ring_full_total = n, "TX 队列满，包已丢弃");
                }
                Err(VnicError::SendRingFull)
            }
            Err(TrySendError::Disconnected(_)) => Err(VnicError::SendOther { os: 0 }),
        }
    }

    /// 接收一个 L3 包（&self，单消费者）。`Ok(None)` = 已关闭。
    pub fn recv_timeout(&self, timeout: Duration) -> Result<Option<PacketBuffer>, VnicError> {
        let r = self.rx.lock().expect("rx 锁中毒").recv_timeout(timeout);
        match r {
            Ok(pkt) => Ok(Some(pkt)),
            Err(RecvTimeoutError::Timeout) => Ok(None),
            Err(RecvTimeoutError::Disconnected) => Ok(None),
        }
    }

    /// 只读统计快照。
    pub fn stats(&self) -> VnicStats {
        self.counters.snapshot()
    }

    /// 可取消 Shutdown（要求十八）：
    /// 停止接受新包 → 通知 shutdown event → 唤醒 RX worker → 等待 workers 退出
    /// → EndSession → CloseAdapter（DLL 由 Drop 链最后释放）。
    /// 超时产生 `ShutdownTimeout`，绝不无限卡死。
    pub fn stop(&mut self) -> Result<(), VnicError> {
        self.shutdown_inner(self.config.shutdown_timeout)
    }

    fn shutdown_inner(&mut self, timeout: Duration) -> Result<(), VnicError> {
        let started = Instant::now();
        // 0. 规格八：回收本会话安装的对端 /32 路由（先于一切资源释放；
        //    路由生命周期 = 会话生命周期，绝不遗留）
        self.remove_all_peer_routes();
        // 1. 停止接受新包：drop TX sender → TX worker 退出
        self.tx = None;
        // 2. 置退出标志 + 唤醒 RX worker（背压等待中的 worker 依赖该标志退出）
        if let Some(flag) = &self.shutdown_flag {
            flag.store(true, Ordering::Release);
        }
        if let Some(ev) = &self.shutdown_event {
            ev.set();
        }
        // 3. 等待 workers（轮询超时，杜绝 Service Stopping... 无限卡住）
        let deadline = started + timeout;
        if let Some(workers) = self.workers.take() {
            for h in [workers.rx, workers.tx].into_iter().flatten() {
                while !h.is_finished() {
                    if Instant::now() >= deadline {
                        let waited = started.elapsed().as_millis() as u64;
                        tracing::error!(
                            target: "vnic",
                            event = "VNIC_SHUTDOWN_TIMEOUT",
                            waited_ms = waited,
                            "worker 未在超时内退出；泄漏 session/adapter/library 资源防止 use-after-free（进程退出由 OS 回收）"
                        );
                        // 要求六：worker 仍持 Arc 引用时绝不能 EndSession/CloseAdapter/FreeLibrary。
                        // 超时场景 M0 策略 = 受控泄漏（绝不 UB），产生 ShutdownTimeout 事件。
                        if let Some(s) = self.session.take() { std::mem::forget(s); }
                        if let Some(a) = self.adapter.take() { std::mem::forget(a); }
                        if let Some(l) = self.library.take() { std::mem::forget(l); }
                        return Err(VnicError::ShutdownTimeout { waited_ms: waited });
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                let _ = h.join(); // 已 finished，立即返回
            }
        }
        // 4/5. EndSession → CloseAdapter（显式释放；DLL 由 Drop 链最后 FreeLibrary）
        self.session = None;
        self.adapter = None;
        tracing::info!(target: "vnic", "MeshVnic 已停止（{}ms）", started.elapsed().as_millis());
        Ok(())
    }

    /// ICMP Echo Reply 辅助（集成测试/将来 agent 内置 ping 应答用）：
    /// 收到 echo request 后构造 reply 并经 TX 路径发回 Windows TCP/IP 栈。
    pub fn send_icmp_echo_reply_for(&self, request: &PacketBuffer) -> Result<(), VnicError> {
        match crate::packet::icmp_echo_reply(request) {
            Some(reply) => self.send(reply),
            None => Err(VnicError::PacketInvalid { reason: PacketRejectReason::UnsupportedIpVersion }),
        }
    }

    /// 供测试/诊断：ICMP checksum 重导出。
    #[doc(hidden)]
    pub fn icmp_checksum(bytes: &[u8]) -> u16 {
        icmp_checksum(bytes)
    }
}

impl Drop for MeshVnic {
    fn drop(&mut self) {
        // Drop 中无法返回错误：失败必须记录 structured log（要求六）。
        if self.session.is_some() || self.workers.is_some() {
            if let Err(e) = self.shutdown_inner(self.config.shutdown_timeout) {
                tracing::error!(
                    target: "vnic",
                    event = "VNIC_SHUTDOWN_ERROR",
                    error = %e,
                    "MeshVnic Drop 清理出错"
                );
            }
        }
        // 字段逆序 Drop 链：shutdown_event(CloseHandle) → session(EndSession)
        // → adapter(CloseAdapter) → library(FreeLibrary)
    }
}

// ---------------------------------------------------------------------------
// Workers
// ---------------------------------------------------------------------------

/// RX worker：正确的等待机制（要求八）——绝不 busy-spin。
fn spawn_rx_worker(
    session: Arc<WintunSession>,
    shutdown_event: ShareableEvent,
    shutdown_flag: Arc<AtomicBool>,
    rx_send: mpsc::SyncSender<PacketBuffer>,
    counters: Arc<Counters>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("vnic-rx".into())
        .spawn(move || {
            // ===================================================================
            // M0-3.1-2 RecvPacketGuard 边界冻结（硬契约，后续所有版本必须遵守）：
            //
            // 1. session.receive_packet() 返回 ReceivedPacketRef<'_>（Wintun ring
            //    buffer 内部 view）。它的 raw pointer / Deref &[u8] / 自身 Guard
            //    只能在本 RX worker 内短暂存在。
            // 2. 在进一步处理前，必须先 pkt.to_vec() 拷贝到我们自己的 Owned
            //    PacketBuffer。
            // 3. 立即 drop(pkt) 显式调用 WintunReleaseReceivePacket 归还 ring slot。
            // 4. 禁止把 ReceivedPacketGuard / *mut u8 / &[u8] 通过 mpsc、
            //    callback、TransportProvider::send_packet 传给 OverlayRouter、
            //    DirectLink、N2N、Cloudflare。对外形态只能是 PacketBuffer(Vec<u8>)。
            // 5. 如果未来要 zero-copy：必须写专门 ADR，并提供新的
            //    `trait LeasePacket { .. }` 保证上层 drop 时归还 Release。
            //    M0 不做 zero-copy。正确性优先。
            // ===================================================================
            let read_event = session.read_wait_event();
            loop {
                if shutdown_flag.load(Ordering::Acquire) {
                    break;
                }
                match session.receive_packet() {
                    Ok(Some(pkt)) => {
                        // --- 拷贝到 Owned buffer（Release 之前完成）---
                        let len = pkt.len() as u64;
                        let buf: PacketBuffer = pkt.to_vec();
                        drop(pkt); // <= ReleaseReceivePacket：ring slot 立即归还
                                   // 之后 buf 是我们的内存，与 Wintun ring 完全无关。

                        // --- classify 按 M0-3.1-3 四分类落 counter ---
                        match classify(&buf) {
                            PacketDisposition::AcceptIpv4Unicast(_) => {
                                counters.rx_packets.fetch_add(1, Ordering::Relaxed);
                                counters.rx_bytes.fetch_add(len, Ordering::Relaxed);
                                // RX 背压：try_send + 短轮询；每 10ms 检查 shutdown
                                let mut pending = buf;
                                loop {
                                    match rx_send.try_send(pending) {
                                        Ok(()) => break,
                                        Err(TrySendError::Full(b)) => {
                                            pending = b;
                                            if shutdown_flag.load(Ordering::Acquire) {
                                                counters.rx_dropped_backpressure.fetch_add(1, Ordering::Relaxed);
                                                break;
                                            }
                                            std::thread::sleep(Duration::from_millis(10));
                                        }
                                        Err(TrySendError::Disconnected(_)) => {
                                            counters.rx_dropped_backpressure.fetch_add(1, Ordering::Relaxed);
                                            return;
                                        }
                                    }
                                }
                                continue;
                            }
                            d => {
                                counters.record_rx_drop(&d);
                                if matches!(d, PacketDisposition::MalformedIpv4(_)) {
                                    tracing::debug!(
                                        target: "vnic",
                                        "RX MalformedIpv4 丢弃 len={len}",
                                    );
                                }
                                // UnsupportedIpv6 / UnsupportedMulticast / PolicyDrop：
                                // 属于正常流量，不打 debug 日志（避免刷屏）。
                            }
                        }
                    }
                    Ok(None) => {
                        // ring 空 → WaitForMultipleObjects([ReadWaitEvent, ShutdownEvent])
                        const WAIT_SHUTDOWN: u32 = WAIT_OBJECT_0 + 1;
                        let handles = [read_event, shutdown_event.get()];
                        let r = unsafe { win::WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
                        match r {
                            WAIT_OBJECT_0 => {}                        // 有新包 → 继续 drain
                            WAIT_SHUTDOWN => break,                    // shutdown
                            WAIT_FAILED => {
                                counters.rx_errors.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(target: "vnic", "WaitForMultipleObjects 失败 (os={})", unsafe { win::GetLastError() });
                                break;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        match &e {
                            VnicError::ReceiveInvalidData => {
                                // DLL 返回 size 异常（>0xFFFF 或 size=0 glitch）：
                                // session 内部已先 ReleaseReceivePacket；按 malformed 计数
                                counters.rx_dropped_malformed_ipv4.fetch_add(1, Ordering::Relaxed);
                                tracing::warn!(target: "vnic", "RX 收到 size 异常包，丢弃: {e}");
                            }
                            VnicError::ReceiveOther { .. } | _ => {
                                counters.rx_errors.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(target: "vnic", "WintunReceivePacket 致命错误: {e}");
                                break;
                            }
                        }
                    }
                }
            }
            tracing::debug!(target: "vnic", "RX worker 已退出");
        })
        .expect("RX worker 启动失败")
}

/// TX worker：有界队列消费 + ring 满丢弃计数（要求十）。
fn spawn_tx_worker(
    session: Arc<WintunSession>,
    tx_recv: mpsc::Receiver<PacketBuffer>,
    counters: Arc<Counters>,
) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("vnic-tx".into())
        .spawn(move || {
            let mut ring_full_warned = 0u64;
            while let Ok(buf) = tx_recv.recv() {
                // SAFETY：allocate 返回的缓冲在本线程立即写入并发送，无别名。
                match session.allocate_send_packet(buf.len() as u32) {
                    Ok(ptr) => unsafe {
                        std::ptr::copy_nonoverlapping(buf.as_ptr(), ptr, buf.len());
                        session.send_packet(ptr as *const u8);
                    },
                    Err(VnicError::SendRingFull) => {
                        let n = counters.tx_dropped_ring_full.fetch_add(1, Ordering::Relaxed) + 1;
                        if n == 1 || n % 1000 == 0 {
                            ring_full_warned = n;
                            tracing::warn!(target: "vnic", vnic_tx_ring_full_total = n, "Wintun TX ring 满，包已丢弃");
                        }
                        let _ = ring_full_warned;
                        continue;
                    }
                    Err(e) => {
                        counters.tx_errors.fetch_add(1, Ordering::Relaxed);
                        tracing::error!(target: "vnic", "WintunAllocateSendPacket 错误: {e}");
                        continue;
                    }
                }
                counters.tx_packets.fetch_add(1, Ordering::Relaxed);
                counters.tx_bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
            }
            tracing::debug!(target: "vnic", "TX worker 已退出");
        })
        .expect("TX worker 启动失败")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_params_accepts_defaults() {
        let p = VnicParams::default();
        let c = VnicConfig::from_params(&p).expect("默认参数必须可解析");
        assert_eq!(c.adapter_name, "MeshLink");
        assert_eq!(c.virtual_ip, Ipv4Addr::new(10, 70, 31, 1));
        assert_eq!(c.prefix_len, 24);
        assert_eq!(c.ring_capacity, 0x400000);
        assert_eq!(c.requested_guid, None, "M0 默认模式 A（不写死 GUID，要求十七）");
        assert_eq!(c.shutdown_timeout, Duration::from_secs(5));
    }

    #[test]
    fn from_params_rejects_illegal_ring_capacity() {
        let p = VnicParams { ring_capacity: 0x300000, ..Default::default() };
        let e = VnicConfig::from_params(&p).unwrap_err();
        assert!(matches!(e, VnicError::RingCapacityInvalid { .. }), "非 2 的幂必须启动前拒绝（要求七）");
    }

    #[test]
    fn from_params_rejects_virtual_ip_outside_overlay() {
        let p = VnicParams { virtual_ip: "10.70.32.1".into(), ..Default::default() };
        let e = VnicConfig::from_params(&p).unwrap_err();
        assert!(matches!(e, VnicError::ConfigInvalid { field: "vnic.virtual_ip", .. }));
    }

    #[test]
    fn from_params_rejects_default_route_cidr() {
        // 要求十四：M0 是 Overlay LAN，禁止 0.0.0.0/0
        let p = VnicParams {
            overlay_cidr: "0.0.0.0/0".into(),
            virtual_ip: "10.70.31.1".into(),
            ..Default::default()
        };
        let e = VnicConfig::from_params(&p).unwrap_err();
        assert!(matches!(e, VnicError::ConfigInvalid { field: "vnic.overlay_cidr", .. }));
    }

    #[test]
    fn from_params_rejects_bad_cidr_and_ip() {
        for p in [
            VnicParams { overlay_cidr: "10.70.31.0".into(), ..Default::default() },
            VnicParams { overlay_cidr: "10.70.31.0/33".into(), ..Default::default() },
            VnicParams { virtual_ip: "not-an-ip".into(), ..Default::default() },
            VnicParams { tx_queue_len: 0, ..Default::default() },
        ] {
            assert!(VnicConfig::from_params(&p).is_err(), "必须拒绝: {p:?}");
        }
    }

    #[test]
    fn from_params_guid_mode_b() {
        let p = VnicParams {
            requested_guid: Some("deadbabe-cafe-beef-0123-456789abcdef".into()),
            ..Default::default()
        };
        let c = VnicConfig::from_params(&p).expect("合法 GUID 模式 B 必须可解析");
        assert!(c.requested_guid.is_some());
        // 非法 GUID 拒绝
        let p = VnicParams { requested_guid: Some("xyz".into()), ..Default::default() };
        assert!(VnicConfig::from_params(&p).is_err());
    }

    #[test]
    fn peer_route_policy_only_allows_overlay_addresses() {
        // 规格八：只有 overlay 网段内的对端 IP 才允许被 /32 钉进 Wintun
        let c = VnicConfig::from_params(&VnicParams::default()).unwrap();
        assert!(peer_in_overlay(&c, Ipv4Addr::new(10, 70, 31, 2)));
        assert!(peer_in_overlay(&c, Ipv4Addr::new(10, 70, 31, 254)));
        assert!(!peer_in_overlay(&c, Ipv4Addr::new(10, 70, 32, 2)), "网段外必须拒绝");
        assert!(!peer_in_overlay(&c, Ipv4Addr::new(192, 168, 1, 10)), "用户 LAN 地址必须拒绝");
        assert!(!peer_in_overlay(&c, Ipv4Addr::new(8, 8, 8, 8)), "公网地址必须拒绝");
    }
}
