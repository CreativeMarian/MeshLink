//! Path Manager（M1-3 核心）：DirectLink ↔ N2N 多路径自动选路与运行中切换。
//!
//! 设计约束（确认版 §4）：
//! - 只面向 `transport_api::TransportProvider`，禁止任何具体实现类型/分支。
//! - 选路 = 强制路径 × 熔断门(四类) × 健康分 × 防抖回切。
//! - Hard Failure（Fatal / PeerUnreachable 事件）→ 立即熔断并切换；
//!   Quality Degradation → 健康分驱动（Critical < `degrade_floor` 持续
//!   `degrade_window`）→ 切换。两套触发机制分离。
//! - 回切更高优先级路径（P2P 恢复）前须稳定 `switchback_stable`，防抖动。
//!
//! 本模块是纯逻辑核心：`evaluate()` 为同步可测的决策入口，`run()` 只是
//! 定时驱动 wrapper。M1-3b 由 mesh-agent 接入（pump 转发 + UI 上抛）。

use circuit_breaker::{
    BreakerScope, BreakerState, CircuitBreakerManager,
};
use config_manager::RuntimeParams;
use mesh_common::{ErrorCode, MeshError};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use std::sync::Arc;
use std::time::{Duration, Instant};
use transport_api::{
    PathKind, PathPolicy, PeerHints, PeerId, TransportEvent, TransportProvider,
};

/// Path Manager 配置（默认值贴合文档 9.4 / 15.4）。
#[derive(Debug, Clone)]
pub struct PathManagerConfig {
    /// 健康采样/选路评估间隔（默认 2s）。
    pub health_interval: Duration,
    /// 质量退化阈值：score < 此值视为 Critical（默认 40）。
    pub degrade_floor: u8,
    /// Critical 持续多久触发切换（默认 3s）。
    pub degrade_window: Duration,
    /// 回切更高优先级路径前的稳定时长（防抖，默认 10s）。
    pub switchback_stable: Duration,
    /// 可视为「健康」的分数下限（回切候选要求，默认 70）。
    pub healthy_threshold: u8,
    /// 熔断器参数来源（RuntimeParams → BreakerParams）。
    pub runtime: RuntimeParams,
}

impl Default for PathManagerConfig {
    fn default() -> Self {
        Self {
            health_interval: Duration::from_secs(2),
            degrade_floor: 40,
            degrade_window: Duration::from_secs(3),
            switchback_stable: Duration::from_secs(10),
            healthy_threshold: 70,
            runtime: RuntimeParams::default(),
        }
    }
}

/// 单个已注册 Provider 的槽位。
struct ProviderSlot {
    /// 展示名（"directlink" / "n2n"），仅日志/诊断用，不参与逻辑分支。
    name: String,
    provider: Arc<dyn TransportProvider>,
    kind: PathKind,
    breaker_scope: BreakerScope,
}

/// 健康缓存 + 退化/稳定计时（防抖依据）。
#[derive(Debug, Clone, Default)]
struct HealthEntry {
    score: u8,
    rtt_ms: Option<f64>,
    /// 进入 Critical 的时刻（None = 当前健康）。
    since_degraded: Option<Instant>,
    /// 达到 healthy_threshold 起的连续时刻（None = 尚未健康）。
    healthy_since: Option<Instant>,
}

impl HealthEntry {
    fn degraded(&self, floor: u8, window: Duration, now: Instant) -> bool {
        self.since_degraded
            .map(|t| now.duration_since(t) >= window && self.score < floor)
            .unwrap_or(false)
    }
    fn stable_healthy(&self, threshold: u8, stable: Duration, now: Instant) -> bool {
        self.healthy_since
            .map(|t| now.duration_since(t) >= stable && self.score >= threshold)
            .unwrap_or(false)
    }
}

/// 对外路径切换记录（UI/诊断/SystemEvent 同源）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathSwitchRecord {
    pub from: Option<String>,
    pub to: String,
    pub reason: String,
    pub score: Option<u8>,
    pub at_ms: u64,
}

/// 当前活跃路径信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivePathInfo {
    pub name: String,
    pub kind: PathKind,
    /// 当前路径已稳定时长（防抖展示）。
    pub stable_ms: u64,
}

/// 单路径健康快照（诊断页展示）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathHealthInfo {
    pub name: String,
    pub kind: PathKind,
    pub score: u8,
    pub rtt_ms: Option<f64>,
    pub breaker: String,
}

/// Path Manager 快照（GetDiagnostics 或诊断页）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathManagerSnapshot {
    pub policy: PathPolicy,
    pub forced: Option<String>,
    pub active: Option<ActivePathInfo>,
    pub paths: Vec<PathHealthInfo>,
}

/// 多路径选路管理器。
pub struct PathManager {
    cfg: PathManagerConfig,
    slots: Vec<ProviderSlot>,
    policy: Mutex<PathPolicy>,
    /// 强制路径槽位（None = 自动）。
    forced: Mutex<Option<usize>>,
    peer: Mutex<Option<PeerId>>,
    active: Mutex<Option<(usize, Instant)>>,
    healths: Mutex<Vec<HealthEntry>>,
    breaker: Mutex<CircuitBreakerManager>,
    /// 各 slot 的 TransportEvent 接收端（attach_peer 时建立）。
    event_rxs: Mutex<Vec<tokio::sync::mpsc::Receiver<TransportEvent>>>,
    /// 对外切换事件出口（agent/UI 订阅）。
    event_tx: Mutex<Option<std::sync::mpsc::Sender<PathSwitchRecord>>>,
}

impl PathManager {
    pub fn new(cfg: PathManagerConfig) -> Self {
        Self {
            cfg,
            slots: Vec::new(),
            policy: Mutex::new(PathPolicy::DirectFirst),
            forced: Mutex::new(None),
            peer: Mutex::new(None),
            active: Mutex::new(None),
            healths: Mutex::new(Vec::new()),
            breaker: Mutex::new(CircuitBreakerManager::new(RuntimeParams::default())),
            event_rxs: Mutex::new(Vec::new()),
            event_tx: Mutex::new(None),
        }
    }

    /// 注册一个 TransportProvider，返回槽位索引（后续 force_path / snapshot 用）。
    pub fn register(
        &mut self,
        name: &str,
        provider: Arc<dyn TransportProvider>,
        kind: PathKind,
        breaker_scope: BreakerScope,
    ) -> usize {
        let i = self.slots.len();
        self.slots.push(ProviderSlot { name: name.to_string(), provider, kind, breaker_scope });
        self.healths.lock().unwrap().push(HealthEntry::default());
        i
    }

    /// 初始选路策略（默认 DirectFirst；LowestRtt 等可在注册后调整）。
    pub fn set_policy(&self, policy: PathPolicy) {
        *self.policy.lock().unwrap() = policy;
    }

    /// 强制路径：Some(槽位) = 锁定该路径；None = 回到自动（按 policy + 健康）。
    pub fn force_path(&self, slot: Option<usize>) {
        *self.forced.lock().unwrap() = slot;
    }

    /// 对外切换事件出口。
    pub fn set_event_sink(&self, tx: std::sync::mpsc::Sender<PathSwitchRecord>) {
        *self.event_tx.lock().unwrap() = Some(tx);
    }

    /// 绑定对端：为每个 Provider 订阅事件 + connect_peer（async）。
    pub async fn attach_peer(&self, peer: PeerId, hints: PeerHints) {
        *self.peer.lock().unwrap() = Some(peer.clone());
        let mut rxs = Vec::new();
        for slot in self.slots.iter() {
            let (tx, rx) = tokio::sync::mpsc::channel::<TransportEvent>(64);
            // subscribe_events 先于 connect_peer：事件回流窗口不丢 Fatal/Reachable。
            slot.provider.subscribe_events(tx).await;
            // N2N 等 provider 可能忽略 hints；DirectLink 需要 endpoints。
            let _ = slot.provider.connect_peer(peer.clone(), hints.clone()).await;
            rxs.push(rx);
        }
        *self.event_rxs.lock().unwrap() = rxs;
    }

    /// 解绑对端（断开所有 provider）。
    pub async fn detach_peer(&self, peer: &PeerId) {
        *self.peer.lock().unwrap() = None;
        *self.active.lock().unwrap() = None;
        for slot in &self.slots {
            let _ = slot.provider.disconnect_peer(peer.clone()).await;
        }
        self.event_rxs.lock().unwrap().clear();
    }

    /// 事件驱动入口（drain_events 或外部注入调用）。
    pub fn handle_event(&self, slot: usize, ev: TransportEvent) {
        let Some(scope) = self.slots.get(slot).map(|s| s.breaker_scope.clone()) else {
            return;
        };
        let clock = circuit_breaker::clock::MonotonicClock::default();
        match ev {
            TransportEvent::Fatal(code) | TransportEvent::PeerUnreachable(_, _, code) => {
                // Hard Failure：立即熔断该路径，evaluate 时切换。
                let _ = self
                    .breaker
                    .lock()
                    .unwrap()
                    .record_fatal(&scope, &clock, format!("{:?}", code));
                tracing::warn!(target: "path_manager", slot, scope = ?scope, code = ?code, "路径 Hard Failure，熔断");
            }
            TransportEvent::HealthChanged(_, h) => {
                if let Some(e) = self.healths.lock().unwrap().get_mut(slot) {
                    e.score = h.score;
                    e.rtt_ms = h.rtt_ms;
                    // 事件驱动的 score 只更新缓存；退化窗口仍由 evaluate 计时。
                }
            }
            _ => {}
        }
    }

    /// 消费各 provider 的事件队列（run 循环调用；也可测试手动触发）。
    pub fn drain_events(&self) {
        let mut rxs = self.event_rxs.lock().unwrap();
        for (slot, rx) in rxs.iter_mut().enumerate() {
            loop {
                match rx.try_recv() {
                    Ok(ev) => self.handle_event(slot, ev),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
                }
            }
        }
    }

    /// 健康采样 + 选路决策（同步、幂等、可测）。
    pub fn evaluate(&self, now: Instant) {
        // 1. 采样所有 provider 健康。
        let peer = self.peer.lock().unwrap().clone();
        if let Some(peer) = peer {
            for (i, slot) in self.slots.iter().enumerate() {
                let h = slot.provider.health(Some(peer.clone()));
                let mut hs = self.healths.lock().unwrap();
                if let Some(e) = hs.get_mut(i) {
                    e.score = h.score;
                    e.rtt_ms = h.rtt_ms;
                    if h.score < self.cfg.degrade_floor {
                        if e.since_degraded.is_none() {
                            e.since_degraded = Some(now);
                            e.healthy_since = None;
                        }
                    } else {
                        e.since_degraded = None;
                        if e.healthy_since.is_none() {
                            e.healthy_since = Some(now);
                        }
                    }
                }
            }
        }

        // 2. 决策切换。
        self.decide(now);
    }

    /// 选路决策：强制路径 → 熔断/退化切换 → 防抖回切。
    ///
    /// 锁纪律：先把健康/熔断/退化/稳定状态**快照**到本地 Vec，再决策；
    /// 决策过程中禁止同时持有任何 MutexGuard 再调用 switch_to
    /// （switch_to 内部会再次加锁，嵌套会导致同线程死锁）。
    fn decide(&self, now: Instant) {
        let forced = *self.forced.lock().unwrap();
        let n = self.slots.len();
        if n == 0 {
            return;
        }
        let clock = circuit_breaker::clock::MonotonicClock::default();

        // 1. 本地快照（唯一一次持锁段）。
        struct View {
            score: u8,
            degraded: bool,
            stable_healthy: bool,
            breaker_open: bool,
            rank: u8,
        }
        let views: Vec<View> = {
            let healths = self.healths.lock().unwrap();
            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let h = &healths[i];
                let breaker_open = {
                    let scope = &self.slots[i].breaker_scope;
                    let mut b = self.breaker.lock().unwrap();
                    b.state(scope, &clock) == BreakerState::Open
                };
                out.push(View {
                    score: h.score,
                    degraded: h.degraded(self.cfg.degrade_floor, self.cfg.degrade_window, now),
                    stable_healthy: h.stable_healthy(
                        self.cfg.healthy_threshold,
                        self.cfg.switchback_stable,
                        now,
                    ),
                    breaker_open,
                    rank: self.slots[i].kind.default_rank(),
                });
            }
            out
        };
        let active = *self.active.lock().unwrap();

        // 2. 候选 = 未熔断 且 健康分非 Critical 的槽位，按 PathKind 默认 rank 排序。
        let mut candidates: Vec<usize> = (0..n)
            .filter(|&i| !views[i].breaker_open && views[i].score >= self.cfg.degrade_floor)
            .collect();
        candidates.sort_by_key(|&i| views[i].rank);

        // 3. 强制路径：目标可用则锁定；目标熔断则回退自动（避免死锁在坏路径）。
        if let Some(target) = forced {
            let target_ok = !views[target].breaker_open
                && views[target].score >= self.cfg.degrade_floor;
            let cur = active.map(|(i, _)| i);
            if target_ok && cur != Some(target) {
                self.switch_to(target, "forced", now, views[target].score);
            } else if !target_ok && cur == Some(target) {
                // 强制路径坏了 → 立即让出给最佳候选。
                if let Some(&best) = candidates.iter().find(|&&i| i != target) {
                    self.switch_to(best, "forced_path_failed", now, views[best].score);
                }
            }
            return;
        }

        // 4. 自动：
        match active {
            None => {
                // 初始/无活跃 → 选最佳候选。
                if let Some(&best) = candidates.first() {
                    self.switch_to(best, "initial", now, views[best].score);
                }
            }
            Some((ci, _since)) => {
                // a. 当前路径熔断 → 立即切换。
                if views[ci].breaker_open {
                    if let Some(&best) = candidates.iter().find(|&&i| i != ci) {
                        self.switch_to(best, "breaker_open", now, views[best].score);
                    }
                    return;
                }
                // b. 当前路径质量退化（Critical 持续 window）→ 切换。
                if views[ci].degraded {
                    if let Some(&best) = candidates.iter().find(|&&i| i != ci) {
                        self.switch_to(best, "degraded", now, views[best].score);
                    }
                    return;
                }
                // c. 防抖回切：存在更高 rank 且已稳定 healthy_threshold 的候选。
                let cur_rank = views[ci].rank;
                if let Some(&better) = candidates.iter().find(|&&i| {
                    views[i].rank < cur_rank && views[i].stable_healthy && i != ci
                }) {
                    self.switch_to(better, "switchback_stable", now, views[better].score);
                }
            }
        }
    }

    fn switch_to(&self, slot: usize, reason: &str, now: Instant, score: u8) {
        let mut active = self.active.lock().unwrap();
        let from = active.map(|(i, _)| self.slots[i].name.clone());
        let to = self.slots[slot].name.clone();
        *active = Some((slot, now));
        tracing::info!(
            target: "path_manager",
            from = ?from,
            to = %to,
            reason,
            score,
            "路径切换"
        );
        if let Some(tx) = self.event_tx.lock().unwrap().as_ref() {
            let _ = tx.send(PathSwitchRecord {
                from,
                to,
                reason: reason.to_string(),
                score: Some(score),
                at_ms: now.elapsed().as_millis() as u64,
            });
        }
    }

    /// 当前活跃路径（name/kind/stable）。
    pub fn active_path(&self) -> Option<ActivePathInfo> {
        let active = self.active.lock().unwrap().clone()?;
        let (i, since) = active;
        let slot = &self.slots[i];
        Some(ActivePathInfo {
            name: slot.name.clone(),
            kind: slot.kind.clone(),
            stable_ms: since.elapsed().as_millis() as u64,
        })
    }

    /// 对外快照（诊断页）。
    pub fn snapshot(&self) -> PathManagerSnapshot {
        let clock = circuit_breaker::clock::MonotonicClock::default();
        let policy = *self.policy.lock().unwrap();
        let forced = self.forced.lock().unwrap().map(|i| self.slots[i].name.clone());
        let active = self.active_path();
        let healths = self.healths.lock().unwrap();
        let paths = self
            .slots
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let st = self.breaker.lock().unwrap().state(&s.breaker_scope, &clock);
                PathHealthInfo {
                    name: s.name.clone(),
                    kind: s.kind.clone(),
                    score: healths[i].score,
                    rtt_ms: healths[i].rtt_ms,
                    breaker: st.as_str().to_string(),
                }
            })
            .collect();
        PathManagerSnapshot { policy, forced, active, paths }
    }

    /// 数据面转发：发送到当前活跃路径。
    pub async fn send_packet(&self, peer: PeerId, pkt: transport_api::Ipv4Packet) -> Result<(), MeshError> {
        let i = self
            .active
            .lock()
            .unwrap()
            .map(|(i, _)| i)
            .ok_or_else(|| MeshError::new(ErrorCode::TransportStartFailed, "无活跃路径"))?;
        self.slots[i].provider.send_packet(peer, pkt).await
    }

    /// 定时驱动（agent 侧 spawn 此任务）。
    pub async fn run(&self) {
        let mut ticker = tokio::time::interval(self.cfg.health_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            self.drain_events();
            self.evaluate(Instant::now());
        }
    }
}
