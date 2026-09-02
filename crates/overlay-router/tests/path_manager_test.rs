//! Path Manager 单元测试（M1-3a）：用可编程 Mock Provider 验证选路/熔断/防抖/强制。

use async_trait::async_trait;
use circuit_breaker::BreakerScope;
use mesh_common::{ErrorCode, MeshError};
use overlay_router::{
    PathManager, PathManagerConfig, PathManagerSnapshot, PathSwitchRecord,
};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use transport_api::{
    HealthSnapshot, PathKind, PeerHints, PeerId, ProbeResult, TransportConfig,
    TransportEvent, TransportProvider, TransportStats,
};

/// 可编程 TransportProvider：score 可随时改；subscribe_events 保存 sender 供测试注入事件。
struct MockProvider {
    score: AtomicU8,
    sent: AtomicUsize,
    ev_tx: Mutex<Option<tokio::sync::mpsc::Sender<TransportEvent>>>,
}

impl MockProvider {
    fn new(_name: &'static str, score: u8) -> Arc<Self> {
        Arc::new(Self {
            score: AtomicU8::new(score),
            sent: AtomicUsize::new(0),
            ev_tx: Mutex::new(None),
        })
    }
    fn set_score(&self, s: u8) {
        self.score.store(s, Ordering::Relaxed);
    }
    fn sent_count(&self) -> usize {
        self.sent.load(Ordering::Relaxed)
    }
    /// 注入一个 TransportEvent（模拟 provider 主动事件回流）。
    fn push_event(&self, ev: TransportEvent) {
        if let Some(tx) = self.ev_tx.lock().unwrap().as_ref() {
            let _ = tx.try_send(ev);
        }
    }
}

#[async_trait]
impl TransportProvider for MockProvider {
    async fn start(&self, _cfg: TransportConfig) -> Result<(), MeshError> {
        Ok(())
    }
    async fn stop(&self, _timeout: Duration) -> Result<(), MeshError> {
        Ok(())
    }
    async fn connect_peer(&self, _peer: PeerId, _hints: PeerHints) -> Result<(), MeshError> {
        Ok(())
    }
    async fn disconnect_peer(&self, _peer: PeerId) -> Result<(), MeshError> {
        Ok(())
    }
    async fn send_packet(&self, _peer: PeerId, _pkt: transport_api::Ipv4Packet) -> Result<(), MeshError> {
        self.sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn health(&self, _peer: Option<PeerId>) -> HealthSnapshot {
        HealthSnapshot {
            score: self.score.load(Ordering::Relaxed),
            rtt_ms: None,
            loss_pct: None,
            jitter_ms: None,
            stall_events: 0,
            transport_alive: self.score.load(Ordering::Relaxed) > 0,
        }
    }
    fn stats(&self) -> TransportStats {
        TransportStats::default()
    }
    async fn probe(&self, _peer: PeerId) -> ProbeResult {
        ProbeResult { ok: true, rtt_ms: None }
    }
    fn path_info(&self, _peer: PeerId) -> Option<transport_api::PathInfo> {
        None
    }
    async fn subscribe_events(&self, tx: tokio::sync::mpsc::Sender<TransportEvent>) {
        *self.ev_tx.lock().unwrap() = Some(tx);
    }
}

/// 构造一个带 directlink(rank1) + n2n(rank3) 双 mock 的 PathManager。
fn build(dl_score: u8, n2n_score: u8) -> (PathManager, Arc<MockProvider>, Arc<MockProvider>) {
    let mut pm = PathManager::new(PathManagerConfig::default());
    let dl = MockProvider::new("directlink", dl_score);
    let n2n = MockProvider::new("n2n", n2n_score);
    pm.register("directlink", dl.clone(), PathKind::DirectLink, BreakerScope::DirectLinkPeer { peer_id: "dev_a".into() });
    pm.register("n2n", n2n.clone(), PathKind::N2nRelay(transport_api::SupernodeId("sn-1".into())), BreakerScope::N2NProvider);
    (pm, dl, n2n)
}

async fn attach(pm: &PathManager) {
    pm.attach_peer(PeerId("dev_a".into()), PeerHints::default()).await;
}

fn base() -> Instant {
    Instant::now()
}

// 1. 初始选路：两者都健康 → DirectFirst 选 directlink（rank1）。
#[tokio::test]
async fn initial_select_directlink_first() {
    let (pm, _, _) = build(100, 100);
    attach(&pm).await;
    pm.evaluate(base());
    let a = pm.active_path().unwrap();
    assert_eq!(a.name, "directlink", "DirectFirst 应选 directlink");
}

// 2. DirectLink 不可用 → 选 n2n。
#[tokio::test]
async fn selects_n2n_when_directlink_down() {
    let (pm, _, _) = build(0, 100);
    attach(&pm).await;
    pm.evaluate(base());
    let a = pm.active_path().unwrap();
    assert_eq!(a.name, "n2n");
}

// 3. 强制路径锁定：即使 directlink 健康也强制 n2n。
#[tokio::test]
async fn forced_path_locks_slot() {
    let (pm, _, _) = build(100, 100);
    attach(&pm).await;
    pm.force_path(Some(1));
    pm.evaluate(base());
    let a = pm.active_path().unwrap();
    assert_eq!(a.name, "n2n");
}

// 4. 质量退化：directlink Critical 持续 3s → 切 n2n。
#[tokio::test]
async fn degraded_switches_to_backup_after_window() {
    let (pm, dl, _) = build(100, 100);
    attach(&pm).await;
    let t0 = base();
    pm.evaluate(t0);
    assert_eq!(pm.active_path().unwrap().name, "directlink");

    // 退化但不足 3s：不切。
    dl.set_score(30); // < 40 Critical
    pm.evaluate(t0);
    pm.evaluate(t0 + Duration::from_secs(1));
    assert_eq!(pm.active_path().unwrap().name, "directlink", "1s < 3s 不应切换");

    // 持续 ≥3s：切到 n2n。
    pm.evaluate(t0 + Duration::from_secs(4));
    assert_eq!(pm.active_path().unwrap().name, "n2n", "Critical 持续 3s 应切换");
}

// 5. Fatal 事件 → 立即熔断并切换（不等健康窗口）。
#[tokio::test]
async fn fatal_event_breaks_and_switches_immediately() {
    let (pm, dl, _) = build(100, 100);
    attach(&pm).await;
    let t0 = base();
    pm.evaluate(t0);
    assert_eq!(pm.active_path().unwrap().name, "directlink");

    // 注入 Fatal（模拟 provider 崩溃）：directlink 立即熔断。
    dl.push_event(TransportEvent::Fatal(ErrorCode::TransportStartFailed));
    pm.drain_events();
    pm.evaluate(t0 + Duration::from_millis(1));
    assert_eq!(pm.active_path().unwrap().name, "n2n", "Fatal 应立即切换");
}

// 6. 防抖回切：directlink 恢复但未稳定 10s 不切回；稳定后切回。
#[tokio::test]
async fn switchback_requires_stability() {
    let (pm, dl, _) = build(100, 100);
    attach(&pm).await;
    let t0 = base();
    pm.evaluate(t0);
    assert_eq!(pm.active_path().unwrap().name, "directlink");

    // 切到 n2n。
    dl.set_score(0);
    pm.evaluate(t0);
    pm.evaluate(t0 + Duration::from_secs(4)); // degraded ≥3s → n2n
    assert_eq!(pm.active_path().unwrap().name, "n2n");

    // directlink 恢复健康：5s 内不回切（防抖 10s）。
    dl.set_score(100);
    let t1 = t0 + Duration::from_secs(4);
    pm.evaluate(t1);
    pm.evaluate(t1 + Duration::from_secs(5));
    assert_eq!(pm.active_path().unwrap().name, "n2n", "恢复 5s < 10s 不应回切");

    // 稳定 ≥10s → 回切 directlink。
    pm.evaluate(t1 + Duration::from_secs(11));
    assert_eq!(pm.active_path().unwrap().name, "directlink", "稳定 10s 应回切 P2P");
}

// 7. 强制路径失败 → 让出给最佳候选（不死锁在坏路径）。
#[tokio::test]
async fn forced_path_failed_falls_back() {
    let (pm, dl, _) = build(100, 100);
    attach(&pm).await;
    pm.force_path(Some(0)); // 强制 directlink
    pm.evaluate(base());
    assert_eq!(pm.active_path().unwrap().name, "directlink");

    // directlink Fatal → 熔断 → 强制路径不可用，让出给 n2n。
    dl.push_event(TransportEvent::Fatal(ErrorCode::TransportStartFailed));
    pm.drain_events();
    pm.evaluate(base() + Duration::from_millis(1));
    assert_eq!(pm.active_path().unwrap().name, "n2n", "强制路径熔断应让出");
}

// 8. snapshot 反映 active/health/breaker。
#[tokio::test]
async fn snapshot_reflects_state() {
    let (pm, _, _) = build(100, 100);
    attach(&pm).await;
    pm.evaluate(base());
    let snap: PathManagerSnapshot = pm.snapshot();
    assert_eq!(snap.active.as_ref().unwrap().name, "directlink");
    assert_eq!(snap.paths.len(), 2);
    let dl = snap.paths.iter().find(|p| p.name == "directlink").unwrap();
    assert_eq!(dl.score, 100);
    assert_eq!(dl.breaker, "closed");
}

// 9. send_packet 转发到活跃路径。
#[tokio::test]
async fn send_packet_routes_to_active() {
    let (pm, dl, n2n) = build(100, 100);
    attach(&pm).await;
    pm.evaluate(base());
    let pkt = transport_api::Ipv4Packet { bytes: vec![1, 2, 3] };
    pm.send_packet(PeerId("dev_a".into()), pkt.clone()).await.unwrap();
    assert_eq!(dl.sent_count(), 1, "active=directlink 时发送到 directlink");
    assert_eq!(n2n.sent_count(), 0);

    // 切到 n2n 后发送到 n2n。
    dl.set_score(0);
    pm.evaluate(base());
    pm.evaluate(base() + Duration::from_secs(4));
    assert_eq!(pm.active_path().unwrap().name, "n2n");
    pm.send_packet(PeerId("dev_a".into()), pkt).await.unwrap();
    assert_eq!(n2n.sent_count(), 1);
    assert_eq!(dl.sent_count(), 1);
}

// 10. 切换事件发出 PathSwitchRecord（文档 9.5）。
#[tokio::test]
async fn event_sink_emits_switch_record() {
    let (pm, dl, _) = build(100, 100);
    attach(&pm).await;
    let (tx, rx) = std::sync::mpsc::channel::<PathSwitchRecord>();
    pm.set_event_sink(tx);
    let t0 = base();
    pm.evaluate(t0);
    // 首次选路 directlink 也发一条（from=None）。
    let r0 = rx.recv().unwrap();
    assert_eq!(r0.from, None);
    assert_eq!(r0.to, "directlink");

    // 退化切换 → 第二条。
    dl.set_score(0);
    pm.evaluate(t0);
    pm.evaluate(t0 + Duration::from_secs(4));
    let r1 = rx.recv().unwrap();
    assert_eq!(r1.from.as_deref(), Some("directlink"));
    assert_eq!(r1.to, "n2n");
    assert_eq!(r1.reason, "degraded");
    assert!(rx.try_recv().is_err(), "不应有多余切换事件");
}
