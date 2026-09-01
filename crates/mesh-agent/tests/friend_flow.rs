//! M1-1 Friend & Device UX 集成测试（全自动，MANUAL TEST REQUIRED = NONE）。
//!
//! 真实 Go Controller + Agent A + Agent B（Mock Overlay）：
//! A 创建好友邀请 → B 兑换（PENDING）→ B 接受（ACCEPTED）→ A 向好友 B 发起
//! 直连 → B 收到 IncomingConnectionRequest → B 接受 → Candidate Exchange →
//! DirectLink → Noise → Overlay → 双方 CONNECTED → 加密 overlay 双向 ping。
//!
//! 覆盖用户规格十五清单：Create/Redeem invite、Friend created、ConnectFriend、
//! Incoming request accept、好友连接后的 Encrypted overlay ping、FriendsChanged
//! 事件；以及 RedeemInvite 不再创建连接会话（规格四：好友关系与 Session 分离）。

use mesh_agent::overlay::OverlayBackend;
use mesh_agent::{spawn_service, AgentConfig, AgentState, OverlayKind};
use mesh_ipc::{Command, Event, PipeClient, Request, ServerMessage};
use std::io::Read;
use std::net::Ipv4Addr;
use std::process::{Child, Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};

const FRIEND_TIMEOUT: Duration = Duration::from_secs(60);

fn tag() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn pipe_name(role: &str) -> String {
    format!(
        r"\\.\pipe\meshlink-friend-{role}-{}-{}",
        std::process::id(),
        tag()
    )
}

struct ControllerGuard {
    child: Child,
}

impl Drop for ControllerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_controller(tmp: &std::path::Path) -> (String, ControllerGuard) {
    if ProcessCommand::new("go").arg("version").output().is_err() {
        panic!("未找到 go 工具链：好友流集成测试需要编译 Go Controller");
    }
    let controller_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../server/controller");
    let exe = tmp.join("controller-friend.exe");
    let out = ProcessCommand::new("go")
        .arg("build")
        .arg("-o")
        .arg(&exe)
        .arg("./cmd/controller")
        .current_dir(&controller_dir)
        .output()
        .expect("go build 执行失败");
    assert!(
        out.status.success(),
        "go build Controller 失败: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);

    let addr = format!("127.0.0.1:{port}");
    let log_path = tmp.join("controller.log");
    let log = std::fs::File::create(&log_path).expect("create controller log");
    let child = ProcessCommand::new(&exe)
        .arg("-addr")
        .arg(&addr)
        .arg("-db")
        .arg(tmp.join("controller.db"))
        .stdout(Stdio::from(log.try_clone().expect("dup log")))
        .stderr(Stdio::from(log))
        .spawn()
        .expect("spawn controller");

    let url = format!("http://{addr}");
    let client = controller_client::Client::new(&url).expect("controller client");
    let guard = ControllerGuard { child };
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(v) = client.healthz() {
            assert_eq!(v["status"], "ok");
            break;
        }
        if Instant::now() > deadline {
            let mut log_text = String::new();
            if let Ok(mut f) = std::fs::File::open(&log_path) {
                let _ = f.read_to_string(&mut log_text);
            }
            panic!(
                "Controller 10s 内未就绪: {}",
                &log_text[log_text.len().saturating_sub(1500)..]
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    (url, guard)
}

fn wait_connect(name: &str, timeout: Duration) -> PipeClient {
    let deadline = Instant::now() + timeout;
    loop {
        match PipeClient::connect(name, Duration::from_secs(2)) {
            Ok(c) => return c,
            Err(_) => {
                if Instant::now() > deadline {
                    panic!("连接管道超时: {name}");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn wait_state(ui: &mut PipeClient, want: AgentState, timeout: Duration) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    let mut id = 0u64;
    loop {
        id += 1;
        let resp = ui
            .request(&Request { id, command: Command::GetStatus })
            .expect("GetStatus");
        assert!(resp.ok, "GetStatus 失败: {:?}", resp.error);
        let data = resp.data.expect("快照");
        if data["state"] == serde_json::json!(want) {
            return data;
        }
        if Instant::now() > deadline {
            panic!("等待 {want:?} 超时，最后快照: {data}");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn request_data(ui: &mut PipeClient, cmd: Command) -> serde_json::Value {
    let resp = ui.request(&Request { id: u64::MAX, command: cmd }).expect("请求");
    assert!(resp.ok, "命令失败: {:?} (data={:?})", resp.error, resp.data);
    resp.data.expect("命令必须携带 data")
}

fn collect_until(ui: &mut PipeClient, timeout: Duration, stop: impl Fn(&Event) -> bool) -> Vec<Event> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while Instant::now() < deadline {
        if let Some(ServerMessage::Event(ev)) = ui.wait_message(Duration::from_millis(200)) {
            let hit = stop(&ev);
            out.push(ev);
            if hit {
                break;
            }
        }
    }
    out
}

fn event_name(e: &Event) -> &'static str {
    match e {
        Event::ControllerConnected { .. } => "ControllerConnected",
        Event::WaitingForPeer { .. } => "WaitingForPeer",
        Event::PeerFound { .. } => "PeerFound",
        Event::GatheringCandidates { .. } => "GatheringCandidates",
        Event::Punching { .. } => "Punching",
        Event::NoiseHandshaking { .. } => "NoiseHandshaking",
        Event::Connected { .. } => "Connected",
        Event::PathChanged { .. } => "PathChanged",
        Event::Disconnected { .. } => "Disconnected",
        Event::Error { .. } => "Error",
        Event::IncomingConnectionRequest { .. } => "IncomingConnectionRequest",
        Event::FriendPending { .. } => "FriendPending",
        Event::FriendAccepted { .. } => "FriendAccepted",
        Event::FriendRemoved { .. } => "FriendRemoved",
        Event::FriendOnline { .. } => "FriendOnline",
        Event::FriendOffline { .. } => "FriendOffline",
        Event::DeviceOnline { .. } => "DeviceOnline",
        Event::DeviceOffline { .. } => "DeviceOffline",
        Event::FriendConnected { .. } => "FriendConnected",
        Event::FriendDisconnected { .. } => "FriendDisconnected",
        Event::FriendsChanged => "FriendsChanged",
        Event::RecentConnectionsChanged => "RecentConnectionsChanged",
    }
}

fn assert_no_error(events: &[Event], who: &str) {
    for ev in events {
        if let Event::Error { code, message } = ev {
            panic!(
                "{who} 出现错误事件 {code}: {message}（事件流: {}）",
                serde_json::to_string(events).unwrap()
            );
        }
    }
}

// 用户 ping 构造（与 mvp_gate 一致：type8 echo + 载荷）。
const USER_PING_PAYLOAD: &[u8] = b"meshlink-friend-ping-v1";

fn user_ping(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let icmp_len = 8 + USER_PING_PAYLOAD.len();
    let total = 20 + icmp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 1;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let hdr_sum = mesh_vnic::icmp_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&hdr_sum.to_be_bytes());
    pkt[20] = 8;
    pkt[24..26].copy_from_slice(&id.to_be_bytes());
    pkt[26..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..total].copy_from_slice(USER_PING_PAYLOAD);
    let icmp_sum = mesh_vnic::icmp_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_sum.to_be_bytes());
    pkt
}

fn is_echo_reply(pkt: &[u8], id: u16, seq: u16) -> bool {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let icmp = &pkt[ihl..];
    icmp[0] == 0
        && u16::from_be_bytes([icmp[4], icmp[5]]) == id
        && u16::from_be_bytes([icmp[6], icmp[7]]) == seq
        && &icmp[8..] == USER_PING_PAYLOAD
}

fn is_request(pkt: &[u8], id: u16) -> bool {
    if pkt.len() < 28 || pkt[0] >> 4 != 4 || pkt[9] != 1 {
        return false;
    }
    let ihl = (pkt[0] & 0x0F) as usize * 4;
    let icmp = &pkt[ihl..];
    icmp[0] == 8
        && u16::from_be_bytes([icmp[4], icmp[5]]) == id
        && u16::from_be_bytes([icmp[6], icmp[7]]) == 1
        && &icmp[8..] == USER_PING_PAYLOAD
}

fn pkt_src_dst(pkt: &[u8]) -> (Ipv4Addr, Ipv4Addr) {
    (
        Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]),
        Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]),
    )
}

fn wait_injected_all(
    mock: &mesh_agent::MockOverlay,
    preds: Vec<Box<dyn Fn(&[u8]) -> bool>>,
    timeout: Duration,
    what: &str,
) {
    let mut seen: Vec<Vec<u8>> = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        seen.extend(mock.take_injected());
        let satisfied: Vec<bool> = (0..preds.len()).map(|i| seen.iter().any(|p| preds[i](p))).collect();
        if satisfied.iter().all(|&s| s) {
            return;
        }
        if Instant::now() > deadline {
            panic!("{what}: 注入队列未满足全部条件（{satisfied:?}，已见 {} 包）", seen.len());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn m1_1_friend_invite_to_encrypted_overlay_ping() {
    mesh_common::logging::init_logging("info,directlink=debug,agent=debug", false);

    let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("meshlink-friend-flow"));
    let run_dir = tmp.join(format!("friend-{}", tag()));
    let _ = std::fs::remove_dir_all(&run_dir);
    std::fs::create_dir_all(&run_dir).expect("mkdir run");

    let (controller_url, _controller) = spawn_controller(&run_dir);

    let agent_cfg = |dir_tag: &str, name: &str| AgentConfig {
        controller_url: controller_url.clone(),
        data_dir: run_dir.join(dir_tag),
        network_id: "meshlink-friend".into(),
        device_name: Some(name.into()),
        overlay: OverlayKind::Mock,
        stun_servers: Vec::new(),
        wait_peer_timeout: Duration::from_secs(45),
        ..AgentConfig::default()
    };
    let pipe_a = pipe_name("a");
    let pipe_b = pipe_name("b");
    let (agent_a, server_a) = spawn_service(agent_cfg("agent-a", "Alice-PC"), &pipe_a).expect("spawn A");
    let (agent_b, server_b) = spawn_service(agent_cfg("agent-b", "Bob-PC"), &pipe_b).expect("spawn B");

    let mut ui_a = wait_connect(&pipe_a, Duration::from_secs(10));
    let mut ui_b = wait_connect(&pipe_b, Duration::from_secs(10));

    // ---- 双端 READY ----
    let snap_a = wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(30));
    let snap_b = wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(30));
    let dev_a = snap_a["device_id"].as_str().unwrap().to_string();
    let dev_b = snap_b["device_id"].as_str().unwrap().to_string();

    // ---- A 创建好友邀请（24h / 不限次）----
    let inv = request_data(
        &mut ui_a,
        Command::CreateFriendInvite { ttl: "24h".into(), max_uses: 0 },
    );
    let invite_id = inv["invite_id"].as_str().expect("invite_id").to_string();
    let token = inv["invite_token"].as_str().expect("一次性 token").to_string();
    assert!(token.starts_with("mli_"), "token 前缀");

    // ---- B 兑换 → PENDING 好友关系（不创建连接会话）----
    let redeemed = request_data(
        &mut ui_b,
        Command::RedeemFriendInvite { invite_id: invite_id.clone(), token: token.clone() },
    );
    let friendship_id = redeemed["friendship_id"].as_str().expect("friendship_id").to_string();
    assert_eq!(redeemed["status"], "PENDING");
    assert_eq!(redeemed["creator_device_id"], dev_a, "邀请方 = Alice");
    // B 收到 FriendPending + FriendsChanged。
    let ev_b1 = collect_until(&mut ui_b, Duration::from_secs(15), |e| {
        matches!(e, Event::FriendPending { .. } | Event::Error { .. })
    });
    assert_no_error(&ev_b1, "B redeem");
    assert!(
        ev_b1.iter().any(|e| matches!(e, Event::FriendPending { peer_device_id, .. } if peer_device_id == &dev_a)),
        "B 必须收到 FriendPending（来自 A），事件流: {:?}",
        ev_b1.iter().map(event_name).collect::<Vec<_>>()
    );

    // ---- A 的邀请列表可见（我的邀请）----
    let invites = request_data(&mut ui_a, Command::ListInvites);
    let list = invites["invites"].as_array().expect("invites");
    assert_eq!(list.len(), 1, "A 有 1 个邀请");
    assert_eq!(list[0]["invite_id"], invite_id);

    // ---- B 接受好友请求 → ACCEPTED；双方好友列表出现对方 ----
    let acc = request_data(&mut ui_b, Command::AcceptFriendship { friendship_id: friendship_id.clone() });
    assert_eq!(acc["status"], "ACCEPTED");
    // B 收到 FriendAccepted。
    let ev_b2 = collect_until(&mut ui_b, Duration::from_secs(15), |e| {
        matches!(e, Event::FriendAccepted { .. })
    });
    assert!(ev_b2.iter().any(|e| matches!(e, Event::FriendAccepted { peer_device_id, .. } if peer_device_id == &dev_a)));

    // A 好友列表：dev-b ACCEPTED，携带公钥指纹（规格九）。
    let friends_a = request_data(&mut ui_a, Command::ListFriends);
    let fa = friends_a["friendships"].as_array().expect("friendships").clone();
    assert_eq!(fa.len(), 1, "A 有 1 个好友");
    assert_eq!(fa[0]["status"], "ACCEPTED");
    assert_eq!(fa[0]["peer_device_id"], dev_b);
    let fp = fa[0]["noise_public_key"].as_str().expect("好友公钥指纹");
    assert_eq!(fp.len(), 64, "Noise 公钥指纹 hex64");

    // ---- A 向好友 B 发起直连（不再输入 6 位码）----
    let resp = ui_a
        .request(&Request { id: 500, command: Command::ConnectFriend { device_id: dev_b.clone() } })
        .expect("ConnectFriend");
    assert!(resp.ok, "ConnectFriend 失败: {:?}", resp.error);

    // ---- B 收到 IncomingConnectionRequest（来自 A）----
    let ev_b3 = collect_until(&mut ui_b, Duration::from_secs(20), |e| {
        matches!(e, Event::IncomingConnectionRequest { .. } | Event::Error { .. })
    });
    assert_no_error(&ev_b3, "B 连接请求阶段");
    let req = ev_b3
        .iter()
        .find_map(|e| match e {
            Event::IncomingConnectionRequest { session_id, from_device_id, from_name, .. } => {
                Some((session_id.clone(), from_device_id.clone(), from_name.clone()))
            }
            _ => None,
        })
        .expect("B 必须收到 IncomingConnectionRequest");
    assert_eq!(req.1, dev_a, "请求来自 A");
    assert_eq!(req.2, "Alice-PC", "from_name 来自 Registry 设备名");

    // ---- B 接受直连请求 → 双端全流程 → CONNECTED ----
    let resp = ui_b
        .request(&Request { id: 600, command: Command::AcceptConnectionRequest { session_id: req.0.clone() } })
        .expect("AcceptConnectionRequest");
    assert!(resp.ok, "接受直连失败: {:?}", resp.error);

    let deadline = Instant::now() + FRIEND_TIMEOUT;
    let mut ev_a: Vec<Event> = Vec::new();
    let mut ev_b: Vec<Event> = Vec::new();
    let mut a_done = false;
    let mut b_done = false;
    while Instant::now() < deadline && !(a_done && b_done) {
        if !a_done {
            if let Some(ServerMessage::Event(ev)) = ui_a.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    a_done = true;
                }
                ev_a.push(ev);
            }
        }
        if !b_done {
            if let Some(ServerMessage::Event(ev)) = ui_b.wait_message(Duration::from_millis(50)) {
                if matches!(&ev, Event::Connected { .. } | Event::Error { .. }) {
                    b_done = true;
                }
                ev_b.push(ev);
            }
        }
    }
    assert!(a_done && b_done, "双端须 CONNECTED（a_done={a_done} b_done={b_done}）\nA: {:?}\nB: {:?}",
        ev_a.iter().map(event_name).collect::<Vec<_>>(),
        ev_b.iter().map(event_name).collect::<Vec<_>>());
    assert_no_error(&ev_a, "A 连接阶段");
    assert_no_error(&ev_b, "B 连接阶段");

    let connected_of = |evs: &[Event], who: &str| -> (String, String, String) {
        evs.iter()
            .find_map(|e| match e {
                Event::Connected { peer_device_id, local_overlay_ip, peer_overlay_ip } => {
                    Some((peer_device_id.clone(), local_overlay_ip.clone(), peer_overlay_ip.clone()))
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("{who} 必须收到 Connected"))
    };
    let (a_peer, a_local, a_peer_ip) = connected_of(&ev_a, "A");
    let (b_peer, b_local, b_peer_ip) = connected_of(&ev_b, "B");
    assert_eq!(a_peer, dev_b, "A 对端 = B");
    assert_eq!(b_peer, dev_a, "B 对端 = A");
    assert_eq!(a_peer_ip, b_local);
    assert_eq!(b_peer_ip, a_local);
    let a_ip: Ipv4Addr = a_local.parse().expect("A IP");
    let b_ip: Ipv4Addr = b_local.parse().expect("B IP");
    assert_ne!(a_ip, b_ip, "Controller IPAM 不同 IP（规格六）");

    // ---- 加密 overlay 双向 ping（好友连接后的 Encrypted overlay ping）----
    let mock_a = agent_a.mock_overlay().expect("A mock");
    let mock_b = agent_b.mock_overlay().expect("B mock");
    assert!(mock_a.is_up() && mock_b.is_up(), "双端 Overlay up");
    assert_eq!(mock_a.routes_installed(), vec![b_ip], "A 侧 /32 路由");
    assert_eq!(mock_b.routes_installed(), vec![a_ip], "B 侧 /32 路由");

    mock_a.inject_outgoing(user_ping(a_ip, b_ip, 0x0A0B, 1));
    mock_b.inject_outgoing(user_ping(b_ip, a_ip, 0x0B0A, 1));
    // A 侧：A 请求的应答（B 内核语义）+ B 的 ping 请求到达 A。
    wait_injected_all(
        &mock_a,
        vec![
            Box::new(move |p| is_echo_reply(p, 0x0A0B, 1) && pkt_src_dst(p) == (b_ip, a_ip)),
            Box::new(move |p| is_request(p, 0x0B0A) && pkt_src_dst(p) == (b_ip, a_ip)),
        ],
        Duration::from_secs(10),
        "A 未完成加密 ping 往返",
    );
    // B 侧：B 请求的应答（A 内核语义）+ A 的 ping 请求到达 B。
    wait_injected_all(
        &mock_b,
        vec![
            Box::new(move |p| is_echo_reply(p, 0x0B0A, 1) && pkt_src_dst(p) == (a_ip, b_ip)),
            Box::new(move |p| is_request(p, 0x0A0B) && pkt_src_dst(p) == (a_ip, b_ip)),
        ],
        Duration::from_secs(10),
        "B 未完成加密 ping 往返",
    );

    // ---- 状态机收敛：CONNECTED ----
    wait_state(&mut ui_a, AgentState::Connected, Duration::from_secs(5));
    wait_state(&mut ui_b, AgentState::Connected, Duration::from_secs(5));

    // ---- 断开（A 取消）→ A 回 READY；B 侧 MVP 无 keepalive 传播，由 B 主动取消 ----
    let resp = ui_a.request(&Request { id: 700, command: Command::CancelSession }).expect("Cancel");
    assert!(resp.ok);
    let ev_a_end = collect_until(&mut ui_a, Duration::from_secs(10), |e| {
        matches!(e, Event::Disconnected { .. })
    });
    // Disconnected/FriendDisconnected 背靠背发出；再排空管道尾部。
    let ev_a_tail = collect_until(&mut ui_a, Duration::from_secs(2), |_| false);
    let ev_a_all: Vec<Event> = ev_a_end.into_iter().chain(ev_a_tail).collect();
    assert!(ev_a_all.iter().any(|e| matches!(e, Event::Disconnected { .. })), "取消须发 Disconnected");
    assert!(
        ev_a_all.iter().any(|e| matches!(e, Event::FriendDisconnected { .. })),
        "好友会话断开须发 FriendDisconnected"
    );
    wait_state(&mut ui_a, AgentState::Ready, Duration::from_secs(5));
    let resp = ui_b.request(&Request { id: 701, command: Command::CancelSession }).expect("Cancel B");
    assert!(resp.ok);
    wait_state(&mut ui_b, AgentState::Ready, Duration::from_secs(5));

    // ---- 清理 ----
    agent_a.shutdown();
    agent_b.shutdown();
    server_a.stop();
    server_b.stop();
    let _ = std::fs::remove_dir_all(&run_dir);
}
