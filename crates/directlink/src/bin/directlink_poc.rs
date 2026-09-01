//! directlink-poc：M0-4 双机实测 PoC 工具（普通人可用）。
//!
//! 兜底纪律：本工具只含 DirectLink/UDP 直连路径——**无** N2N / Supernode /
//! Cloudflare Relay / TURN / TCP Relay，P2P 失败必然显式 FAIL，绝无中继兜底。
//!
//! M0-5：Session Code v4（`k` = creator X25519 静态公钥）；Track B 连接后
//! 自动完成 Noise_IK 握手，数据面全程加密（防重放 + 10min/1GB 重密钥）。
//!
//! 用法（三种模式）：
//!
//! ```text
//! # 单次连接（用户找朋友）：电脑 A 生成 Code，电脑 B join Code，自动完成
//! directlink-poc.exe create --track b [--port 42000] [--keepalive-ms 15000]
//! directlink-poc.exe join <code>  [--port 42000] [--hold-min 10] [--roam-test] [--mtu-test]
//!
//! # Track A（标准 ICE）需要 answer 回传（ICE 双向凭据是协议要求）：
//! A: directlink-poc.exe create --track a            → 输出 Code
//! B: directlink-poc.exe join <code>                 → 输出 Answer Code
//! A: directlink-poc.exe create --track a --answer <answer-code>
//!
//! # 批量矩阵（两端同跑，exchange 目录自动交换，20 轮独立连接重建 + 汇总）
//! A 机: directlink-poc.exe matrix --track b --rounds 20 --exchange <dir> --side a
//! B 机: directlink-poc.exe matrix --track b --rounds 20 --exchange <dir> --side b
//! ```
//!
//! 输出（Final Gate 证据）：device/候选（host+srflx+STUN server）/Observed
//! Mapping 明细/selected pair 类型/connect 时延/RTT P50/P95/loss/jitter/TX/RX。

// result.json / summary 的 json! 字段很多，默认 128 层宏展开不够。
#![recursion_limit = "256"]

use directlink::crypto::StaticIdentity;
use directlink::crypto::keys::hex as key_hex;
use directlink::ice::candidate::primary_local_ipv4;
use directlink::ice::candidate::CandidateKind;
use directlink::ice::stun::{new_txid, StunAttr, StunMessage, BINDING_RESPONSE};
use directlink::ice::webrtc_track::WebRtcIceAgent;
use directlink::transport::DirectLinkTransport;
use serde::{Deserialize, Serialize};
use std::io::{BufRead, Write};
use std::net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use transport_api::{Endpoint, Ipv4Packet, PeerHints, PeerId, TransportConfig, TransportProvider};

const PEER: &str = "remote"; // create 端 accept 的 peer id
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
/// 单次 join 的 smoke 包数（§一：第一版判定纯连通 = 20/20 全收）。
const JOIN_SMOKE_N: usize = 20;
/// matrix 每轮 smoke 包数。
const MATRIX_SMOKE_N: usize = 10;

// ---------- Session Code（base64url(JSON)） ----------

/// M0-4R.1 §二：Session Code——带 schema 版本与生命周期（10 分钟），
/// 禁止无限期复用旧 Code / 旧公网映射打洞。v3 起连接码用紧凑 wire 格式
/// （见 WireOffer），内部结构仍为本 CodeOffer。
/// v4（M0-5）：新增 `k`——creator 静态公钥（hex 64 字符）。join 端用它做
/// Noise IK 握手的 responder 公钥绑定：篡改已预期的 responder static public
/// key 会导致握手失败，证明握手能检测 expected-key mismatch。
/// 注意：k 的真实性依赖传输通道（PoC 为人工转述 Code），Noise IK 本身
/// 不解决 signaling 公钥替换/中间人问题——公钥真实性须由 Controller
/// 身份系统提供（Controller MVP 起 k 改由注册表分发）。
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodeOffer {
    schema_version: u8,
    session_id: String,
    issued_at_ms: u64,
    expires_at_ms: u64,
    nonce: String,
    creator_device_id: String,
    track: char,
    /// NAT 映射观测（Track B；Track A 记 srflx 明细）
    nat: String,
    /// Track A 凭据（Track B 为空）
    ufrag: String,
    pwd: String,
    /// M0-5 v4：creator X25519 静态公钥指纹（hex 小写 64 字符；Track A 为空）
    #[serde(default)]
    k: String,
    host_candidates: Vec<Endpoint>,
    srflx_candidates: Vec<Endpoint>,
}

const CODE_SCHEMA_VERSION: u8 = 4;
/// PoC 默认有效期 10 分钟（§二）。
const CODE_TTL_MS: u64 = 10 * 60 * 1000;
/// §三：整个 code 最大长度（base64url 字符）。
const CODE_MAX_CHARS: usize = 8192;
/// §三：candidate 数量上限（host + srflx 合计）。
const CODE_MAX_CANDIDATES: usize = 16;

// ---------- v3 紧凑 wire 格式（只用于 base64url 连接码；CodeOffer/校验逻辑不变） ----------
// 目标：朋友微信粘贴不截断。手段：字段名单字符、IPv4→u32 数值、候选取 [ip_u32, port]
// 数组对、空字符串省略、host 候选只发**物理接口**（虚拟接口地址对对端永远不可达，
// 纯冗余——发送侧裁剪，本地 gathering/降权逻辑不受影响，§八语义保持）。

#[derive(serde::Serialize, serde::Deserialize)]
struct WireOffer {
    v: u8,
    sid: String,
    iat: u64,
    eat: u64,
    n: String,
    dev: String,
    t: char,
    /// M0-5 v4：creator 静态公钥（hex 64；Track A 空省略）
    #[serde(default, skip_serializing_if = "String::is_empty")]
    k: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    na: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    u: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    p: String,
    h: Vec<[u32; 2]>,
    s: Vec<[u32; 2]>,
}

/// IPv4 ↔ wire 数值（两端对称 roundtrip，与字节序无关）。
fn ip_to_wire(ip: &str) -> Option<u32> {
    ip.parse::<std::net::Ipv4Addr>().ok().map(|a| u32::from_be_bytes(a.octets()))
}
fn ip_from_wire(v: u32) -> String {
    std::net::Ipv4Addr::from(u32::to_be_bytes(v)).to_string()
}

fn eps_to_wire(eps: &[Endpoint]) -> Vec<[u32; 2]> {
    eps.iter().filter_map(|e| ip_to_wire(&e.ip).map(|ip| [ip, e.port as u32])).collect()
}

/// CodeOffer → base64url 连接码（v3）。序列化失败不可能发生（纯内存结构），
/// 保守返回空串——对端按 empty_code 拒绝，不 panic。
fn encode_code(o: &CodeOffer) -> String {
    let w = WireOffer {
        v: CODE_SCHEMA_VERSION,
        sid: o.session_id.clone(),
        iat: o.issued_at_ms,
        eat: o.expires_at_ms,
        n: o.nonce.clone(),
        dev: o.creator_device_id.clone(),
        t: o.track,
        k: o.k.clone(),
        na: o.nat.clone(),
        u: o.ufrag.clone(),
        p: o.pwd.clone(),
        h: eps_to_wire(&o.host_candidates),
        s: eps_to_wire(&o.srflx_candidates),
    };
    b64encode(&serde_json::to_vec(&w).unwrap_or_default())
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64encode(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64URL[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64URL[n as usize & 63] as char } else { '=' });
    }
    out.trim_end_matches('=').to_string()
}

// ---------- Session Code 校验（M0-4R.1 §三/§四/§五，全程不 panic） ----------

/// 统一错误码：SESSION_CODE_INVALID（附 reason）/ SESSION_CODE_EXPIRED。
#[derive(Debug, Clone)]
struct CodeParseError {
    code: &'static str,
    reason: String,
}

fn code_invalid(reason: impl Into<String>) -> CodeParseError {
    CodeParseError { code: "SESSION_CODE_INVALID", reason: reason.into() }
}

/// session_id / nonce 格式：非空、≤64 字符、ASCII 字母数字与 - _。
fn code_id_ok(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// 生成 session_id 与 nonce（零依赖：系统时钟毫秒/纳秒 hex；PoC 用途足够）。
/// v3：尽量短（连接码总长敏感）。
fn make_code_header() -> (String, u64, u64, String) {
    let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let issued = d.as_millis() as u64;
    let session_id = format!("{:x}{:08x}", issued, d.subsec_nanos());
    let nonce = format!("{:08x}", (d.subsec_nanos() as u128 ^ d.as_nanos()) as u32);
    (session_id, issued, issued + CODE_TTL_MS, nonce)
}

/// §四：远端候选是**不可信输入**——只当作待探测 endpoint。
/// 拒绝：非法 IP / IPv6（PoC 只做 IPv4）/ loopback / unspecified（含 0.0.0.0/8）/
/// multicast / broadcast / port 0；**保留私网 unicast**（10/8、172.16/12、192.168/16，
/// Same LAN host↔host 必需，§五）。去重（按 ip:port）。全程记录拒绝原因。
fn filter_remote_candidates(
    eps: &[Endpoint],
) -> (Vec<Endpoint>, Vec<(String, String)>) {
    let mut keep: Vec<Endpoint> = Vec::new();
    let mut rejected: Vec<(String, String)> = Vec::new();
    for e in eps {
        let tag = format!("{}:{} ({})", e.ip, e.port, e.kind);
        let ip: std::net::IpAddr = match e.ip.parse() {
            Ok(i) => i,
            Err(_) => {
                rejected.push((tag, "invalid_ip_format".into()));
                continue;
            }
        };
        let v4 = match ip {
            IpAddr::V6(_) => {
                rejected.push((tag, "ipv6_unsupported".into())); // 含 IPv6 loopback/multicast/::
                continue;
            }
            IpAddr::V4(v) => v,
        };
        if v4.is_loopback() {
            rejected.push((tag, "loopback_forbidden".into()));
            continue;
        }
        if v4.is_unspecified() || v4.octets()[0] == 0 {
            rejected.push((tag, "unspecified_forbidden".into())); // 0.0.0.0 及 0.0.0.0/8
            continue;
        }
        if v4.is_multicast() {
            rejected.push((tag, "multicast_forbidden".into())); // 224.0.0.0/4
            continue;
        }
        if v4.is_broadcast() {
            rejected.push((tag, "broadcast_forbidden".into())); // 255.255.255.255
            continue;
        }
        if e.port == 0 {
            rejected.push((tag, "port_zero_forbidden".into()));
            continue;
        }
        if !keep.iter().any(|k| k.ip == e.ip && k.port == e.port) {
            keep.push(e.clone()); // §三：重复 candidate 去重
        }
    }
    (keep, rejected)
}

/// §三：结构性校验 + 过期检查 + 候选过滤。任何一步失败统一返回
/// SESSION_CODE_INVALID（附 reason）或 SESSION_CODE_EXPIRED，绝不 panic。
fn validate_offer(mut o: CodeOffer) -> Result<(CodeOffer, Vec<(String, String)>), CodeParseError> {
    if o.schema_version != CODE_SCHEMA_VERSION {
        return Err(code_invalid(format!(
            "schema_version_unsupported（本工具支持 v{CODE_SCHEMA_VERSION}，收到 v{}——请对方用同版本工具重新生成）",
            o.schema_version
        )));
    }
    if !code_id_ok(&o.session_id) {
        return Err(code_invalid("session_id_format_invalid"));
    }
    if !code_id_ok(&o.nonce) {
        return Err(code_invalid("nonce_format_invalid"));
    }
    if o.creator_device_id.is_empty() || o.creator_device_id.len() > 64 {
        return Err(code_invalid("creator_device_id_invalid"));
    }
    if o.track != 'a' && o.track != 'b' {
        return Err(code_invalid("track_invalid"));
    }
    // M0-5 v4：Track B 连接码必须携带 creator 静态公钥（Noise IK responder 绑定）。
    // Track A 冻结为连通性基线（无加密数据面），k 允许为空。
    if o.track == 'b' {
        if o.k.is_empty() {
            return Err(code_invalid("static_key_missing（Track B 需要 v4 连接码携带 k 公钥——请对方用 v4 工具重新生成）"));
        }
        if key_hex::decode_key32(&o.k).is_none() {
            return Err(code_invalid("static_key_invalid（k 应为 64 字符 hex 公钥）"));
        }
    }
    if o.issued_at_ms == 0 || o.expires_at_ms == 0 {
        return Err(code_invalid("lifetime_missing"));
    }
    if o.expires_at_ms <= o.issued_at_ms {
        return Err(code_invalid("lifetime_inverted"));
    }
    let now = now_ms();
    if now > o.expires_at_ms as u128 {
        let over_min = (now - o.expires_at_ms as u128) / 60_000;
        return Err(CodeParseError {
            code: "SESSION_CODE_EXPIRED",
            reason: format!("连接码已于 {} 分钟前过期（禁止复用旧公网映射，请对方重新生成）", over_min.max(1)),
        });
    }
    if o.host_candidates.len() + o.srflx_candidates.len() > CODE_MAX_CANDIDATES {
        return Err(code_invalid(format!(
            "too_many_candidates（上限 {CODE_MAX_CANDIDATES}，收到 {}）",
            o.host_candidates.len() + o.srflx_candidates.len()
        )));
    }
    let (host, mut rejected) = filter_remote_candidates(&o.host_candidates);
    let (srflx, rej2) = filter_remote_candidates(&o.srflx_candidates);
    rejected.extend(rej2);
    if host.is_empty() && srflx.is_empty() {
        let reasons = rejected.iter().map(|(_, r)| r.as_str()).collect::<Vec<_>>().join(",");
        return Err(code_invalid(format!("all_candidates_rejected [{reasons}]")));
    }
    o.host_candidates = host;
    o.srflx_candidates = srflx;
    Ok((o, rejected))
}

/// join/answer 入口：base64url → JSON → 校验。任何非法输入显式报错不 panic。
/// 成功返回（过滤后的 offer, 被拒候选明细）——供 candidate trace（§七）。
fn parse_session_code(raw: &str) -> Result<(CodeOffer, Vec<(String, String)>), CodeParseError> {
    let raw = raw.trim().trim_matches('"').trim_matches('\'');
    if raw.is_empty() {
        return Err(code_invalid("empty_code"));
    }
    if raw.len() > CODE_MAX_CHARS {
        return Err(code_invalid(format!("code_too_long（上限 {CODE_MAX_CHARS} 字符，收到 {}）", raw.len())));
    }
    let decoded = b64decode(raw).ok_or_else(|| code_invalid("base64_decode_failed（复制不完整或被改写）"))?;
    // v3 紧凑 wire 格式：字段名单字符 + IPv4→u32 + 候选 [ip_u32, port] 对。
    let w: WireOffer = serde_json::from_slice(&decoded)
        .map_err(|e| code_invalid(format!("json_parse_failed（{e}）")))?;
    let offer = CodeOffer {
        schema_version: w.v,
        session_id: w.sid,
        issued_at_ms: w.iat,
        expires_at_ms: w.eat,
        nonce: w.n,
        creator_device_id: w.dev,
        track: w.t,
        nat: w.na,
        ufrag: w.u,
        pwd: w.p,
        k: w.k,
        host_candidates: w.h.iter().map(|c| Endpoint {
            ip: ip_from_wire(c[0]),
            port: c[1] as u16,
            kind: "host".into(),
        }).collect(),
        srflx_candidates: w.s.iter().map(|c| Endpoint {
            ip: ip_from_wire(c[0]),
            port: c[1] as u16,
            kind: "server_reflexive".into(),
        }).collect(),
    };
    let (o, rejected) = validate_offer(offer)?;
    Ok((o, rejected))
}

fn b64decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        B64URL.iter().position(|&x| x == c).map(|p| p as u32)
    };
    let bytes: Vec<u8> = s.trim_end_matches('=').bytes().collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    Some(out)
}

// ---------- 公共 ----------

/// 朋友模式标记（main 按 --friend 设置；ui() 只在该模式下输出 [UI] 行）。
static FRIEND_MODE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 朋友模式关键状态行（M0-4R.1 §十）：ps1 只把这些行显示给朋友，
/// 其余技术细节全部留在 client.log。
fn ui(line: &str) {
    if FRIEND_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        println!("[UI] {line}");
    }
}

/// 真实测试 Profile（§十三）：只给预期参考与日志标签，不改变协议行为。
fn profile_expected(profile: &str) -> &'static str {
    match profile {
        "same-lan" => "host↔host（同网段 host 候选优先）",
        "home-mobile" => "srflx 参与（一端在 NAT 后）",
        "home-home" => "srflx↔srflx 或其他 ICE 可用 pair",
        _ => "",
    }
}

fn now_ms() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0)
}

/// 合法 IPv4 数据帧（transport 分派要求：len ≥20 且 version=4）。
fn ipv4_frame(payload: &[u8]) -> Ipv4Packet {
    let mut b = vec![0u8; 20 + payload.len()];
    b[0] = 0x45;
    b[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
    b[8] = 64; // TTL
    b[20..].copy_from_slice(payload);
    Ipv4Packet { bytes: b }
}

struct Args {
    port: u16,
    keepalive_ms: u64,
    hold_min: u64,
    roam: bool,
    mtu_test: bool,
    rounds: usize,
    exchange: PathBuf,
    answer: Option<String>,
    stun: Vec<String>,
    /// M0-4R：写 result.json 报告（--report）
    report: bool,
    /// 报告输出目录（--out-dir，默认 results/）
    out_dir: PathBuf,
    /// 测试场景标识（--test-id，如 "same-lan-tb-01"）
    test_id: String,
    /// idle mapping 对照组时点（--idle-test 30,60,120；join Track B 专用）
    idle_test: Vec<u64>,
    /// M0-4R.1 §十三：测试场景（same-lan | home-mobile | home-home；只影响
    /// 标签与预期记录，不改协议逻辑）
    profile: String,
    /// M0-4R.1 §一：round_success 的 smoke 阈值（百分比，默认 100 = 20/20）
    smoke_threshold: u32,
}

fn arg(name: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn has_flag(name: &str) -> bool {
    std::env::args().any(|a| a == name)
}

fn parse_common() -> Args {
    Args {
        port: arg("--port").map(|v| v.parse().expect("--port 数字")).unwrap_or(42000),
        keepalive_ms: arg("--keepalive-ms").map(|v| v.parse().expect("数字")).unwrap_or(15_000),
        hold_min: arg("--hold-min").map(|v| v.parse().expect("数字")).unwrap_or(0),
        roam: has_flag("--roam-test"),
        mtu_test: has_flag("--mtu-test"),
        rounds: arg("--rounds").map(|v| v.parse().expect("数字")).unwrap_or(20),
        exchange: PathBuf::from(arg("--exchange").unwrap_or_else(|| ".".into())),
        answer: arg("--answer"),
        stun: arg("--stun")
            .map(|s| s.split(',').map(str::trim).map(String::from).collect())
            .unwrap_or_default(),
        report: has_flag("--report"),
        out_dir: PathBuf::from(arg("--out-dir").unwrap_or_else(|| "results".into())),
        test_id: arg("--test-id").unwrap_or_else(|| "unnamed".into()),
        idle_test: arg("--idle-test")
            .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
            .unwrap_or_default(),
        profile: arg("--profile").unwrap_or_else(|| "unspecified".into()),
        smoke_threshold: arg("--smoke-threshold").map(|v| v.parse().expect("--smoke-threshold 数字")).unwrap_or(100),
    }
}

fn device_id() -> String {
    arg("--id").unwrap_or_else(|| std::env::var("COMPUTERNAME").unwrap_or_else(|_| "host".into()))
}

/// Observed Mapping 打印（不宣称 cone 类型——RFC 5780 未做）。
fn print_nat(kind: &str, classification: &str, observed: &[(SocketAddrV4, SocketAddrV4)]) {
    println!("[NAT] {kind}: {classification}");
    for (server, mapped) in observed {
        println!("[NAT]   Observed Mapping: {server} → {mapped}");
    }
}

// ---------- M0-4R result.json 报告 ----------

/// 失败阶段（M0-4R §五：禁止只有 FAIL）。M0-5 新增 Noise 握手阶段。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    Stun,
    CandidateExchange,
    Punch,
    NoiseHandshake,
    ConnectivityCheck,
    DataSmoke,
    None,
}

impl Stage {
    fn as_str(&self) -> &'static str {
        match self {
            Stage::Stun => "stun_failed",
            Stage::CandidateExchange => "candidate_exchange_failed",
            Stage::Punch => "punch_timeout",
            Stage::NoiseHandshake => "noise_handshake_failed",
            Stage::ConnectivityCheck => "connectivity_check_failed",
            Stage::DataSmoke => "data_smoke_failed",
            Stage::None => "none",
        }
    }
}

/// M0-5：生成本端静态密钥身份。失败显式退出（CSPRNG 故障属环境问题），
/// 不 panic——朋友机双击窗口闪退无法回报问题。
fn gen_identity(id: &str) -> StaticIdentity {
    match StaticIdentity::generate(id) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("\nFAIL: 静态密钥生成失败（CSPRNG 不可用？）: {e:?}");
            ui("RESULT: FAIL:STATIC_KEYGEN_FAILED");
            std::process::exit(1);
        }
    }
}

/// M0-5：打印 + 记录 Noise 通道状态（established/epoch/统计——报告证据）。
fn attach_crypto_report(dl: &DirectLinkTransport, role: &str, rec: Option<&mut serde_json::Value>) {
    let report = dl.crypto_report(&PeerId(PEER.into()));
    let est = report.get("established").and_then(|v| v.as_bool()).unwrap_or(false);
    if est {
        let epoch = report.get("epoch_id").and_then(|v| v.as_u64()).unwrap_or(0);
        let rekeys = report.get("rekey_count").cloned().unwrap_or(serde_json::json!(0));
        println!("[noise] ✓ {role}: IK 通道已建立 epoch={epoch} rekey_count={rekeys}（数据面已加密）");
    } else {
        println!("[noise] {role}: 通道未建立（established=false）");
    }
    if let Some(r) = rec {
        r["crypto"] = report;
    }
}

/// 写 result.json（--report 开启时）。失败不 panic（报告不能拖垮测试流程）。
fn write_result(out_dir: &PathBuf, filename: &str, record: serde_json::Value) {
    let p = out_dir.join(filename);
    if let Err(e) = std::fs::create_dir_all(out_dir).and_then(|_| {
        std::fs::write(&p, serde_json::to_vec_pretty(&record).unwrap_or_default())
    }) {
        eprintln!("[report] 写 {p:?} 失败: {e}");
    } else {
        println!("[report] {}", p.display());
    }
}

fn iso_timestamp() -> String {
    iso_from_epoch_ms(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0))
}

fn iso_from_epoch_ms(ms: u64) -> String {
    // 无 chrono 依赖：epoch 秒换算 UTC（PoC 精度到秒即可，另存 epoch_ms）
    let secs = ms / 1000;
    let days = secs / 86400;
    let (y, mo, d) = civil_from_days(days as i64);
    let rem = secs % 86400;
    format!("{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// Howard Hinnant civil_from_days（公历换算，公共领域算法）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 伪随机毫秒（500–3000）：系统时间低位；避免引 rand 破坏零依赖纪律。
fn jitter_ms() -> u64 {
    500 + (SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().subsec_nanos() as u64) % 2501
}

// ---------- M0-4R.1 §九 环境快照 / §十四 公平参数 ----------

/// 外部命令捕获（环境快照专用；失败返回 None 不影响测试流程）。
/// CREATE_NO_WINDOW：朋友双击运行时避免弹出黑框。
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}

fn os_version() -> String {
    run_capture("cmd", &["/c", "ver"]).unwrap_or_else(|| std::env::consts::OS.to_string())
}

fn windows_firewall_enabled() -> Option<bool> {
    let s = run_capture("powershell", &["-NoProfile", "-Command",
        "if ((Get-NetFirewallProfile | Where-Object Enabled -eq $true | Measure-Object).Count -gt 0) { 'true' } else { 'false' }",
    ])?;
    Some(s.contains("true"))
}

fn network_profile() -> Option<String> {
    // 语言无关：返回 Private / Public / DomainAuthenticated 枚举值
    run_capture("powershell", &["-NoProfile", "-Command",
        "(Get-NetConnectionProfile | Select-Object -First 1).NetworkCategory"])
}

fn git_commit() -> String {
    if let Some(c) = option_env!("GIT_COMMIT") {
        return c.to_string();
    }
    run_capture("git", &["rev-parse", "--short", "HEAD"]).unwrap_or_else(|| "unknown".into())
}

/// §九：环境快照（全量写 network_snapshot.json；result/summary 内嵌同一对象）。
fn env_snapshot(track: char, stun: &str) -> serde_json::Value {
    let ifaces = directlink::ice::ifinfo::list_ipv4_interfaces();
    let vm_detected = ifaces.iter().any(|i| i.kind.is_virtual());
    let vpn_detected = ifaces.iter().any(|i| {
        let d = i.descr.to_lowercase();
        ["vpn", "wireguard", "tailscale", "tunnel", "wintun", "tap"].iter().any(|k| d.contains(k))
    });
    let primary = primary_local_ipv4();
    let default_if = ifaces.iter().find(|i| Some(i.ip) == primary).map(|i| {
        serde_json::json!({
            "index": i.index, "name": i.descr, "ip": i.ip.to_string(),
            "kind": i.kind.as_str(),
            "class": if i.kind.is_virtual() { "virtual" } else { "physical" },
        })
    });
    serde_json::json!({
        "os_version": os_version(),
        "app_version": env!("CARGO_PKG_VERSION"),
        "git_commit": git_commit(),
        "track_version": if track == 'a' { "rtc-ice-0.20.4/m0-4r.1" } else { "minimal-punch-agent/m0-4r.1" },
        "stun_server": stun,
        "local_interfaces": ifaces.iter().map(|i| serde_json::json!({
            "index": i.index, "name": i.descr, "ip": i.ip.to_string(),
            "kind": i.kind.as_str(), "if_type": i.if_type, "oper_up": i.oper_up,
            "class": if i.kind.is_virtual() { "virtual" } else { "physical" },
        })).collect::<Vec<_>>(),
        "default_route_interface": default_if,
        "windows_firewall_enabled": windows_firewall_enabled(),
        "network_profile": network_profile(),
        "vm_detected": vm_detected,
        "vpn_detected": vpn_detected,
        "timestamp": iso_timestamp(),
    })
}

/// §十四：Track A/B 公平参数全量记录进 result.json（对比时差异可见——
/// 不允许给 A 5s / B 2s timeout 后比较成功率）。
fn test_params_json(args: &Args, smoke_n: usize) -> serde_json::Value {
    serde_json::json!({
        "stun_servers": args.stun,
        "smoke_packets": smoke_n,
        "smoke_threshold_percent": args.smoke_threshold,
        "check_timeout_ms": CHECK_TIMEOUT.as_millis() as u64,
        "rebuild_jitter_ms": [500, 3000],
        "keepalive_interval_ms": args.keepalive_ms,
        "rounds": args.rounds,
        "session_code_ttl_minutes": CODE_TTL_MS / 60_000,
        "session_code_schema_version": CODE_SCHEMA_VERSION,
        "noise": {
            "pattern": "Noise_IK_25519_ChaChaPoly_BLAKE2s",
            "role_binding": "join=initiator, create=responder",
            "session_code_k_field": "creator X25519 static pubkey (hex64)",
            "replay_window_bits": 2048,
            "rekey_after_ms": 600_000,
            "rekey_after_bytes": 1073741824,
            "rekey_grace_ms": 5000,
        },
        "profile": args.profile,
        "expected_selected_pair": profile_expected(&args.profile),
    })
}

/// §一：round_success = P2P path established AND selected_pair confirmed
/// AND smoke_packets_rx ≥ expected × threshold（默认 threshold=100% 即 20/20）。
fn round_success(connect: bool, smoke_rx: usize, expected: usize, threshold_pct: u32) -> bool {
    connect && (smoke_rx as f64) >= (expected as f64 * threshold_pct as f64 / 100.0).ceil()
}

async fn start_transport_b(port: u16, keepalive_ms: u64, stun: &[String]) -> DirectLinkTransport {
    let dl = DirectLinkTransport::new();
    let mut params = serde_json::json!({ "listen_port": port, "keepalive_interval_ms": keepalive_ms });
    if !stun.is_empty() {
        params["stun_servers"] = serde_json::json!(stun);
    }
    // 启动失败（端口占用等）是常见环境问题：显式报错退出，不 panic（窗口不闪退）
    if let Err(e) = dl.start(TransportConfig { name: "directlink".into(), params }).await {
        let d = format!("{e:?}");
        if d.contains("10048") {
            eprintln!("\nFAIL: 端口 {port} 已被占用——通常是上一次测试的窗口还在运行（先关掉它），或另一个程序占用了该端口。");
        } else {
            eprintln!("\nFAIL: transport start 失败：{d}");
        }
        std::process::exit(1);
    }
    let obs = dl.nat_mapping().await;
    match obs {
        Some(o) => print_nat("Track B (MinimalPunchAgent)", &format!("{:?}", o.classification), &o.observed),
        None => println!("[NAT] Track B: UNKNOWN（STUN 不可达；Observed Mapping 不可得）"),
    }
    for c in dl.local_candidates() {
        // §七：候选带接口信息——punch timeout 时能立即看出在打什么地址
        println!("[cand] host {}:{} (base {}:{}) [{}:{}{}]",
            c.addr.ip(), c.addr.port(), c.base.ip(), c.base.port(), c.iface_kind, c.if_name,
            if c.is_virtual { ",virtual" } else { "" });
    }
    for c in dl.srflx_candidates() {
        println!("[cand] srflx {}:{} (base {}:{})", c.addr.ip(), c.addr.port(), c.base.ip(), c.base.port());
    }
    dl
}

/// Track A agent 创建 + srflx（同一 socket）。
fn make_agent_a(port: u16, stun: &[String]) -> WebRtcIceAgent {
    let ip = primary_local_ipv4().unwrap_or(std::net::Ipv4Addr::LOCALHOST);
    let a = WebRtcIceAgent::new(port, ip).expect("Track A agent 创建");
    if let Some(s) = stun.first() {
        if let Some(server) = s.to_socket_addrs().ok().and_then(|mut i| i.next()) {
            if let SocketAddr::V4(server) = server {
                match a.gather_srflx(server) {
                    Ok(mapped) => {
                        println!("[NAT] Track A (rtc-ice): Observed Mapping: {server} → {mapped}");
                        println!("[NAT] Track A: 同一 socket srflx ✓（local port {}）", a.local_base().port());
                    }
                    Err(e) => println!("[NAT] Track A: srflx 失败（容忍，host 直连仍可）: {e}"),
                }
            }
        }
    }
    println!("[cand] Track A host {}:{} (socket 同端口)", a.local_base().ip(), a.local_base().port());
    if let Some(m) = a.srflx_addr() {
        println!("[cand] Track A srflx {m}");
    }
    a
}

fn endpoints_of_a(a: &WebRtcIceAgent) -> (Vec<Endpoint>, Vec<Endpoint>) {
    let host = vec![Endpoint { ip: a.local_base().ip().to_string(), port: a.local_base().port(), kind: "host".into() }];
    let mut srflx = Vec::new();
    if let Some(m) = a.srflx_addr() {
        srflx.push(Endpoint { ip: m.ip().to_string(), port: m.port(), kind: "server_reflexive".into() });
    }
    (host, srflx)
}

// ---------- smoke ping/pong（Track B 走 transport，Track A 走 raw socket） ----------

#[derive(Debug, Default, Clone)]
struct SmokeStats {
    sent: usize,
    recv: usize,
    rtts: Vec<Duration>,
}

impl SmokeStats {
    fn loss(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { (self.sent - self.recv) as f64 / self.sent as f64 * 100.0 }
    }
    fn pct(v: &mut Vec<Duration>, p: f64) -> f64 {
        if v.is_empty() { return 0.0; }
        v.sort();
        v[((v.len() as f64 * p) as usize).min(v.len() - 1)].as_secs_f64() * 1000.0
    }
    fn jitter(&self) -> f64 {
        if self.rtts.len() < 2 { return 0.0; }
        let mut d = Vec::new();
        for w in self.rtts.windows(2) {
            d.push(w[0].abs_diff(w[1]));
        }
        d.iter().sum::<Duration>().as_secs_f64() * 1000.0 / d.len() as f64
    }
    fn report(&self, tag: &str) {
        let mut rtts = self.rtts.clone();
        println!(
            "[{tag}] TX={} RX={} loss={:.1}% rtt P50={:.2}ms P95={:.2}ms jitter={:.2}ms",
            self.sent, self.recv, self.loss(),
            Self::pct(&mut rtts, 0.5), Self::pct(&mut rtts, 0.95), self.jitter()
        );
    }
}

/// join 端：发 N 个 PING 收 PONG（Track B：transport 数据面）。
async fn ping_pong_b(dl: &DirectLinkTransport, n: usize) -> SmokeStats {
    let mut rx = dl.packet_rx(&PeerId(PEER.into())).expect("packet_rx");
    let mut st = SmokeStats { sent: 0, recv: 0, rtts: Vec::new() };
    for i in 0..n {
        let payload = format!("PING-{i}-{}", now_ms());
        if dl.send_packet(PeerId(PEER.into()), ipv4_frame(payload.as_bytes())).await.is_ok() {
            st.sent += 1;
        }
        // 等 PONG（500ms 窗口；期间可能收到对端 PING——忽略，echo 端不主动发 PING）
        let deadline = Instant::now() + Duration::from_millis(500);
        let want = format!("PONG-{i}-");
        loop {
            let now = Instant::now();
            if now >= deadline { break; }
            match tokio::time::timeout(deadline - now, rx.recv()).await {
                Ok(Some(pkt)) => {
                    let text = String::from_utf8_lossy(&pkt[20.min(pkt.len())..]).to_string();
                    if text.starts_with(&want) {
                        let ts: u128 = text.rsplit('-').next().and_then(|s| s.parse().ok()).unwrap_or(0);
                        st.rtts.push(Duration::from_millis((now_ms().saturating_sub(ts)) as u64));
                        st.recv += 1;
                        break;
                    }
                }
                _ => break,
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    st
}

/// echo 端（Track B）：收 PING 回 PONG，直至超时无流量或收到 QUIT。
async fn echo_loop_b(dl: &DirectLinkTransport, idle_timeout: Duration) {
    let Some(mut rx) = dl.packet_rx(&PeerId(PEER.into())) else { return; };
    let deadline = Instant::now() + idle_timeout;
    loop {
        let now = Instant::now();
        if now >= deadline { println!("[create] echo 空闲超时退出"); return; }
        match tokio::time::timeout(deadline - now, rx.recv()).await {
            Ok(Some(pkt)) => {
                let text = String::from_utf8_lossy(&pkt[20.min(pkt.len())..]).to_string();
                if let Some(rest) = text.strip_prefix("PING-") {
                    let _ = dl.send_packet(PeerId(PEER.into()), ipv4_frame(format!("PONG-{rest}").as_bytes())).await;
                }
            }
            _ => continue,
        }
    }
}

/// Track A raw ping/pong。
fn ping_pong_raw(a: &WebRtcIceAgent, remote: SocketAddrV4, n: usize) -> SmokeStats {
    let mut st = SmokeStats { sent: 0, recv: 0, rtts: Vec::new() };
    for i in 0..n {
        let payload = format!("PING-{i}-{}", now_ms());
        if a.raw_send(payload.as_bytes(), remote).is_ok() {
            st.sent += 1;
        }
        let deadline = Instant::now() + Duration::from_millis(500);
        let want = format!("PONG-{i}-");
        loop {
            let now = Instant::now();
            if now >= deadline { break; }
            if let Some((_, pkt)) = a.raw_recv(deadline - now) {
                let text = String::from_utf8_lossy(&pkt).to_string();
                if text.starts_with(&want) {
                    let ts: u128 = text.rsplit('-').next().and_then(|s| s.parse().ok()).unwrap_or(0);
                    st.rtts.push(Duration::from_millis((now_ms().saturating_sub(ts)) as u64));
                    st.recv += 1;
                    break;
                }
            } else { break; }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    st
}

/// Track A raw echo（create/matrix 共用；见 echo_a_for）。

// ---------- main ----------

#[tokio::main]
async fn main() {
    // M0-4R：默认开 directlink 库日志（srflx gathering 失败等 warn 需可见）；
    // RUST_LOG 可覆盖。
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "directlink=info".into()))
        .try_init();
    let args_v: Vec<String> = std::env::args().collect();
    FRIEND_MODE.store(has_flag("--friend"), std::sync::atomic::Ordering::Relaxed);
    println!("== directlink-poc（M0-5 Noise_IK 加密数据面） ==");
    println!("[兜底] N2N=OFF Supernode=OFF CF-Relay=OFF TURN=OFF TCP-Relay=OFF（工具仅含 UDP 直连，失败必显式 FAIL）");
    println!("[加密] Track B 数据面 = Noise_IK_25519_ChaChaPoly_BLAKE2s（Session Code v4 k 字段携带公钥，自动握手/防重放/重密钥）");
    match args_v.get(1).map(String::as_str) {
        Some("create") => create().await,
        Some("join") => {
            let Some(code) = args_v.get(2) else { usage(); return };
            join(code).await;
        }
        Some("matrix") => matrix().await,
        Some("nat-behavior") => cmd_nat_behavior(&parse_common()),
        _ => usage(),
    }
}

fn usage() {
    eprintln!(
        "用法:\n  directlink-poc.exe create --track b|a [--port 42000] [--keepalive-ms 15000] [--mtu-test] [--answer <code>]\n  directlink-poc.exe join <code> [--port 42000] [--keepalive-ms 15000] [--hold-min 10] [--roam-test] [--mtu-test]\n                        [--idle-test 30,60,120] [--report] [--out-dir results] [--test-id <场景标识>]\n  directlink-poc.exe matrix --track b|a --rounds 20 --exchange <dir> --side a|b [--report] [--test-id <场景标识>]\n  （matrix 两端各跑一条命令：A 机 --side a，B 机 --side b；exchange 指向同一目录）\n\nM0-5 加密数据面（Track B）:\n  Session Code v4 携带 creator 静态公钥（k 字段）；join 后自动完成 Noise_IK 握手，\n  数据面全加密（ChaCha20-Poly1305 + 防重放 + 10min/1GB 自动重握手）。\n  result.json 新增 crypto 段（established/epoch/frames_tx/rx/replay_rejected/decrypt_failed）。\n  Track A 冻结为连通性基线，无加密（若最终选 A，加密同样叠加在此轨道）。\n\nM0-4R 报告:\n  --report          每次连接/每轮写 result JSON（join→result.json；matrix→result-rNN.json + summary-a|b.json）\n  --idle-test 30,60,120   连接后停止 Keepalive，分时点探测 NAT mapping 存活（Track B join）\n  --roam-test       网络切换：detect/regather/repunch 分段计时（Track B join）\n  --test-id         场景标识写入报告（如 same-lan-tb-01）\n  --profile same-lan|home-mobile|home-home   测试场景标签与预期（不改协议逻辑）\n  --smoke-threshold 95   round_success 的 smoke 收包阈值百分比（默认 100 = 全收）\n  --friend          朋友模式：只输出 [UI] 关键状态行（run-test.ps1 使用）"
    );
}

// ---------- nat-behavior（M0-4R.1 §十：RFC 5780 可选诊断，不阻塞主线） ----------

/// RFC 5780 NAT Behavior Discovery。
/// 仅当 STUN server 支持 OTHER-ADDRESS/CHANGE-REQUEST 时输出 Mapping/Filtering
/// Behavior 分类；否则明确输出 UNVERIFIED——禁止仅凭一次 STUN 查询宣称 NAT 类型
/// （M0-4 Final Gate 硬规则：Mapping 与 Filtering 是两件不同的事，未做行为实验
/// 前报告一律写 UNVERIFIED + Observed symptom）。
fn cmd_nat_behavior(args: &Args) {
    use std::net::ToSocketAddrs;
    let servers = if args.stun.is_empty() { vec!["stun.l.google.com:19302".to_string()] } else { args.stun.clone() };
    let server = match servers.first().and_then(|s| s.to_socket_addrs().ok())
        .and_then(|mut it| it.find_map(|a| match a { SocketAddr::V4(v4) => Some(v4), _ => None }))
    {
        Some(s) => s,
        None => {
            println!("[nat-behavior] FAIL: STUN server 解析失败");
            return;
        }
    };
    let sock = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            println!("[nat-behavior] FAIL: bind: {e}");
            return;
        }
    };

    // 发一个 Binding Request（可带 CHANGE-REQUEST），等响应（校验 txid）。
    let exchange = |change_ip: bool, change_port: bool| -> Option<StunMessage> {
        let txid = new_txid();
        let mut req = StunMessage::binding_request(txid);
        if change_ip || change_port {
            req.attrs.push(StunAttr::ChangeRequest { change_ip, change_port });
        }
        sock.send_to(&req.encode(), server).ok()?;
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            sock.set_read_timeout(Some((deadline - now).min(Duration::from_millis(500)))).ok()?;
            let mut buf = [0u8; 2048];
            let (n, _) = sock.recv_from(&mut buf).ok()?;
            let Ok(msg) = StunMessage::decode(&buf[..n]) else { continue };
            if msg.txid == txid && msg.msg_type == BINDING_RESPONSE {
                return Some(msg);
            }
        }
    };

    println!("[nat-behavior] server={server}");
    // Test I：普通 Binding → 映射 X1 + 服务器能力（OTHER-ADDRESS）
    let Some(m1) = exchange(false, false) else {
        println!("[nat-behavior] RESULT: UNVERIFIED（Test I 无响应——服务器不可达）");
        return;
    };
    let Some(x1) = m1.get_xor_mapped() else {
        println!("[nat-behavior] RESULT: UNVERIFIED（Test I 无 XOR-MAPPED）");
        return;
    };
    let other = m1.attrs.iter().find_map(|a| match a { StunAttr::OtherAddress(a) => Some(*a), _ => None });
    println!("[nat-behavior] Observed Mapping (Test I): {x1}");
    let Some(other) = other else {
        println!("[nat-behavior] RESULT: UNVERIFIED（服务器不支持 RFC 5780 OTHER-ADDRESS——仅记录 Observed Mapping，不做 behavior 分类）");
        return;
    };
    println!("[nat-behavior] server 支持 RFC 5780（other={other}）");

    // ---- Mapping Behavior（§4.3）：比较对不同目标的映射 ----
    let x2 = exchange(false, true).and_then(|m| m.get_xor_mapped());
    let x3 = exchange(true, true).and_then(|m| m.get_xor_mapped());
    println!("[nat-behavior] Mapping Test II (→other port): {:?}", x2.map(|x| x.to_string()));
    println!("[nat-behavior] Mapping Test III (→other ip:port): {:?}", x3.map(|x| x.to_string()));
    let mapping = match (x2, x3) {
        (Some(x2), Some(x3)) => {
            if x2.port() == x1.port() {
                "Endpoint-Independent Mapping (EIM)"
            } else if x3.ip() == x1.ip() {
                "Address-Dependent Mapping (ADM)"
            } else {
                "Address-and-Port-Dependent Mapping (APDM)"
            }
        }
        _ => "UNVERIFIED（change 测试响应未到达——可能被本端 NAT filtering 拦截，无法区分映射行为）",
    };
    println!("[nat-behavior] Mapping Behavior = {mapping}");

    // ---- Filtering Behavior（§4.4）：服务器从 other 地址回响应，看入站能否到达 ----
    // 到达性只由本端 NAT 过滤决定（本端从未向 other 地址出站）。
    let f2 = exchange(false, true).is_some(); // same ip, other port
    let f3 = exchange(true, true).is_some(); // other ip, other port
    println!("[nat-behavior] Filtering Test II (same ip/other port 响应到达) = {f2}");
    println!("[nat-behavior] Filtering Test III (other ip:port 响应到达) = {f3}");
    let filtering = match (f2, f3) {
        (true, true) => "Endpoint-Independent Filtering (EIF)",
        (true, false) => "Address-Dependent Filtering (ADF)",
        (false, false) => "Address-and-Port-Dependent Filtering (APDF)",
        (false, true) => "UNVERIFIED（异常组合：陌生 IP 放行但同 IP 换端口拦截）",
    };
    println!("[nat-behavior] Filtering Behavior = {filtering}");
    println!("[nat-behavior] RESULT: {mapping} / {filtering}（RFC 5780 实验完成；可将该分类写入报告）");
}

// ---------- create ----------

async fn create() {
    let args = parse_common();
    let id = device_id();
    let track = arg("--track").unwrap_or_else(|| "b".into());
    match track.as_str() {
        "b" => create_b(&args, &id).await,
        "a" => create_a(&args, &id),
        _ => usage(),
    }
}

async fn create_b(args: &Args, id: &str) {
    let dl = start_transport_b(args.port, args.keepalive_ms, &args.stun).await;
    // M0-5：creator = Noise responder——msg1 到达前必须已配置身份
    //（prologue 绑定 network_id = session tag，join 侧须用同值）。
    let (session_id, issued, expires, nonce) = make_code_header();
    let network_id = format!("meshlink-poc:{session_id}:{nonce}");
    let identity = gen_identity(id);
    let creator_fp = identity.fingerprint();
    println!("[noise] creator 静态公钥 fp={creator_fp}（v4 连接码 k 字段携带，join 侧 IK 握手绑定）");
    dl.configure_noise(std::sync::Arc::new(identity), network_id.clone());
    // v3：发码只带**物理接口** host 候选（虚拟接口地址对对端不可达，纯冗余）
    let host_eps: Vec<Endpoint> = dl.local_candidates().iter().filter(|c| !c.is_virtual).map(|c| Endpoint {
        ip: c.addr.ip().to_string(), port: c.addr.port(), kind: "host".into(),
    }).collect();
    let srflx_eps: Vec<Endpoint> = dl.srflx_candidates().iter().map(|c| Endpoint {
        ip: c.addr.ip().to_string(), port: c.addr.port(), kind: "server_reflexive".into(),
    }).collect();
    let offer = CodeOffer {
        schema_version: CODE_SCHEMA_VERSION, session_id, issued_at_ms: issued, expires_at_ms: expires, nonce,
        creator_device_id: id.into(), track: 'b', nat: String::new(), ufrag: String::new(), pwd: String::new(),
        k: creator_fp,
        host_candidates: host_eps, srflx_candidates: srflx_eps,
    };
    let code = encode_code(&offer);
    println!("\n[Session Code]（v4 含加密公钥；发给对方，长度 {len} 字符，对端粘贴后应显示相同长度；**{ttl} 分钟内有效**，至 {exp}）\n{code}\n",
        len = code.len(), ttl = CODE_TTL_MS / 60_000, exp = iso_from_epoch_ms(expires));
    ui(&format!("SESSION_CODE:{code}"));
    dl.start_accepting(PeerId(PEER.into()), network_id);
    ui("STAGE: waiting_join");
    println!("[create] 等待对方 join（首个打洞请求即接入，漫游重连自动跟随）……");
    // 等 session 出现后进入 echo
    loop {
        if dl.session_info(&PeerId(PEER.into())).is_some() {
            let (_local_ep, remote, kind) = dl.session_info(&PeerId(PEER.into())).unwrap();
            println!("[create] 已接入: remote={remote} pair=host(local) ↔ {kind:?}(remote)");
            ui("SESSION: connected");
            // M0-4R.2 §三：creator 侧证据摘要（create 无 rec，仅控制台输出）
            let mut ev_sink = serde_json::Value::Null;
            attach_punch_evidence(&dl, "creator", &mut ev_sink);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    // M0-5：joiner 的 msg1 在 punch 后立即到达——提前显示加密就绪状态
    //（echo 期间收到的首包即已解密；10s 上限，超时仅告警不失败）
    let hs_deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if dl.crypto_report(&PeerId(PEER.into()))
            .get("established").and_then(|v| v.as_bool()).unwrap_or(false)
        {
            println!("[noise] ✓ creator: joiner IK 握手完成（数据面已加密）");
            ui("NOISE: established");
            break;
        }
        if Instant::now() >= hs_deadline {
            println!("[noise] creator: 10s 内未见 IK 握手（echo 期间仍可完成；如对端为旧版工具请改用 v4）");
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    echo_loop_b(&dl, Duration::from_secs(600)).await;
    // M0-5：echo 结束（空闲超时/QUIT）后输出加密通道统计
    attach_crypto_report(&dl, "creator", None);
    ui("RESULT: SUCCESS");
}

fn create_a(args: &Args, id: &str) {
    let a = make_agent_a(args.port, &args.stun);
    let (ufrag, pwd) = a.credentials();
    let (host_eps, srflx_eps) = endpoints_of_a(&a);
    let (session_id, issued, expires, nonce) = make_code_header();
    let offer = CodeOffer {
        schema_version: CODE_SCHEMA_VERSION, session_id, issued_at_ms: issued, expires_at_ms: expires, nonce,
        creator_device_id: id.into(), track: 'a', nat: String::new(),
        ufrag, pwd, k: String::new(), host_candidates: host_eps, srflx_candidates: srflx_eps,
    };
    // v4：Track A 同样走统一 wire 编码（曾直接序列化 CodeOffer 长字段名，
    // 与 parse_session_code 的 WireOffer 短字段名不兼容——join 端必解析失败）
    let code = encode_code(&offer);
    println!("\n[Session Code]（发给对方，长度 {len} 字符，对端粘贴后应显示相同长度；**{ttl} 分钟内有效**，至 {exp}）\n{code}\n",
        len = code.len(), ttl = CODE_TTL_MS / 60_000, exp = iso_from_epoch_ms(expires));
    ui(&format!("SESSION_CODE:{code}"));
    let answer = match &args.answer {
        Some(c) => c.clone(),
        None => {
            print!("[create] Track A 需要双向凭据：请粘贴对方 join 后输出的 Answer Code > ");
            std::io::stdout().flush().ok();
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line).ok();
            line.trim().to_string()
        }
    };
    // Answer Code 同样是不可信输入：统一校验，不 panic（M0-4R.1 §三）
    let (b, rejected) = match parse_session_code(&answer) {
        Ok((o, rej)) => (o, rej),
        Err(e) => {
            eprintln!("[create] FAIL: {}（{}）", e.code, e.reason);
            std::process::exit(1);
        }
    };
    if !rejected.is_empty() {
        for (cand, why) in &rejected {
            eprintln!("[create] candidate rejected: {cand} ← {why}");
        }
    }
    let remote_eps: Vec<Endpoint> = b.host_candidates.iter().chain(b.srflx_candidates.iter()).cloned().collect();
    println!("[create] 收到 Answer: id={} session={} endpoints={}", b.creator_device_id, b.session_id, remote_eps.len());
    let started = Instant::now();
    let remote = a
        .accept(b.ufrag, b.pwd, &remote_eps.iter().map(|e| parse_ep(e)).collect::<Vec<_>>(), CHECK_TIMEOUT)
        .expect("FAIL: Track A accept 超时");
    println!("[create] ✓ Track A 连通（{:.1}ms）selected remote={remote} pair=host(local) ↔ ?(remote)", started.elapsed().as_secs_f64() * 1000.0);
    echo_a_for(&a, Duration::from_secs(600));
}

// ---------- join ----------

async fn join(code: &str) {
    let args = parse_common();
    // M0-4R.1 §三：连接码是不可信输入——统一校验（版本/生命周期/候选/长度），
    // 失败显式报 SESSION_CODE_INVALID（附 reason）或 SESSION_CODE_EXPIRED，
    // 绝不 panic（panic 会让双击运行的朋友机窗口直接闪退，无法回报问题）。
    let (offer, rejected) = match parse_session_code(code) {
        Ok((o, rej)) => (o, rej),
        Err(e) => {
            eprintln!("[join] FAIL: {}（{}）", e.code, e.reason);
            ui(&format!("RESULT: FAIL:{}", e.code));
            std::process::exit(1);
        }
    };
    ui("STAGE: code_ok");
    let remain_min = (offer.expires_at_ms as u128).saturating_sub(now_ms()) / 60_000;
    println!("[join] 对端: id={} track={} session={} 剩余有效期 {remain_min} 分钟", offer.creator_device_id, offer.track, offer.session_id);
    match offer.track {
        'b' => join_b(&args, &offer, &rejected).await,
        'a' => join_a(&args, &offer, &rejected),
        _ => usage(),
    }
}

async fn join_b(args: &Args, offer: &CodeOffer, rejected: &[(String, String)]) {
    let local_id = device_id();
    let remote_host = offer.host_candidates.first()
        .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default();
    let remote_srflx = offer.srflx_candidates.first()
        .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default();
    // §七：候选 trace——sanitize 前后 / 尝试顺序 / selected（诊断 punch timeout 的关键证据）
    let kept_tags: Vec<String> = offer.host_candidates.iter().chain(offer.srflx_candidates.iter())
        .map(|e| format!("{}:{} ({})", e.ip, e.port, e.kind)).collect();
    let mut before_tags: Vec<String> = kept_tags.clone();
    before_tags.extend(rejected.iter().map(|(t, _)| t.clone()));
    let mut attempt: Vec<String> = offer.host_candidates.iter().enumerate()
        .map(|(n, e)| format!("{} host {}:{}", n + 1, e.ip, e.port)).collect();
    attempt.extend(offer.srflx_candidates.iter().enumerate()
        .map(|(n, e)| format!("{} srflx {}:{}", offer.host_candidates.len() + n + 1, e.ip, e.port)));
    let mut trace = serde_json::json!({
        "test_id": args.test_id,
        "session_id": offer.session_id,
        "track": "b",
        "candidates_before_sanitize": before_tags,
        "candidates_after_sanitize": kept_tags,
        "candidates_rejected": rejected.iter().map(|(t, r)| serde_json::json!({"candidate": t, "reason": r})).collect::<Vec<_>>(),
        "attempt_order": attempt,
        "selected_remote": serde_json::Value::Null,
    });
    let env = env_snapshot('b', args.stun.first().map(String::as_str).unwrap_or_default());
    let mut rec = serde_json::json!({
        "test_id": args.test_id,
        "timestamp": iso_timestamp(),
        "epoch_ms": now_ms(),
        "track": "b",
        "engine": "MinimalPunchAgent",
        "session_id": offer.session_id,
        "profile": args.profile,
        "expected_selected_pair": profile_expected(&args.profile),
        "local_device_id": local_id,
        "remote_device_id": offer.creator_device_id,
        "remote_host_candidate": remote_host,
        "remote_srflx_candidate": remote_srflx,
        "stun_server": args.stun.first().cloned().unwrap_or_default(),
        "connect_success": false,
        "selected_pair_confirmed": false,
        "round_success": false,
        "smoke_packets_expected": JOIN_SMOKE_N,
        "smoke_packets_tx": 0,
        "smoke_packets_rx": 0,
        "smoke_packets_lost": null,
        "smoke_loss_percent": null,
        "candidate_gather_ms": null,
        "connect_ms": null,
        "rtt_p50": null,
        "rtt_p95": null,
        "jitter": null,
        "loss": null,
        "packets_tx": 0,
        "packets_rx": 0,
        "keepalive_interval": args.keepalive_ms,
        "keepalive_survived": null,
        "mtu_results": null,
        "network_change_recovery_ms": null,
        "recovery_detail": null,
        "idle_mapping_results": null,
        "relay_used": false,
        "start_type": "cold",
        "firewall_required": true,
        "firewall_prompt_observed": null,
        "test_parameters": test_params_json(args, JOIN_SMOKE_N),
        "environment": env.clone(),
        "error_code": "",
        "error_stage": Stage::None.as_str(),
    });
    // 失败收尾：写报告后显式退出（无兜底）
    macro_rules! fail {
        ($stage:expr, $code:expr) => {{
            rec["error_stage"] = serde_json::json!($stage.as_str());
            rec["error_code"] = serde_json::json!($code);
            if args.report {
                write_result(&args.out_dir, "result.json", rec.clone());
                write_result(&args.out_dir, "candidate_trace.json", trace.clone());
            }
            ui(&format!("RESULT: FAIL:{}", $code));
            println!("FAIL: {}（stage={}）", $code, $stage.as_str());
            std::process::exit(1);
        }};
    }
    let started = Instant::now();
    ui("STAGE: gathering");
    let dl = start_transport_b(args.port, args.keepalive_ms, &args.stun).await;
    let stun_ok = !dl.srflx_candidates().is_empty();
    rec["stun_server"] = serde_json::json!(dl.first_stun_server().unwrap_or_default());
    rec["local_host_candidate"] = serde_json::json!(
        dl.local_candidates().first().map(|c| format!("{}:{}", c.addr.ip(), c.addr.port())).unwrap_or_default());
    rec["local_srflx_candidate"] = serde_json::json!(
        dl.srflx_candidates().first().map(|c| format!("{}:{}", c.addr.ip(), c.addr.port())).unwrap_or_default());
    let gather = started.elapsed();
    rec["candidate_gather_ms"] = serde_json::json!((gather.as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
    if args.report {
        write_result(&args.out_dir, "network_snapshot.json", env_snapshot('b', dl.first_stun_server().unwrap_or_default().as_str()));
    }
    if !stun_ok && dl.local_candidates().is_empty() {
        fail!(Stage::Stun, "no_local_candidates");
    }
    ui("STAGE: punching");
    // M0-4 双向 punch：session tag + 本端候选集（物理 host + srflx）随 probe 携带，
    // 对端收到后主动反向出站（双向 simultaneous punch 的 candidate exchange 逆向通道）。
    // M0-5：session tag 同时是 Noise prologue 的 network_id（creator 侧同值）。
    let network_id = format!("meshlink-poc:{}:{}", offer.session_id, offer.nonce);
    dl.set_punch_session(
        network_id.clone(),
        dl.punch_candidates_wire(),
    );
    let t0 = Instant::now();
    let punched = dl.connect_peer(
        PeerId(PEER.into()),
        PeerHints {
            endpoints: offer.host_candidates.iter().chain(offer.srflx_candidates.iter()).cloned().collect(),
            static_key_fingerprint: Some(offer.k.clone()),
            overlay_mac: None,
        },
    )
    .await;
    // M0-4R.2 §三：成败都留证据（joiner 首包必先于任何入站，tx < rx 即主动出站证明）
    attach_punch_evidence(&dl, "joiner", &mut rec);
    if punched.is_err() {
        fail!(Stage::Punch, "punch_timeout_or_check_failed");
    }
    let connect = t0.elapsed();
    rec["connect_success"] = serde_json::json!(true);
    rec["connect_ms"] = serde_json::json!((connect.as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
    let (local_ep, remote, kind) = dl.session_info(&PeerId(PEER.into())).unwrap();
    rec["selected_local_endpoint"] = serde_json::json!(local_ep.to_string());
    rec["selected_remote_endpoint"] = serde_json::json!(remote.to_string());
    let pair = format!("host(local) ↔ {kind:?}(remote)");
    rec["selected_pair_type"] = serde_json::json!(pair.clone());
    // M0-4 §八：selected pair origin（Track B 本端恒 host，按对端候选类型映射）
    rec["selected_pair_origin"] = serde_json::json!(match kind {
        CandidateKind::PeerReflexive => "prflx",
        CandidateKind::ServerReflexive => "srflx",
        CandidateKind::Host => "host",
    });
    rec["peer_reflexive_candidates"] = serde_json::json!([]); // Track B 无 prflx 学习
    rec["selected_pair_confirmed"] = serde_json::json!(true);
    trace["selected_remote"] = serde_json::json!(remote.to_string());
    rec["expectation_match"] = match args.profile.as_str() {
        // same-lan：预期 host↔host；其他 profile 预期仅参考，实际以真实 pair 为准
        "same-lan" => serde_json::json!(pair.to_lowercase().contains("host")),
        _ => serde_json::Value::Null,
    };
    if args.report { write_result(&args.out_dir, "candidate_trace.json", trace.clone()); }
    println!("[join] ✓ 打洞成功（connect {:.1}ms，gathering {:.1}ms）", connect.as_secs_f64() * 1000.0, gather.as_secs_f64() * 1000.0);
    println!("[join] selected pair: {pair}  remote={remote}");

    // M0-5：Noise IK 握手（join = initiator）。responder 公钥来自连接码 k 字段
    //（validate_offer 已保证 Track B 必有合法 64-hex）；prologue 绑定
    // network_id + 双方 device_id。失败 → 显式 FAIL（含 error_detail），不 panic。
    ui("STAGE: noise_handshake");
    let Some(remote_key) = key_hex::decode_key32(&offer.k) else {
        rec["error_detail"] = serde_json::json!("k 字段公钥解码失败（理论不可达：validate_offer 已校验）");
        fail!(Stage::CandidateExchange, "static_key_invalid");
    };
    let t_hs = Instant::now();
    let joiner_identity = std::sync::Arc::new(gen_identity(&local_id));
    rec["local_static_fingerprint"] = serde_json::json!(joiner_identity.fingerprint());
    rec["remote_static_fingerprint"] = serde_json::json!(offer.k);
    match dl
        .start_noise_initiator(
            &PeerId(PEER.into()),
            joiner_identity,
            &network_id,
            &offer.creator_device_id,
            &remote_key,
        )
        .await
    {
        Ok(noise_sid) => {
            let hs_ms = (t_hs.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0;
            rec["noise_handshake_ms"] = serde_json::json!(hs_ms);
            rec["noise_session_id"] = serde_json::json!(key_hex::encode_lower(&noise_sid));
            println!("[join] ✓ Noise_IK 握手完成（{hs_ms:.1}ms）creator fp={}…（数据面已加密）", &offer.k[..16]);
            ui("NOISE: established");
        }
        Err(e) => {
            rec["error_detail"] = serde_json::json!(format!("{e:?}"));
            fail!(Stage::NoiseHandshake, "noise_handshake_failed");
        }
    }
    attach_crypto_report(&dl, "joiner", None); // 握手即提示（统计在 smoke 后再入 rec）
    ui("STAGE: data_test");

    let st = ping_pong_b(&dl, JOIN_SMOKE_N).await;
    st.report("smoke");
    rec["rtt_p50"] = serde_json::json!(SmokeStats::pct(&mut st.rtts.clone(), 0.5));
    rec["rtt_p95"] = serde_json::json!(SmokeStats::pct(&mut st.rtts.clone(), 0.95));
    rec["jitter"] = serde_json::json!(st.jitter());
    rec["loss"] = serde_json::json!((st.loss() * 10.0).round() / 10.0);
    rec["packets_tx"] = serde_json::json!(st.sent);
    rec["packets_rx"] = serde_json::json!(st.recv);
    // §一：每轮独立 smoke 口径——expected/tx/rx/lost/loss_percent
    rec["smoke_packets_tx"] = serde_json::json!(st.sent);
    rec["smoke_packets_rx"] = serde_json::json!(st.recv);
    rec["smoke_packets_lost"] = serde_json::json!(st.sent.saturating_sub(st.recv));
    rec["smoke_loss_percent"] = serde_json::json!((st.loss() * 10.0).round() / 10.0);
    // M0-5：smoke 后记录完整加密通道统计（frames_tx/rx/bytes/防重放——
    // 失败路径的 fail! 也带此证据）
    attach_crypto_report(&dl, "joiner", Some(&mut rec));
    let ok = round_success(true, st.recv, JOIN_SMOKE_N, args.smoke_threshold);
    rec["round_success"] = serde_json::json!(ok);
    if st.recv == 0 {
        fail!(Stage::DataSmoke, "smoke_all_lost");
    }
    if !ok {
        fail!(Stage::DataSmoke, "smoke_below_threshold");
    }

    if args.mtu_test {
        match dl.probe_mtu(&PeerId(PEER.into())).await {
            Ok(p) => {
                println!("[MTU] ladder {:?} → payload_max={} path_mtu={}", p.ladder_results, p.payload_max, p.path_mtu);
                rec["mtu_results"] = serde_json::json!({
                    "ladder_results": p.ladder_results,
                    "payload_max": p.payload_max,
                    "path_mtu": p.path_mtu,
                });
            }
            Err(e) => {
                rec["mtu_results"] = serde_json::json!({ "error": format!("{e}") });
                println!("[MTU] FAIL: {e}");
            }
        }
    }

    if args.hold_min > 0 {
        // Keepalive hold：idle 保持（仅 keepalive），结束再 smoke 验证映射未失效
        let before = dl.nat_mapping().await;
        println!("[hold] idle {} 分钟（keepalive {}ms/次）……", args.hold_min, args.keepalive_ms);
        for i in 0..args.hold_min * 2 {
            tokio::time::sleep(Duration::from_secs(30)).await;
            let h = dl.health(Some(PeerId(PEER.into())));
            println!("[hold {:>3}s] health: score={} rtt={:?} alive={}", (i + 1) * 30, h.score, h.rtt_ms, h.transport_alive);
        }
        let st2 = ping_pong_b(&dl, 10).await;
        st2.report("hold-smoke");
        let after = dl.nat_mapping().await;
        println!("[hold] mapping before={before:?}");
        println!("[hold] mapping after ={after:?}");
        rec["keepalive_survived"] = serde_json::json!(st2.recv > 0);
        if st2.recv == 0 {
            fail!(Stage::DataSmoke, "hold_mapping_expired");
        }
    }

    if !args.idle_test.is_empty() {
        // M0-4R §十：完全停止 Keepalive 对照组——粗略判断 mapping idle lifetime
        rec["idle_mapping_results"] = idle_test_b(&dl, &args.idle_test).await;
    }

    if args.roam {
        let all_eps: Vec<Endpoint> = offer.host_candidates.iter().chain(offer.srflx_candidates.iter()).cloned().collect();
        let session_tag = format!("meshlink-poc:{}:{}", offer.session_id, offer.nonce);
        let (total, detail) = roam_test_b(&dl, &all_eps, &session_tag).await;
        rec["network_change_recovery_ms"] = serde_json::json!(total);
        rec["recovery_detail"] = detail;
    }
    if args.report {
        write_result(&args.out_dir, "result.json", rec.clone());
    }
    ui("RESULT: SUCCESS");
    println!("PASS");
}

/// idle mapping 对照组：停 keepalive → 分时点发业务包。
/// 结论纪律：只记 "Mapping survived Ns / expired"，不推导 NAT 类型。
async fn idle_test_b(dl: &DirectLinkTransport, points: &[u64]) -> serde_json::Value {
    dl.stop_keepalive(&PeerId(PEER.into()));
    println!("[idle] Keepalive 已全部停止，检测时点 {:?}s", points);
    let start = Instant::now();
    let mut out = Vec::new();
    for &p in points {
        let elapsed = start.elapsed().as_secs();
        if p > elapsed {
            tokio::time::sleep(Duration::from_secs(p - elapsed)).await;
        }
        let st = ping_pong_b(dl, 5).await;
        let alive = st.recv > 0;
        println!("[idle] after {p}s: {}（loss {:.0}%）", if alive { "Mapping survived" } else { "Mapping expired" }, st.loss());
        out.push(serde_json::json!({
            "after_s": p,
            "alive": alive,
            "loss_pct": (st.loss() * 10.0).round() / 10.0,
            "rtt_p50_ms": SmokeStats::pct(&mut st.rtts.clone(), 0.5),
        }));
    }
    serde_json::Value::Array(out)
}

fn join_a(args: &Args, offer: &CodeOffer, rejected: &[(String, String)]) {
    let remote_host = offer.host_candidates.first()
        .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default();
    let remote_srflx = offer.srflx_candidates.first()
        .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default();
    let kept_tags: Vec<String> = offer.host_candidates.iter().chain(offer.srflx_candidates.iter())
        .map(|e| format!("{}:{} ({})", e.ip, e.port, e.kind)).collect();
    let mut attempt: Vec<String> = offer.host_candidates.iter().enumerate()
        .map(|(n, e)| format!("{} host {}:{}", n + 1, e.ip, e.port)).collect();
    attempt.extend(offer.srflx_candidates.iter().enumerate()
        .map(|(n, e)| format!("{} srflx {}:{}", offer.host_candidates.len() + n + 1, e.ip, e.port)));
    let mut trace = serde_json::json!({
        "test_id": args.test_id,
        "session_id": offer.session_id,
        "track": "a",
        "candidates_after_sanitize": kept_tags,
        "candidates_rejected": rejected.iter().map(|(t, r)| serde_json::json!({"candidate": t, "reason": r})).collect::<Vec<_>>(),
        "attempt_order": attempt,
        "selected_remote": serde_json::Value::Null,
    });
    let env = env_snapshot('a', args.stun.first().map(String::as_str).unwrap_or_default());
    let mut rec = serde_json::json!({
        "test_id": args.test_id,
        "timestamp": iso_timestamp(),
        "epoch_ms": now_ms(),
        "track": "a",
        "engine": "rtc-ice 0.20.4",
        "session_id": offer.session_id,
        "profile": args.profile,
        "expected_selected_pair": profile_expected(&args.profile),
        "local_device_id": device_id(),
        "remote_device_id": offer.creator_device_id,
        "remote_host_candidate": remote_host,
        "remote_srflx_candidate": remote_srflx,
        "stun_server": args.stun.first().cloned().unwrap_or_default(),
        "connect_success": false,
        "selected_pair_confirmed": false,
        "round_success": false,
        "smoke_packets_expected": JOIN_SMOKE_N,
        "smoke_packets_tx": 0,
        "smoke_packets_rx": 0,
        "smoke_packets_lost": null,
        "smoke_loss_percent": null,
        "candidate_gather_ms": null,
        "connect_ms": null,
        "rtt_p50": null,
        "rtt_p95": null,
        "jitter": null,
        "loss": null,
        "packets_tx": 0,
        "packets_rx": 0,
        "keepalive_interval": null,
        "keepalive_survived": null,
        "mtu_results": null,
        "network_change_recovery_ms": null,
        "idle_mapping_results": null,
        "relay_used": false,
        "start_type": "cold",
        "firewall_required": true,
        "firewall_prompt_observed": null,
        "test_parameters": test_params_json(args, JOIN_SMOKE_N),
        "environment": env.clone(),
        "error_code": "",
        "error_stage": Stage::None.as_str(),
    });
    let t_start = Instant::now();
    ui("STAGE: gathering");
    let b = make_agent_a(args.port, &args.stun);
    rec["local_host_candidate"] = serde_json::json!(b.local_base().to_string());
    if let Some(m) = b.srflx_addr() { rec["local_srflx_candidate"] = serde_json::json!(m.to_string()); }
    rec["candidate_gather_ms"] = serde_json::json!((t_start.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
    if args.report {
        write_result(&args.out_dir, "network_snapshot.json", env);
    }
    let (ufrag, pwd) = b.credentials();
    let (host_eps, srflx_eps) = endpoints_of_a(&b);
    let (session_id, issued, expires, nonce) = make_code_header();
    let answer = CodeOffer {
        schema_version: CODE_SCHEMA_VERSION, session_id, issued_at_ms: issued, expires_at_ms: expires, nonce,
        creator_device_id: device_id(), track: 'a', nat: String::new(),
        ufrag, pwd, k: String::new(), host_candidates: host_eps, srflx_candidates: srflx_eps,
    };
    ui("STAGE: punching");
    // Answer Code 必须先于 dial 输出：creator 需要它才能进入 accept，
    // dial 成功后才发会导致死锁（joiner 等 creator accept，creator 等 answer）
    // v4：与 create 端统一 wire 编码（双端 parse_session_code 同格式）
    let answer_code = encode_code(&answer);
    println!("\n[Answer Code]（立即回传给 create 端；A 端粘贴后直连继续；10 分钟内有效）\n{answer_code}\n");
    ui(&format!("ANSWER_CODE:{answer_code}"));
    let t0 = Instant::now();
    let remote_eps: Vec<Endpoint> = offer.host_candidates.iter().chain(offer.srflx_candidates.iter()).cloned().collect();
    // 交互式流程 answer 需经人工回传（微信等），dial 窗口放宽到 120s
    let remote = match b
        .dial(offer.ufrag.clone(), offer.pwd.clone(), &remote_eps.iter().map(|e| parse_ep(e)).collect::<Vec<_>>(), Duration::from_secs(120))
    {
        Ok(r) => r,
        Err(e) => {
            rec["error_stage"] = serde_json::json!(Stage::Punch.as_str());
            rec["error_code"] = serde_json::json!("dial_failed");
            rec["error_detail"] = serde_json::json!(e);
            if args.report {
                write_result(&args.out_dir, "result.json", rec.clone());
                write_result(&args.out_dir, "candidate_trace.json", trace.clone());
            }
            ui("RESULT: FAIL:dial_failed");
            println!("FAIL: Track A dial 超时（无兜底）: {e}");
            std::process::exit(1);
        }
    };
    let connect = t0.elapsed();
    rec["connect_success"] = serde_json::json!(true);
    rec["connect_ms"] = serde_json::json!((connect.as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
    rec["selected_local_endpoint"] = serde_json::json!(b.local_base().to_string());
    rec["selected_remote_endpoint"] = serde_json::json!(remote.to_string());
    rec["selected_pair_type"] = serde_json::json!("host(local) ↔ ?(remote)");
    rec["selected_pair_confirmed"] = serde_json::json!(true);
    trace["selected_remote"] = serde_json::json!(remote.to_string());
    if args.report { write_result(&args.out_dir, "candidate_trace.json", trace.clone()); }
    println!("[join] ✓ Track A 连通（{:.1}ms）selected remote={remote}", t0.elapsed().as_secs_f64() * 1000.0);
    ui("STAGE: data_test");
    let st = ping_pong_raw(&b, remote, JOIN_SMOKE_N);
    st.report("smoke");
    rec["rtt_p50"] = serde_json::json!(SmokeStats::pct(&mut st.rtts.clone(), 0.5));
    rec["rtt_p95"] = serde_json::json!(SmokeStats::pct(&mut st.rtts.clone(), 0.95));
    rec["jitter"] = serde_json::json!(st.jitter());
    rec["loss"] = serde_json::json!((st.loss() * 10.0).round() / 10.0);
    rec["packets_tx"] = serde_json::json!(st.sent);
    rec["packets_rx"] = serde_json::json!(st.recv);
    rec["smoke_packets_tx"] = serde_json::json!(st.sent);
    rec["smoke_packets_rx"] = serde_json::json!(st.recv);
    rec["smoke_packets_lost"] = serde_json::json!(st.sent.saturating_sub(st.recv));
    rec["smoke_loss_percent"] = serde_json::json!((st.loss() * 10.0).round() / 10.0);
    let ok = round_success(true, st.recv, JOIN_SMOKE_N, args.smoke_threshold);
    rec["round_success"] = serde_json::json!(ok);
    if !ok {
        rec["error_stage"] = serde_json::json!(Stage::DataSmoke.as_str());
        rec["error_code"] = serde_json::json!(if st.recv == 0 { "smoke_all_lost" } else { "smoke_below_threshold" });
        if args.report { write_result(&args.out_dir, "result.json", rec.clone()); }
        ui(&format!("RESULT: FAIL:{}", rec["error_code"].as_str().unwrap_or("smoke_failed")));
        println!("FAIL: smoke 未达阈值（rx={}/{}）", st.recv, JOIN_SMOKE_N);
        std::process::exit(1);
    }
    if args.hold_min > 0 {
        for i in 0..args.hold_min * 2 {
            std::thread::sleep(Duration::from_secs(30));
            println!("[hold {:>3}s] keepalive 由 agent 内部驱动（rtc-ice）", (i + 1) * 30);
        }
        let st2 = ping_pong_raw(&b, remote, 10);
        st2.report("hold-smoke");
        rec["keepalive_survived"] = serde_json::json!(st2.recv > 0);
    }
    if args.report { write_result(&args.out_dir, "result.json", rec.clone()); }
    ui("RESULT: SUCCESS");
    println!("PASS");
}

// ---------- roam（Track B join 端） ----------

/// roam（Track B join 端）：path lost 检测 → 重新 gather → 重新 punch → 恢复。
/// 分段计时（M0-4R §十一）：detect_ms / regather_ms / repunch_ms / total_recovery_ms。
async fn roam_test_b(dl: &DirectLinkTransport, endpoints: &[Endpoint], session_tag: &str) -> (Option<u64>, serde_json::Value) {
    println!("[roam] 网络切换测试：请切换网络（Wi-Fi→热点），本端自动检测并重建");
    let roam_start = Instant::now();
    let mut miss = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(2)).await;
        let probe = ping_pong_b(dl, 1).await;
        let alive = dl.health(Some(PeerId(PEER.into()))).transport_alive;
        if probe.recv == 0 && !alive {
            miss += 1;
            println!("[roam] 探测失败 {miss}/3");
            if miss >= 3 {
                let detect_ms = roam_start.elapsed().as_secs_f64() * 1000.0;
                println!("[roam] 判定 path lost → 重新 gather/srflx → 重新 punch");
                let t_re = Instant::now();
                let _ = dl.stop(Duration::from_secs(1)).await;
                let _ = start_transport_b(0, 15_000, &[]).await; // 重新 start（新 socket 新映射）
                let regather_ms = t_re.elapsed().as_secs_f64() * 1000.0;
                // 新 transport 实例：session tag 与候选集需重设（否则 probe 用默认全局 tag 被对端拒绝）
                dl.set_punch_session(session_tag.to_string(), dl.punch_candidates_wire());
                dl.start_accepting(PeerId(PEER.into()), session_tag.to_string()); // 本端也 accept 便于对端跟随
                let t_pu = Instant::now();
                if dl.connect_peer(PeerId(PEER.into()), PeerHints { endpoints: endpoints.to_vec(), static_key_fingerprint: None, overlay_mac: None })
                    .await
                    .is_err()
                {
                    println!("[roam] FAIL: 漫游后重连失败");
                    return (
                        None,
                        serde_json::json!({
                            "detect_ms": (detect_ms * 10.0).round() / 10.0,
                            "regather_ms": (regather_ms * 10.0).round() / 10.0,
                            "repunch_ms": null,
                            "total_recovery_ms": null,
                            "reconnected": false,
                        }),
                    );
                }
                let repunch_ms = t_pu.elapsed().as_secs_f64() * 1000.0;
                let total = roam_start.elapsed().as_secs_f64() * 1000.0;
                let (local_ep, remote, kind) = dl.session_info(&PeerId(PEER.into())).unwrap();
                println!("[roam] ✓ 恢复 detect={detect_ms:.0}ms regather={regather_ms:.0}ms repunch={repunch_ms:.0}ms total={total:.0}ms");
                println!("[roam] 新 pair: {local_ep} ↔ {remote} {kind:?}");
                let st = ping_pong_b(dl, 10).await;
                st.report("roam-smoke");
                return (
                    Some((total * 10.0).round() as u64),
                    serde_json::json!({
                        "detect_ms": (detect_ms * 10.0).round() / 10.0,
                        "regather_ms": (regather_ms * 10.0).round() / 10.0,
                        "repunch_ms": (repunch_ms * 10.0).round() / 10.0,
                        "total_recovery_ms": (total * 10.0).round() / 10.0,
                        "reconnected": st.recv > 0,
                        "new_pair": format!("{local_ep} ↔ {remote} {kind:?}"),
                    }),
                );
            }
        } else {
            miss = 0;
        }
    }
}

fn parse_ep(e: &Endpoint) -> SocketAddrV4 {
    let addr: SocketAddr = format!("{}:{}", e.ip, e.port).parse().expect("候选地址非法");
    match addr { SocketAddr::V4(v) => v, _ => panic!("只支持 IPv4") }
}

// ---------- matrix（两端同跑，exchange 目录自动交换） ----------

/// matrix 每轮统计（M0-4R.1 §一：连接口径与数据口径分开记账）。
struct RoundAgg {
    /// P2P path established + selected_pair confirmed
    connect_success: bool,
    /// = connect_success AND smoke_packets_rx ≥ expected × threshold
    round_success: bool,
    connect: Duration,
    gather: Duration,
    /// joiner 实际发送数（creator 不发 = None）
    smoke_tx: Option<usize>,
    /// 数据面收包数：joiner = 收到的 PONG；creator = echo 的对端 PING（交叉核对）
    smoke_rx: usize,
    rtts: Vec<Duration>,
    start_type: &'static str,
    rec: serde_json::Value,
}

async fn matrix() {
    let args = parse_common();
    let id = device_id();
    let track = arg("--track").unwrap_or_else(|| "b".into()).chars().next().unwrap_or('b');
    std::fs::create_dir_all(&args.exchange).expect("exchange 目录");
    let mut rounds: Vec<RoundAgg> = Vec::new();
    let is_creator = arg("--side").map(|s| s == "a").unwrap_or(false);
    let side = if is_creator { "a" } else { "b" };
    if args.report {
        // §九：环境快照（每次运行写一份）
        write_result(&args.out_dir, "network_snapshot.json",
            env_snapshot(track, args.stun.first().map(String::as_str).unwrap_or_default()));
    }
    println!("[matrix] profile={} 预期pair={} rounds={} smoke/round={} round阈值={}%",
        args.profile, profile_expected(&args.profile), args.rounds, MATRIX_SMOKE_N, args.smoke_threshold);

    for i in 0..args.rounds {
        let offer_p = args.exchange.join(format!("offer-r{i}.json"));
        // Track A 的 answer 是真实 CodeOffer JSON（.json 走 wait_file 完整性校验）；
        // Track B 的 answer 仅"transport 已就绪"信号（.sig 免 JSON 校验）。
        // done 同理是文本信号（.sig）——曾因 .json 后缀 + "ready"/"done" 纯文本
        // 被 wait_file 判为半截文件，creator 侧忙等 120s 拖垮全部后续轮次。
        let answer_p = args.exchange.join(format!("answer-r{i}.json"));
        let answer_sig = args.exchange.join(format!("answer-r{i}.sig"));
        let done_p = args.exchange.join(format!("done-r{i}.sig"));
        // M0-4R：join 侧 connect 成功后写 "ok"/失败写 "fail"；creator 等此信号
        // 再取 session_info/echo——保证拿到的是真对端 punch 建的 session
        //（配合 transport accept 的 USERNAME 校验，杜绝外来 STUN 污染）。
        let punch_ok_p = args.exchange.join(format!("punchok-r{i}.sig"));
        let _ = std::fs::remove_file(&done_p);
        let _ = std::fs::remove_file(&answer_sig);
        let _ = std::fs::remove_file(&punch_ok_p);
        let started = Instant::now();
        // M0-4R §八：程序启动后的第一轮 = Cold Start，其余 = Warm Start
        let start_type = if i == 0 { "cold" } else { "warm" };
        let mut rr = if track == 'b' {
            matrix_round_b(&args, &id, i, is_creator, &offer_p, &answer_sig, &punch_ok_p, &done_p).await
        } else {
            matrix_round_a(&args, &id, is_creator, &offer_p, &answer_p, &done_p)
        };
        rr.start_type = start_type; // 供 summary cold/warm 分组（M0-4R §八）
        let rec = &mut rr.rec;
        rec["test_id"] = serde_json::json!(args.test_id);
        rec["round"] = serde_json::json!(i);
        rec["timestamp"] = serde_json::json!(iso_timestamp());
        rec["epoch_ms"] = serde_json::json!(now_ms());
        rec["track"] = serde_json::json!(track);
        rec["local_device_id"] = serde_json::json!(id);
        rec["start_type"] = serde_json::json!(start_type);
        rec["side"] = serde_json::json!(side);
        rec["profile"] = serde_json::json!(args.profile);
        rec["expected_selected_pair"] = serde_json::json!(profile_expected(&args.profile));
        rec["relay_used"] = serde_json::json!(false);
        rec["firewall_required"] = serde_json::json!(true);
        rec["firewall_prompt_observed"] = serde_json::Value::Null;
        rec["keepalive_interval"] = serde_json::json!(args.keepalive_ms);
        rec["keepalive_survived"] = serde_json::Value::Null;
        rec["mtu_results"] = serde_json::Value::Null;
        rec["network_change_recovery_ms"] = serde_json::Value::Null;
        rec["idle_mapping_results"] = serde_json::Value::Null;
        rr.round_success = round_success(rr.connect_success, rr.smoke_rx, MATRIX_SMOKE_N, args.smoke_threshold);
        // §一：每轮独立 smoke 口径
        rec["smoke_packets_expected"] = serde_json::json!(MATRIX_SMOKE_N);
        rec["smoke_packets_tx"] = match rr.smoke_tx {
            Some(t) => serde_json::json!(t),
            None => serde_json::Value::Null, // creator 不发 smoke，只 echo（角色记录在 summary.smoke_role）
        };
        rec["smoke_packets_rx"] = serde_json::json!(rr.smoke_rx);
        rec["smoke_packets_lost"] = serde_json::json!(MATRIX_SMOKE_N.saturating_sub(rr.smoke_rx));
        rec["smoke_loss_percent"] = serde_json::json!(
            (MATRIX_SMOKE_N.saturating_sub(rr.smoke_rx) as f64 / MATRIX_SMOKE_N as f64 * 1000.0).round() / 10.0);
        rec["round_success"] = serde_json::json!(rr.round_success);
        rec["test_parameters"] = test_params_json(&args, MATRIX_SMOKE_N);
        rec["connect_success"] = serde_json::json!(rr.connect_success);
        rec["connect_ms"] = serde_json::json!((rr.connect.as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
        rec["candidate_gather_ms"] = serde_json::json!((rr.gather.as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
        rec["rtt_p50"] = serde_json::json!(SmokeStats::pct(&mut rr.rtts.clone(), 0.5));
        rec["rtt_p95"] = serde_json::json!(SmokeStats::pct(&mut rr.rtts.clone(), 0.95));
        rec["jitter"] = serde_json::json!(if rr.rtts.len() < 2 { 0.0 } else { SmokeStats { sent: 0, recv: 0, rtts: rr.rtts.clone() }.jitter() });
        rec["loss"] = serde_json::json!(rr.smoke_tx.map(|t|
            (SmokeStats { sent: t, recv: rr.smoke_rx, rtts: vec![] }.loss() * 10.0).round() / 10.0));
        rec["packets_tx"] = serde_json::json!(rr.smoke_tx.unwrap_or(0));
        rec["packets_rx"] = serde_json::json!(rr.smoke_rx);
        rec["error_stage"] = serde_json::json!(if rr.connect_success { Stage::None.as_str() } else { Stage::Punch.as_str() });
        rec["error_code"] = serde_json::json!(if rr.connect_success { "" } else { "round_failed" });
        if args.report {
            write_result(&args.out_dir, &format!("result-r{i:02}.json"), rec.clone());
        }
        let total = started.elapsed();
        let smoke_loss_pct = MATRIX_SMOKE_N.saturating_sub(rr.smoke_rx) as f64 / MATRIX_SMOKE_N as f64 * 100.0;
        println!(
            "[round {i:>2}] {} {} connect={:.1}ms gather={:.1}ms total={:.1}ms smoke_rx={}/{} smoke_loss={:.0}% rtt_p50={:.2}ms",
            start_type.to_uppercase(),
            if rr.connect_success { "OK " } else { "FAIL" },
            rr.connect.as_secs_f64() * 1000.0,
            rr.gather.as_secs_f64() * 1000.0,
            total.as_secs_f64() * 1000.0,
            rr.smoke_rx, MATRIX_SMOKE_N, smoke_loss_pct,
            if rr.rtts.is_empty() { 0.0 } else { SmokeStats::pct(&mut rr.rtts.clone(), 0.5) }
        );
        rounds.push(rr);
        // M0-4R §七：轮间随机 500–3000ms（防止 NAT mapping 复用；真重建见每轮新 socket）
        let gap = jitter_ms();
        println!("[round {i:>2}] 下一轮前随机间隔 {}ms（真重建：新 socket/新端口/重新 STUN/重新 exchange/重新 punch）", gap);
        tokio::time::sleep(Duration::from_millis(gap)).await;
    }

    // ===== 汇总（M0-4R.1 §一：connection 与 data_smoke 两个口径分别报告） =====
    let rounds_n = args.rounds;
    let conn_ok = rounds.iter().filter(|r| r.connect_success).count();
    let smoke_ok = rounds.iter().filter(|r| r.round_success).count();
    let mut connects: Vec<f64> = rounds.iter().filter(|r| r.connect_success).map(|r| r.connect.as_secs_f64() * 1000.0).collect();
    connects.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut gathers: Vec<f64> = rounds.iter().filter(|r| r.connect_success).map(|r| r.gather.as_secs_f64() * 1000.0).collect();
    gathers.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p = |v: &Vec<f64>, q: f64| -> f64 {
        if v.is_empty() { return 0.0; }
        v[((v.len() as f64 * q) as usize).min(v.len() - 1)]
    };
    let mut all_rtts = Vec::new();
    for r in &rounds { all_rtts.extend(r.rtts.clone()); }
    let expected_total = MATRIX_SMOKE_N * rounds_n;
    let tx_total: usize = rounds.iter().filter_map(|r| r.smoke_tx).sum();
    let rx_total: usize = rounds.iter().map(|r| r.smoke_rx).sum();
    let lost_total = expected_total.saturating_sub(rx_total);
    let rate = |n: usize| -> f64 {
        if rounds_n == 0 { 0.0 } else { (n as f64 / rounds_n as f64 * 1000.0).round() / 10.0 }
    };
    let smoke_loss_pct = if expected_total == 0 { 0.0 } else { (lost_total as f64 / expected_total as f64 * 1000.0).round() / 10.0 };
    println!("== MATRIX SUMMARY track={track} side={side} rounds={rounds_n} profile={} ==", args.profile);
    println!("connection_success: {conn_ok}/{rounds_n} ({}%)", rate(conn_ok));
    println!("data_smoke_success(round_success): {smoke_ok}/{rounds_n} ({}%)  [口径: connect + pair确认 + smoke rx≥{}%×{MATRIX_SMOKE_N}]", rate(smoke_ok), args.smoke_threshold);
    println!("smoke packets: expected={expected_total} tx={tx_total} rx={rx_total} lost={lost_total} ({smoke_loss_pct}%)");
    println!("connect P50={:.1}ms P95={:.1}ms | gather P50={:.1}ms", p(&connects, 0.5), p(&connects, 0.95), p(&gathers, 0.5));
    println!("RTT P50={:.2}ms P95={:.2}ms",
        SmokeStats::pct(&mut all_rtts.clone(), 0.5), SmokeStats::pct(&mut all_rtts.clone(), 0.95));

    // M0-4R §八：Cold/Warm 分开统计（不混成一个 P50）
    let stat_group = |g: Vec<&RoundAgg>| -> serde_json::Value {
        let conn = g.iter().filter(|r| r.connect_success).count();
        let smk = g.iter().filter(|r| r.round_success).count();
        let mut cs: Vec<f64> = g.iter().filter(|r| r.connect_success).map(|r| r.connect.as_secs_f64() * 1000.0).collect();
        cs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mut gr: Vec<f64> = g.iter().filter(|r| r.connect_success).map(|r| r.gather.as_secs_f64() * 1000.0).collect();
        gr.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let exp = MATRIX_SMOKE_N * g.len();
        let tx: usize = g.iter().filter_map(|r| r.smoke_tx).sum();
        let rx: usize = g.iter().map(|r| r.smoke_rx).sum();
        serde_json::json!({
            "rounds": g.len(),
            "connection_success": format!("{conn}/{}", g.len()),
            "connection_success_rate": rate(conn),
            "data_smoke_success": format!("{smk}/{}", g.len()),
            "data_smoke_success_rate": rate(smk),
            "smoke_packets_expected": exp,
            "smoke_packets_tx": tx,
            "smoke_packets_rx": rx,
            "smoke_packets_lost": exp.saturating_sub(rx),
            "connect_p50_ms": p(&cs, 0.5),
            "connect_p95_ms": p(&cs, 0.95),
            "gather_p50_ms": p(&gr, 0.5),
        })
    };
    let cold = stat_group(rounds.iter().filter(|r| r.start_type == "cold").collect());
    let warm = stat_group(rounds.iter().filter(|r| r.start_type == "warm").collect());
    println!("cold_start: conn {} smoke {}  connect P50={:.1}ms", cold["connection_success"], cold["data_smoke_success"], cold["connect_p50_ms"]);
    println!("warm_start: conn {} smoke {}  connect P50={:.1}ms P95={:.1}ms", warm["connection_success"], warm["data_smoke_success"], warm["connect_p50_ms"], warm["connect_p95_ms"]);

    if args.report {
        let stun0 = args.stun.first().cloned().unwrap_or_default();
        let summary = serde_json::json!({
            "test_id": args.test_id,
            "track": track,
            "side": side,
            "engine": if track == 'b' { "MinimalPunchAgent" } else { "rtc-ice 0.20.4" },
            "rounds": rounds_n,
            "generated_at": iso_timestamp(),
            "profile": args.profile,
            "expected_selected_pair": profile_expected(&args.profile),
            "smoke_role": if is_creator { "echoer（smoke_packets_rx = 收到的对端 PING 数）" } else { "sender" },
            "round_success_definition": "connect_success AND selected_pair_confirmed AND smoke_packets_rx >= smoke_packets_expected × smoke_threshold_percent",
            "overall": {
                "rounds": rounds_n,
                "connection_success": format!("{conn_ok}/{rounds_n}"),
                "connection_success_rate": rate(conn_ok),
                "data_smoke_success": format!("{smoke_ok}/{rounds_n}"),
                "data_smoke_success_rate": rate(smoke_ok),
                "smoke_packets_expected": expected_total,
                "smoke_packets_tx": tx_total,
                "smoke_packets_rx": rx_total,
                "smoke_packets_lost": lost_total,
                "smoke_loss_percent": smoke_loss_pct,
                "connect_p50_ms": p(&connects, 0.5),
                "connect_p95_ms": p(&connects, 0.95),
                "gather_p50_ms": p(&gathers, 0.5),
                "rtt_p50_ms": SmokeStats::pct(&mut all_rtts.clone(), 0.5),
                "rtt_p95_ms": SmokeStats::pct(&mut all_rtts, 0.95),
            },
            "test_parameters": test_params_json(&args, MATRIX_SMOKE_N),
            "environment": env_snapshot(track, &stun0),
            "cold_start": cold,
            "warm_start": warm,
            "relay_used": false,
            "results": rounds.iter().map(|r| r.rec.clone()).collect::<Vec<_>>(),
        });
        write_result(&args.out_dir, &format!("summary-{side}.json"), summary);
    }
    if conn_ok < rounds_n {
        println!("FAIL: 存在失败轮次（connection {conn_ok}/{rounds_n}，data_smoke {smoke_ok}/{rounds_n}）");
        std::process::exit(1);
    }
    if smoke_ok < rounds_n {
        println!("WARN: 连接全部成功，但 {} 轮未达 smoke 阈值（data_smoke {smoke_ok}/{rounds_n}）——见 result-rNN.json 的 smoke_packets_rx", rounds_n - smoke_ok);
    }
}

/// M0-4R.2 §三：simultaneous punch 时间证据 → rec["punch_evidence"] + 控制台摘要。
/// 相对毫秒只做同端先后关系证明（两侧时钟不同步，anchor_epoch_ms 仅留档）。
fn attach_punch_evidence(dl: &DirectLinkTransport, role: &str, rec: &mut serde_json::Value) {
    let mut ev = dl.punch_evidence();
    if ev.is_null() {
        return;
    }
    ev["role"] = serde_json::json!(role);
    let fmt = |k: &str| ev[k].as_u64().map(|v| format!("+{v}ms")).unwrap_or_else(|| "none".into());
    println!("[punch-evidence] role={role} first_punch_tx={} first_peer_rx={}", fmt("first_punch_tx_ms"), fmt("first_peer_rx_ms"));
    rec["punch_evidence"] = ev;
}

async fn matrix_round_b(
    args: &Args, id: &str, i: usize, creator: bool,
    offer_p: &PathBuf, answer_sig: &PathBuf, punch_ok_p: &PathBuf, done_p: &PathBuf,
) -> RoundAgg {
    let mut rec = serde_json::json!({
        "engine": "MinimalPunchAgent",
        "remote_device_id": serde_json::Value::Null,
        "session_id": serde_json::Value::Null,
        "local_host_candidate": serde_json::Value::Null,
        "local_srflx_candidate": serde_json::Value::Null,
        "remote_host_candidate": serde_json::Value::Null,
        "remote_srflx_candidate": serde_json::Value::Null,
        "stun_server": args.stun.first().cloned().unwrap_or_default(),
        "selected_local_endpoint": serde_json::Value::Null,
        "selected_remote_endpoint": serde_json::Value::Null,
        "selected_pair_type": serde_json::Value::Null,
        "selected_pair_confirmed": false,
        "candidate_attempt_order": serde_json::Value::Null,
        "candidates_rejected": serde_json::Value::Null,
        "punch_evidence": serde_json::Value::Null,
    });
    if creator {
        // create 侧：start → accept → 写 offer → 等 ready 信号 → 等 session → echo
        let dl = start_transport_b(0, args.keepalive_ms, &args.stun).await;
        rec["stun_server"] = serde_json::json!(dl.first_stun_server().unwrap_or_default());
        rec["local_host_candidate"] = serde_json::json!(
            dl.local_candidates().first().map(|c| format!("{}:{}", c.addr.ip(), c.addr.port())).unwrap_or_default());
        rec["local_srflx_candidate"] = serde_json::json!(
            dl.srflx_candidates().first().map(|c| format!("{}:{}", c.addr.ip(), c.addr.port())).unwrap_or_default());
        // v3：matrix 同样只发物理 host 候选（与 create 行为一致）
        let host_eps: Vec<Endpoint> = dl.local_candidates().iter().filter(|c| !c.is_virtual).map(|c| Endpoint {
            ip: c.addr.ip().to_string(), port: c.addr.port(), kind: "host".into(),
        }).collect();
        let srflx_eps: Vec<Endpoint> = dl.srflx_candidates().iter().map(|c| Endpoint {
            ip: c.addr.ip().to_string(), port: c.addr.port(), kind: "server_reflexive".into(),
        }).collect();
        rec["candidate_attempt_order"] = serde_json::json!(host_eps.iter().chain(srflx_eps.iter())
            .enumerate().map(|(n, e)| format!("{} {} {}:{}", n + 1, e.kind, e.ip, e.port)).collect::<Vec<_>>());
        let (session_id, issued, expires, nonce) = make_code_header();
        rec["session_id"] = serde_json::json!(session_id.clone());
        // M0-5：每轮新会话 = 新 session tag + 新 Noise 身份（exchange 目录的
        // offer 文件直接带 k 公钥，join 侧 IK 握手绑定）
        let network_id = format!("meshlink-poc:{session_id}:{nonce}");
        let identity = gen_identity(id);
        let creator_fp = identity.fingerprint();
        rec["local_static_fingerprint"] = serde_json::json!(creator_fp);
        dl.configure_noise(std::sync::Arc::new(identity), network_id.clone());
        let offer = CodeOffer {
            schema_version: CODE_SCHEMA_VERSION, session_id, issued_at_ms: issued, expires_at_ms: expires, nonce,
            creator_device_id: id.into(), track: 'b', nat: String::new(),
            ufrag: String::new(), pwd: String::new(), k: creator_fp,
            host_candidates: host_eps, srflx_candidates: srflx_eps,
        };
        atomic_write(offer_p, &serde_json::to_vec(&offer).unwrap());
        dl.start_accepting(PeerId(PEER.into()), network_id);
        let _ = wait_file(answer_sig, Duration::from_secs(120)); // B transport 就绪信号
        // M0-4R：等 B 的真实 punch 结果（"ok"/"fail"），再取 session_info/echo。
        // 原 session_info 轮询已被外来 STUN 请求抢先满足（transport accept 已加
        // USERNAME 校验，此处信号化是双保险：record/echo 都落在真 session 上）。
        let t0 = Instant::now();
        let punch = wait_file(punch_ok_p, CHECK_TIMEOUT);
        let connect = t0.elapsed();
        match punch.as_deref() {
            Some(b"ok") => {}
            _ => {
                println!("[matrix] FAIL: create 侧等待对端 punch {}（{}）",
                    if punch.is_some() { "失败" } else { "超时" }, format!("{:.1}s", connect.as_secs_f64()));
                rec["error_stage"] = serde_json::json!(if punch.is_some() { Stage::Punch.as_str() } else { Stage::ConnectivityCheck.as_str() });
                // §三：失败轮同样留证据（join 已 probe 到达但未完成时 creator 有 peer_rx）
                attach_punch_evidence(&dl, "creator", &mut rec);
                return RoundAgg {
                    connect_success: false, round_success: false, connect, gather: Duration::ZERO,
                    smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
                };
            }
        }
        let (local_ep, remote, kind) = dl.session_info(&PeerId(PEER.into())).unwrap();
        rec["selected_local_endpoint"] = serde_json::json!(local_ep.to_string());
        rec["selected_remote_endpoint"] = serde_json::json!(remote.to_string());
        rec["selected_pair_type"] = serde_json::json!(format!("host(local) ↔ {kind:?}(remote)"));
        rec["selected_pair_origin"] = serde_json::json!(match kind {
            CandidateKind::PeerReflexive => "prflx",
            CandidateKind::ServerReflexive => "srflx",
            CandidateKind::Host => "host",
        });
        rec["peer_reflexive_candidates"] = serde_json::json!([]);
        rec["selected_pair_confirmed"] = serde_json::json!(true);
        // creator = echoer：收到的对端 PING 数即数据面 rx（与 joiner 的 PONG 计数交叉核对）
        attach_punch_evidence(&dl, "creator", &mut rec);
        let echoed = echo_b_for(&dl, Duration::from_secs(10), done_p).await;
        // M0-5：echo 结束后记录加密通道证据（established/frames_tx/rx/防重放统计）
        attach_crypto_report(&dl, "creator", Some(&mut rec));
        return RoundAgg {
            connect_success: true, round_success: false, connect, gather: Duration::ZERO,
            smoke_tx: None, smoke_rx: echoed, rtts: vec![], start_type: "", rec,
        };
    }
    // join 侧：等 offer → 校验（v2/过期/候选过滤）→ start（就绪即发信号）→ connect → ping/pong → done
    let Some(bytes) = wait_file(offer_p, Duration::from_secs(120)) else {
        println!("[matrix] FAIL: 等待 offer 超时");
        rec["error_stage"] = serde_json::json!(Stage::CandidateExchange.as_str());
        rec["error_code"] = serde_json::json!("offer_wait_timeout");
        return RoundAgg {
            connect_success: false, round_success: false, connect: Duration::ZERO, gather: Duration::ZERO,
            smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
        };
    };
    // exchange 文件同样是不可信输入（可能残留旧版/过期文件）：统一校验
    let (offer, rejected) = match serde_json::from_slice::<CodeOffer>(&bytes)
        .map_err(|e| code_invalid(format!("json_parse_failed（{e}）")))
        .and_then(validate_offer)
    {
        Ok((o, rej)) => (o, rej),
        Err(e) => {
            println!("[matrix] FAIL: offer 校验失败: {}（{}）", e.code, e.reason);
            rec["error_stage"] = serde_json::json!(Stage::CandidateExchange.as_str());
            rec["error_code"] = serde_json::json!(e.code);
            rec["error_detail"] = serde_json::json!(e.reason);
            return RoundAgg {
                connect_success: false, round_success: false, connect: Duration::ZERO, gather: Duration::ZERO,
                smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
            };
        }
    };
    rec["session_id"] = serde_json::json!(offer.session_id.clone());
    rec["remote_device_id"] = serde_json::json!(offer.creator_device_id);
    rec["remote_host_candidate"] = serde_json::json!(offer.host_candidates.first()
        .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default());
    rec["remote_srflx_candidate"] = serde_json::json!(offer.srflx_candidates.first()
        .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default());
    rec["candidates_rejected"] = serde_json::json!(rejected.iter()
        .map(|(t, r)| serde_json::json!({"candidate": t, "reason": r})).collect::<Vec<_>>());
    rec["candidate_attempt_order"] = serde_json::json!(
        offer.host_candidates.iter().chain(offer.srflx_candidates.iter()).enumerate()
            .map(|(n, e)| format!("{} {} {}:{}", n + 1, e.kind, e.ip, e.port)).collect::<Vec<_>>());
    let t0 = Instant::now();
    let dl = start_transport_b(0, args.keepalive_ms, &args.stun).await;
    rec["stun_server"] = serde_json::json!(dl.first_stun_server().unwrap_or_default());
    rec["local_host_candidate"] = serde_json::json!(
        dl.local_candidates().first().map(|c| format!("{}:{}", c.addr.ip(), c.addr.port())).unwrap_or_default());
    rec["local_srflx_candidate"] = serde_json::json!(
        dl.srflx_candidates().first().map(|c| format!("{}:{}", c.addr.ip(), c.addr.port())).unwrap_or_default());
    // transport 就绪即发信号：creator 收到后立刻进入 accept+echo 等待，
    // connect 一成功 smoke 立即可通（曾等 connect 后才发 → creator 未进 echo，PING 全丢）
    atomic_write(answer_sig, b"ready");
    let gather = t0.elapsed();
    // M0-4 双向 punch：matrix joiner 同样携带 session tag 与本端候选集。
    // M0-5：session tag = Noise prologue network_id（与 creator configure_noise 同值）。
    let network_id = format!("meshlink-poc:{}:{}", offer.session_id, offer.nonce);
    dl.set_punch_session(
        network_id.clone(),
        dl.punch_candidates_wire(),
    );
    let t1 = Instant::now();
    let r = dl.connect_peer(
        PeerId(PEER.into()),
        PeerHints {
            endpoints: offer.host_candidates.iter().chain(offer.srflx_candidates.iter()).cloned().collect(),
            static_key_fingerprint: Some(offer.k.clone()),
            overlay_mac: None,
        },
    ).await;
    // §三：成败都留证据——joiner 首包必先于任何入站（tx < rx 即主动出站证明）
    attach_punch_evidence(&dl, "joiner", &mut rec);
    if r.is_err() {
        atomic_write(punch_ok_p, b"fail");
        rec["error_stage"] = serde_json::json!("punch_timeout");
        return RoundAgg {
            connect_success: false, round_success: false, connect: t1.elapsed(), gather,
            smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
        };
    }
    let connect = t1.elapsed();
    let (local_ep, remote, kind) = dl.session_info(&PeerId(PEER.into())).unwrap();
    rec["selected_local_endpoint"] = serde_json::json!(local_ep.to_string());
    rec["selected_remote_endpoint"] = serde_json::json!(remote.to_string());
    rec["selected_pair_type"] = serde_json::json!(format!("host(local) ↔ {kind:?}(remote)"));
    rec["selected_pair_origin"] = serde_json::json!(match kind {
        CandidateKind::PeerReflexive => "prflx",
        CandidateKind::ServerReflexive => "srflx",
        CandidateKind::Host => "host",
    });
    rec["peer_reflexive_candidates"] = serde_json::json!([]);
    rec["selected_pair_confirmed"] = serde_json::json!(true);
    println!("[matrix] round {i} selected pair: host(local) ↔ {kind:?}(remote) remote={remote}");
    // M0-5：Noise IK 握手完成才发 "ok"——creator 侧 punch_ok 语义升级为
    // 「打洞 + 加密通道就绪」，失败/超时同样走 "fail" 分支（echo 等 smoke 不会空转）
    let t_hs = Instant::now();
    let joiner_identity = std::sync::Arc::new(gen_identity(id));
    rec["local_static_fingerprint"] = serde_json::json!(joiner_identity.fingerprint());
    rec["remote_static_fingerprint"] = serde_json::json!(offer.k);
    // 理论不可达：validate_offer 已对 Track B 校验 k（64-hex），仍显式失败不 panic
    let Some(remote_key) = key_hex::decode_key32(&offer.k) else {
        println!("[matrix] round {i} FAIL: k 公钥解码失败");
        atomic_write(punch_ok_p, b"fail");
        rec["error_stage"] = serde_json::json!(Stage::CandidateExchange.as_str());
        rec["error_code"] = serde_json::json!("static_key_invalid");
        return RoundAgg {
            connect_success: false, round_success: false, connect, gather,
            smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
        };
    };
    match dl
        .start_noise_initiator(
            &PeerId(PEER.into()),
            joiner_identity,
            &network_id,
            &offer.creator_device_id,
            &remote_key,
        )
        .await
    {
        Ok(noise_sid) => {
            rec["noise_handshake_ms"] = serde_json::json!(
                (t_hs.elapsed().as_secs_f64() * 1000.0 * 10.0).round() / 10.0);
            rec["noise_session_id"] = serde_json::json!(key_hex::encode_lower(&noise_sid));
        }
        Err(e) => {
            println!("[matrix] round {i} FAIL: Noise 握手失败: {e:?}");
            atomic_write(punch_ok_p, b"fail");
            rec["error_stage"] = serde_json::json!(Stage::NoiseHandshake.as_str());
            rec["error_code"] = serde_json::json!("noise_handshake_failed");
            rec["error_detail"] = serde_json::json!(format!("{e:?}"));
            return RoundAgg {
                connect_success: false, round_success: false, connect, gather,
                smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
            };
        }
    }
    atomic_write(punch_ok_p, b"ok"); // creator 见此才取 record/echo
    let st = ping_pong_b(&dl, MATRIX_SMOKE_N).await;
    atomic_write(done_p, b"done");
    attach_crypto_report(&dl, "joiner", Some(&mut rec));
    RoundAgg {
        connect_success: true, round_success: false, connect, gather,
        smoke_tx: Some(st.sent), smoke_rx: st.recv, rtts: st.rtts, start_type: "", rec,
    }
}

fn matrix_round_a(
    args: &Args, _id: &str, creator: bool,
    offer_p: &PathBuf, answer_p: &PathBuf, done_p: &PathBuf,
) -> RoundAgg {
    let mut rec = serde_json::json!({
        "engine": "rtc-ice 0.20.4",
        "remote_device_id": serde_json::Value::Null,
        "session_id": serde_json::Value::Null,
        "local_host_candidate": serde_json::Value::Null,
        "local_srflx_candidate": serde_json::Value::Null,
        "remote_host_candidate": serde_json::Value::Null,
        "remote_srflx_candidate": serde_json::Value::Null,
        "stun_server": args.stun.first().cloned().unwrap_or_default(),
        "selected_local_endpoint": serde_json::Value::Null,
        "selected_remote_endpoint": serde_json::Value::Null,
        "selected_pair_type": serde_json::Value::Null,
        "selected_pair_confirmed": false,
        "candidates_rejected": serde_json::Value::Null,
    });
    if creator {
        let a = make_agent_a(0, &args.stun);
        rec["local_host_candidate"] = serde_json::json!(a.local_base().to_string());
        if let Some(m) = a.srflx_addr() { rec["local_srflx_candidate"] = serde_json::json!(m.to_string()); }
        let (ufrag, pwd) = a.credentials();
        let (host_eps, srflx_eps) = endpoints_of_a(&a);
        let (session_id, issued, expires, nonce) = make_code_header();
        rec["session_id"] = serde_json::json!(session_id.clone());
        let offer = CodeOffer {
            schema_version: CODE_SCHEMA_VERSION, session_id, issued_at_ms: issued, expires_at_ms: expires, nonce,
            creator_device_id: _id.into(), track: 'a', nat: String::new(),
            ufrag, pwd, k: String::new(), host_candidates: host_eps, srflx_candidates: srflx_eps,
        };
        atomic_write(offer_p, &serde_json::to_vec(&offer).unwrap());
        let Some(bytes) = wait_file(answer_p, Duration::from_secs(120)) else {
            println!("[matrix] FAIL: 等待 answer 超时");
            rec["error_stage"] = serde_json::json!(Stage::CandidateExchange.as_str());
            rec["error_code"] = serde_json::json!("answer_wait_timeout");
            return RoundAgg {
                connect_success: false, round_success: false, connect: Duration::ZERO, gather: Duration::ZERO,
                smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
            };
        };
        // answer 文件是不可信输入：统一校验（含过期——旧 answer 文件直接判失败）
        let (b, rejected) = match serde_json::from_slice::<CodeOffer>(&bytes)
            .map_err(|e| code_invalid(format!("json_parse_failed（{e}）")))
            .and_then(validate_offer)
        {
            Ok((o, rej)) => (o, rej),
            Err(e) => {
                println!("[matrix] FAIL: answer 校验失败: {}（{}）", e.code, e.reason);
                rec["error_stage"] = serde_json::json!(Stage::CandidateExchange.as_str());
                rec["error_code"] = serde_json::json!(e.code);
                rec["error_detail"] = serde_json::json!(e.reason);
                return RoundAgg {
                    connect_success: false, round_success: false, connect: Duration::ZERO, gather: Duration::ZERO,
                    smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
                };
            }
        };
        rec["remote_device_id"] = serde_json::json!(b.creator_device_id);
        rec["remote_host_candidate"] = serde_json::json!(b.host_candidates.first()
            .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default());
        rec["remote_srflx_candidate"] = serde_json::json!(b.srflx_candidates.first()
            .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default());
        rec["candidates_rejected"] = serde_json::json!(rejected.iter()
            .map(|(t, r)| serde_json::json!({"candidate": t, "reason": r})).collect::<Vec<_>>());
        let t0 = Instant::now();
        let remote_eps: Vec<Endpoint> = b.host_candidates.iter().chain(b.srflx_candidates.iter()).cloned().collect();
        match a.accept(b.ufrag, b.pwd, &remote_eps.iter().map(|e| parse_ep(e)).collect::<Vec<_>>(), CHECK_TIMEOUT) {
            Ok(remote) => {
                let connect = t0.elapsed();
                rec["selected_local_endpoint"] = serde_json::json!(a.local_base().to_string());
                rec["selected_remote_endpoint"] = serde_json::json!(remote.to_string());
                rec["selected_pair_type"] = serde_json::json!("host(local) ↔ ?(remote)");
                // M0-4 §八：Track A 从 SelectedCandidatePairChange 事件取 pair 证据
                let (origin, prflx) = a.selected_pair_evidence();
                rec["selected_pair_origin"] = serde_json::json!(origin);
                rec["peer_reflexive_candidates"] = serde_json::json!(prflx);
                rec["selected_pair_confirmed"] = serde_json::json!(true);
                let echoed = echo_a_for(&a, Duration::from_secs(10));
                let _ = wait_file(done_p, Duration::from_secs(30));
                RoundAgg {
                    connect_success: true, round_success: false, connect, gather: Duration::ZERO,
                    smoke_tx: None, smoke_rx: echoed, rtts: vec![], start_type: "", rec,
                }
            }
            Err(e) => {
                println!("[matrix] FAIL: accept 超时: {e}");
                rec["error_stage"] = serde_json::json!(Stage::ConnectivityCheck.as_str());
                let _ = std::fs::write(done_p, b"fail");
                RoundAgg {
                    connect_success: false, round_success: false, connect: t0.elapsed(), gather: Duration::ZERO,
                    smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
                }
            }
        }
    } else {
        let Some(bytes) = wait_file(offer_p, Duration::from_secs(120)) else {
            println!("[matrix] FAIL: 等待 offer 超时");
            rec["error_stage"] = serde_json::json!(Stage::CandidateExchange.as_str());
            rec["error_code"] = serde_json::json!("offer_wait_timeout");
            return RoundAgg {
                connect_success: false, round_success: false, connect: Duration::ZERO, gather: Duration::ZERO,
                smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
            };
        };
        let (offer, rejected) = match serde_json::from_slice::<CodeOffer>(&bytes)
            .map_err(|e| code_invalid(format!("json_parse_failed（{e}）")))
            .and_then(validate_offer)
        {
            Ok((o, rej)) => (o, rej),
            Err(e) => {
                println!("[matrix] FAIL: offer 校验失败: {}（{}）", e.code, e.reason);
                rec["error_stage"] = serde_json::json!(Stage::CandidateExchange.as_str());
                rec["error_code"] = serde_json::json!(e.code);
                rec["error_detail"] = serde_json::json!(e.reason);
                return RoundAgg {
                    connect_success: false, round_success: false, connect: Duration::ZERO, gather: Duration::ZERO,
                    smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
                };
            }
        };
        rec["session_id"] = serde_json::json!(offer.session_id.clone());
        rec["remote_device_id"] = serde_json::json!(offer.creator_device_id);
        rec["remote_host_candidate"] = serde_json::json!(offer.host_candidates.first()
            .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default());
        rec["remote_srflx_candidate"] = serde_json::json!(offer.srflx_candidates.first()
            .map(|e| format!("{}:{}", e.ip, e.port)).unwrap_or_default());
        rec["candidates_rejected"] = serde_json::json!(rejected.iter()
            .map(|(t, r)| serde_json::json!({"candidate": t, "reason": r})).collect::<Vec<_>>());
        let t0 = Instant::now();
        let b = make_agent_a(0, &args.stun);
        rec["local_host_candidate"] = serde_json::json!(b.local_base().to_string());
        if let Some(m) = b.srflx_addr() { rec["local_srflx_candidate"] = serde_json::json!(m.to_string()); }
        let gather = t0.elapsed();
        let t1 = Instant::now();
        let remote_eps: Vec<Endpoint> = offer.host_candidates.iter().chain(offer.srflx_candidates.iter()).cloned().collect();
        // answer 必须先落盘再 dial：creator 读到 answer 才 accept；dial 成功后才写
        // 会导致死锁（joiner 的检查无响应，creator 永远等不到 answer）
        let (ufrag, pwd) = b.credentials();
        let (host_eps, srflx_eps) = endpoints_of_a(&b);
        let (session_id, issued, expires, nonce) = make_code_header();
        let answer = CodeOffer {
            schema_version: CODE_SCHEMA_VERSION, session_id, issued_at_ms: issued, expires_at_ms: expires, nonce,
            creator_device_id: device_id(), track: 'a', nat: String::new(),
            ufrag, pwd, k: String::new(), host_candidates: host_eps, srflx_candidates: srflx_eps,
        };
        atomic_write(answer_p, &serde_json::to_vec(&answer).unwrap());
        let remote = match b.dial(offer.ufrag.clone(), offer.pwd.clone(), &remote_eps.iter().map(|e| parse_ep(e)).collect::<Vec<_>>(), CHECK_TIMEOUT) {
            Ok(r) => r,
            Err(e) => {
                println!("[matrix] FAIL: dial: {e}");
                rec["error_stage"] = serde_json::json!("punch_timeout");
                atomic_write(done_p, b"fail");
                return RoundAgg {
                    connect_success: false, round_success: false, connect: t1.elapsed(), gather,
                    smoke_tx: None, smoke_rx: 0, rtts: vec![], start_type: "", rec,
                };
            }
        };
        let connect = t1.elapsed();
        rec["selected_local_endpoint"] = serde_json::json!(b.local_base().to_string());
        rec["selected_remote_endpoint"] = serde_json::json!(remote.to_string());
        rec["selected_pair_type"] = serde_json::json!("host(local) ↔ ?(remote)");
        // M0-4 §八：Track A 从 SelectedCandidatePairChange 事件取 pair 证据
        let (origin, prflx) = b.selected_pair_evidence();
        rec["selected_pair_origin"] = serde_json::json!(origin);
        rec["peer_reflexive_candidates"] = serde_json::json!(prflx);
        rec["selected_pair_confirmed"] = serde_json::json!(true);
        let st = ping_pong_raw(&b, remote, MATRIX_SMOKE_N);
        atomic_write(done_p, b"done");
        RoundAgg {
            connect_success: true, round_success: false, connect, gather,
            smoke_tx: Some(st.sent), smoke_rx: st.recv, rtts: st.rtts, start_type: "", rec,
        }
    }
}

/// creator（echoer）侧：统计收到的 PING 数（=数据面 rx）并回 PONG。
fn echo_b_for<'a>(dl: &'a DirectLinkTransport, dur: Duration, stop: &'a PathBuf) -> std::pin::Pin<Box<dyn std::future::Future<Output = usize> + Send + 'a>> {
    Box::pin(async move {
        let Some(mut rx) = dl.packet_rx(&PeerId(PEER.into())) else { return 0 };
        let deadline = Instant::now() + dur;
        let mut echoed: usize = 0;
        loop {
            let now = Instant::now();
            if now >= deadline || stop.exists() { return echoed; }
            match tokio::time::timeout(deadline - now, rx.recv()).await {
                Ok(Some(pkt)) => {
                    let text = String::from_utf8_lossy(&pkt[20.min(pkt.len())..]).to_string();
                    if let Some(rest) = text.strip_prefix("PING-") {
                        echoed += 1;
                        let _ = dl.send_packet(PeerId(PEER.into()), ipv4_frame(format!("PONG-{rest}").as_bytes())).await;
                    }
                }
                _ => continue,
            }
        }
    })
}

fn echo_a_for(a: &WebRtcIceAgent, dur: Duration) -> usize {
    let deadline = Instant::now() + dur;
    let mut echoed: usize = 0;
    loop {
        let now = Instant::now();
        if now >= deadline { return echoed; }
        if let Some((from, pkt)) = a.raw_recv(Duration::from_millis(100)) {
            let text = String::from_utf8_lossy(&pkt).to_string();
            if let Some(rest) = text.strip_prefix("PING-") {
                echoed += 1;
                let _ = a.raw_send(format!("PONG-{rest}").as_bytes(), from);
            }
        }
    }
}

fn atomic_write(p: &PathBuf, data: &[u8]) {
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, data).expect("写文件");
    std::fs::rename(&tmp, p).expect("rename");
}

fn wait_file(p: &PathBuf, timeout: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(bytes) = std::fs::read(p) {
            if !bytes.is_empty() {
                if p.extension().map(|e| e == "json").unwrap_or(false) {
                    if serde_json::from_slice::<serde_json::Value>(&bytes).is_err() { continue; } // 半截文件
                }
                return Some(bytes);
            }
        }
        if Instant::now() >= deadline { return None; }
        std::thread::sleep(Duration::from_millis(200));
    }
}

// ---------- M0-5 Session Code v4 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hex64() -> String {
        let id = StaticIdentity::generate("k-test").expect("generate");
        id.fingerprint()
    }

    fn offer_v4(track: char, k: &str) -> CodeOffer {
        let issued = now_ms() as u64;
        CodeOffer {
            schema_version: CODE_SCHEMA_VERSION,
            session_id: "a1b2c3d4".into(),
            issued_at_ms: issued,
            expires_at_ms: issued + CODE_TTL_MS,
            nonce: "deadbeef".into(),
            creator_device_id: "creator-dev".into(),
            track,
            nat: String::new(),
            ufrag: String::new(),
            pwd: String::new(),
            k: k.into(),
            host_candidates: vec![Endpoint { ip: "192.168.1.10".into(), port: 42000, kind: "host".into() }],
            srflx_candidates: vec![Endpoint { ip: "1.2.3.4".into(), port: 50000, kind: "server_reflexive".into() }],
        }
    }

    #[test]
    fn v4_roundtrip_preserves_k() {
        let k = key_hex64();
        let code = encode_code(&offer_v4('b', &k));
        let (o, rejected) = parse_session_code(&code).expect("parse v4");
        assert!(rejected.is_empty());
        assert_eq!(o.k, k);
        assert_eq!(o.track, 'b');
        assert_eq!(o.host_candidates[0].ip, "192.168.1.10");
    }

    #[test]
    fn track_a_without_k_is_valid() {
        let code = encode_code(&offer_v4('a', ""));
        let (o, _) = parse_session_code(&code).expect("parse v4 track A");
        assert_eq!(o.k, "");
        assert_eq!(o.ufrag, "");
    }

    #[test]
    fn track_b_without_k_rejected() {
        let code = encode_code(&offer_v4('b', ""));
        let e = parse_session_code(&code).expect_err("must reject");
        assert_eq!(e.code, "SESSION_CODE_INVALID");
        assert!(e.reason.contains("static_key_missing"), "reason={}", e.reason);
    }

    #[test]
    fn track_b_bad_k_rejected() {
        let code = encode_code(&offer_v4('b', "zz-not-hex"));
        let e = parse_session_code(&code).expect_err("must reject");
        assert_eq!(e.code, "SESSION_CODE_INVALID");
        assert!(e.reason.contains("static_key_invalid"), "reason={}", e.reason);
    }

    #[test]
    fn v3_code_rejected_by_version() {
        // encode_code 恒写当前版本——旧版本码需手工构造 wire 模拟
        let w = serde_json::json!({
            "v": 3,
            "sid": "a1b2c3d4",
            "iat": now_ms() as u64,
            "eat": now_ms() as u64 + CODE_TTL_MS,
            "n": "deadbeef",
            "dev": "creator-dev",
            "t": "b",
            "k": key_hex64(),
            "h": [[ip_to_wire("192.168.1.10").expect("ip"), 42000]],
            "s": [[ip_to_wire("1.2.3.4").expect("ip"), 50000]],
        });
        let code = b64encode(&serde_json::to_vec(&w).expect("wire"));
        let e = parse_session_code(&code).expect_err("must reject v3");
        assert_eq!(e.code, "SESSION_CODE_INVALID");
        assert!(e.reason.contains("schema_version_unsupported"), "reason={}", e.reason);
    }

    /// 篡改 k 中任意一个字符 → 解析成功但与真实公钥不匹配 → IK 握手
    /// 必然失败（wrong_expected_static_rejected，crypto 模块已测）。
    /// 此处验证：解析层不因篡改 panic，且指纹可被逐字节比对。
    #[test]
    fn tampered_k_still_parses_but_differs() {
        let k = key_hex64();
        let mut tampered = k.clone();
        // 翻转一个 hex 字符（保持 64-hex 合法格式）
        let flip = if tampered.starts_with('0') { '1' } else { '0' };
        tampered.replace_range(0..1, &flip.to_string());
        let code = encode_code(&offer_v4('b', &tampered));
        let (o, _) = parse_session_code(&code).expect("tampered but well-formed");
        assert_ne!(o.k, k, "篡改后的 k 必须与原指纹不同");
    }

    /// 真实身份公钥 ↔ 码内 k 的一致性（create 端写入的即是自己的公钥）。
    #[test]
    fn offer_k_matches_creator_identity() {
        let id = StaticIdentity::generate("creator-dev").expect("generate");
        let code = encode_code(&offer_v4('b', &id.fingerprint()));
        let (o, _) = parse_session_code(&code).expect("parse");
        let remote = key_hex::decode_key32(&o.k).expect("decode k");
        assert_eq!(&remote, id.public());
    }
}
