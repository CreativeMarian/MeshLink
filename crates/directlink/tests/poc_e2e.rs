//! M0-5 双进程 E2E（本机真实 NIC）：create → Session Code v4 → join →
//! Noise IK 握手 → 加密 smoke 20/20 → result.json crypto 段。
//!
//! 自动化验证（无人工步骤）：cargo test 起两个真实进程，通过 stdout 的
//! `[UI]` 状态行驱动（--friend 模式），断言两端加密通道建立与数据往返。
//!
//! 覆盖的反向路径：篡改连接码中已预期的 responder static public key 后，
//! Noise IK 握手必须失败——证明握手能够检测 expected-key mismatch。
//! （注意：这不等于声称 Noise IK 已解决 signaling 公钥替换/中间人问题；
//! 公钥真实性必须由 Controller 身份系统提供。）

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_directlink-poc");
/// join smoke 20 包 × ~700ms + gathering，正常 < 30s；留 3 倍余量。
const WAIT_RESULT: Duration = Duration::from_secs(120);
const WAIT_CODE: Duration = Duration::from_secs(30);

struct Proc {
    child: Child,
    out: std::sync::mpsc::Receiver<String>,
}

impl Proc {
    fn spawn(args: &[&str]) -> Self {
        let mut child = Command::new(BIN)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn directlink-poc");
        let stdout = child.stdout.take().expect("piped stdout");
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                let _ = tx.send(line);
            }
        });
        Self { child, out: rx }
    }

    /// 等待输出中出现包含 `marker` 的行，返回该行。
    fn wait_line(&self, marker: &str, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        while let Ok(line) = self.out.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            if line.contains(marker) {
                return Some(line);
            }
        }
        None
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.kill();
    }
}

#[test]
fn e2e_create_join_noise_encrypted() {
    // 1. creator 起进程（真实 NIC host 候选 + v4 码带 k 公钥）
    let creator = Proc::spawn(&[
        "create", "--track", "b", "--port", "42110", "--id", "e2e-creator", "--friend",
    ]);
    let code_line = creator
        .wait_line("[UI] SESSION_CODE:", WAIT_CODE)
        .expect("creator 应在 30s 内输出连接码");
    let code = code_line
        .trim_start_matches("[UI] SESSION_CODE:")
        .trim()
        .to_string();
    assert!(!code.is_empty(), "连接码不应为空");
    assert!(code.len() > 100, "v4 码应携带 64 hex 公钥（长度 {} 异常）", code.len());

    // 2. joiner 起进程：解析 v4 码 → punch → IK 握手 → 20 包加密 smoke
    let out_dir = std::env::temp_dir().join(format!("dl-poc-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    let out_dir_s = out_dir.to_string_lossy().to_string();
    let joiner = Proc::spawn(&[
        "join", &code,
        "--port", "0",
        "--id", "e2e-joiner",
        "--friend",
        "--report",
        "--out-dir", &out_dir_s,
        "--test-id", "e2e-noise",
    ]);

    // 3. 两端状态断言：握手建立 + 数据面加密
    let noise_a = creator.wait_line("[UI] NOISE: established", WAIT_RESULT)
        .expect("creator 侧 IK 握手应完成");
    let noise_b = joiner.wait_line("[UI] NOISE: established", WAIT_RESULT)
        .expect("joiner 侧 IK 握手应完成");
    assert!(noise_a.contains("NOISE"), "{noise_a}");
    assert!(noise_b.contains("NOISE"), "{noise_b}");

    // 4. joiner 20/20 加密 smoke 通过（round_success 阈值默认 100%）
    joiner.wait_line("[UI] RESULT: SUCCESS", WAIT_RESULT)
        .expect("joiner 应完成加密 smoke 并输出 SUCCESS");

    // 5. result.json 的 crypto 段：established=true + 帧收发计数 + 无解密失败
    let result = std::fs::read_to_string(out_dir.join("result.json"))
        .expect("joiner --report 应写 result.json");
    let v: serde_json::Value = serde_json::from_str(&result).expect("result.json 应为合法 JSON");
    assert_eq!(v["connect_success"], true, "打洞应成功");
    assert_eq!(v["round_success"], true, "加密 smoke 20/20 应达标");
    assert_eq!(
        v["crypto"]["established"], true,
        "crypto.established 应为 true（实际: {}）",
        v["crypto"]
    );
    let frames_rx = v["crypto"]["frames_rx"].as_u64().unwrap_or(0);
    assert!(frames_rx >= 20, "加密帧接收应 ≥ 20（实际 {frames_rx}）");
    assert_eq!(v["crypto"]["decrypt_failed"], 0, "不应有解密失败");
    assert_eq!(v["crypto"]["replay_rejected"], 0, "不应有重放拒收");
    let remote_fp = v["remote_static_fingerprint"].as_str().unwrap_or_default();
    assert_eq!(remote_fp.len(), 64, "remote_static_fingerprint 应为 64 hex");
}

/// 反向验证：篡改 k 公钥（模拟连接码中的公钥被替换）→ punch 仍可成功，但
/// 已预期的 responder static public key 不再匹配，Noise IK 握手必然失败
/// （noise_handshake_failed），绝不静默降级为明文。
/// 该测试仅证明握手能检测 expected-key mismatch；公钥真实性（防 signaling
/// 层替换）须由 Controller 身份系统提供。
#[test]
fn e2e_tampered_key_handshake_fails() {
    let creator = Proc::spawn(&[
        "create", "--track", "b", "--port", "42112", "--id", "e2e-creator2", "--friend",
    ]);
    let code_line = creator
        .wait_line("[UI] SESSION_CODE:", WAIT_CODE)
        .expect("creator 应输出连接码");
    let code = code_line.trim_start_matches("[UI] SESSION_CODE:").trim().to_string();

    // 篡改：解码 wire → 替换 k 为另一个合法 64-hex（不是 creator 的公钥）→ 重编码。
    // 与真码仅 k 不同——模拟「连接码中公钥被替换」场景（expected-key mismatch）。
    let tampered = tamper_key(&code);
    assert_ne!(tampered, code, "篡改后的码应与原码不同");

    let out_dir = std::env::temp_dir().join(format!("dl-poc-e2e-mitm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out_dir);
    let out_dir_s = out_dir.to_string_lossy().to_string();
    let joiner = Proc::spawn(&[
        "join", &tampered,
        "--port", "0",
        "--id", "e2e-joiner2",
        "--friend",
        "--report",
        "--out-dir", &out_dir_s,
        "--test-id", "e2e-tampered-key",
    ]);

    // 握手重试 5×400ms 后必须显式 FAIL:noise_handshake_failed（不挂死、不明文降级）
    let line = joiner
        .wait_line("[UI] RESULT: FAIL:", Duration::from_secs(60))
        .expect("篡改 k 后 joiner 应显式 FAIL");
    assert!(
        line.contains("noise_handshake_failed"),
        "应为 noise_handshake_failed（实际: {line}）"
    );

    let result = std::fs::read_to_string(out_dir.join("result.json"))
        .expect("失败也应写 result.json（禁止只有 FAIL 无报告）");
    let v: serde_json::Value = serde_json::from_str(&result).expect("合法 JSON");
    assert_eq!(v["error_code"], "noise_handshake_failed");
    assert_eq!(v["error_stage"], "noise_handshake_failed");
}

// ---------- 连接码篡改工具（测试专用：与 PoC 的 wire 格式对称） ----------

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64decode(s: &str) -> Vec<u8> {
    let val = |c: u8| B64URL.iter().position(|&x| x == c).unwrap_or(0) as u32;
    let bytes: Vec<u8> = s.trim_end_matches('=').bytes().collect();
    let mut out = Vec::new();
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c) << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 { out.push((n >> 8) as u8); }
        if chunk.len() > 3 { out.push(n as u8); }
    }
    out
}

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

/// 解码 v4 连接码 → 把 k 替换为「另一个」合法 64-hex 公钥 → 重编码。
fn tamper_key(code: &str) -> String {
    let mut w: serde_json::Value =
        serde_json::from_slice(&b64decode(code)).expect("v4 码应为合法 JSON");
    // 64 个 'a'——hex 合法、格式合法，但不是 creator 的真实公钥
    w["k"] = serde_json::json!("a".repeat(64));
    b64encode(&serde_json::to_vec(&w).expect("re-serialize"))
}
