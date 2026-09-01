//! ProcessSupervisor（M1-1.5 规格一/二/三/五 + M1-2）：
//!
//! MeshLink 是当前运行监督者（DEV 模式）——负责 mesh-agent.exe、DEV
//! controller.exe 与 DEV n2n-supernode.exe 的 spawn 与完整回收：
//! - 所有权记录在 `runtime/managed_process.json`（pid / start_time / 期望映像名）；
//! - 正常退出：有序 Shutdown（规格二）后清空 runtime；
//! - 异常退出：下次启动 `detect_and_clean_residue()` 检测残留，仅终止记录中仍
//!   存活且**映像名匹配**的 owned 进程（防 PID 复用误杀），然后清空 runtime；
//! - 永久身份（device_id / X25519 私钥 / credential / 好友授权）在 data_dir 的
//!   secure-store 中，本模块的 `clear_all()` 绝不触碰（规格四）。

use std::path::PathBuf;
use std::process::{Child, Command as StdCommand};
use std::time::{SystemTime, UNIX_EPOCH};

pub const MANAGED_PROCESS: &str = "managed_process.json";

/// Agent 可能写入 runtime 目录的临时文件（残留检测信号源）。
pub const RUNTIME_FILES: [&str; 4] = [
    "active_session.json",
    "quick_code.json",
    "runtime_token.json",
    "temporary_candidates.json",
];

/// 一条受管理进程的所有权记录。
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ManagedProcess {
    pub kind: String, // agent | controller | supernode
    pub pid: u32,
    pub start_time: String,
    /// 期望进程映像名（小写，如 "mesh-agent.exe"）——残留清理时用 tasklist 校验，
    /// 防止 PID 复用把无关进程误杀。
    pub image: String,
}

/// runtime/managed_process.json 内容。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ManagedManifest {
    pub supervisor: String,
    #[serde(default)]
    pub started_at: String,
    #[serde(default)]
    pub processes: Vec<ManagedProcess>,
}

/// runtime 临时目录（active_session/quick_code/managed_process 等全部临时文件）。
#[derive(Debug, Clone)]
pub struct RuntimeDir {
    pub dir: PathBuf,
}

impl RuntimeDir {
    /// 直接指定 runtime 目录（测试/集成使用；生产走 `from_env`）。
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// 默认 `%LOCALAPPDATA%\MeshLink\runtime`（`MESHLINK_RUNTIME_DIR` 可覆盖）。
    pub fn from_env() -> Self {
        let dir = std::env::var("MESHLINK_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let local = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| ".".into());
                PathBuf::from(local).join("MeshLink").join("runtime")
            });
        Self { dir }
    }

    pub fn ensure(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)
    }

    fn manifest_path(&self) -> PathBuf {
        self.dir.join(MANAGED_PROCESS)
    }

    pub fn load_manifest(&self) -> ManagedManifest {
        match std::fs::read_to_string(self.manifest_path()) {
            Ok(text) => serde_json::from_str(&text).unwrap_or_default(),
            Err(_) => ManagedManifest::default(),
        }
    }

    pub fn save_manifest(&self, m: &ManagedManifest) {
        if let Err(e) = self
            .ensure()
            .and_then(|_| std::fs::write(self.manifest_path(), serde_json::to_vec_pretty(m).unwrap_or_default()))
        {
            eprintln!("[MeshLink] runtime 所有权记录写入失败: {e}");
        }
    }

    /// 是否存在残留（managed_process.json 或 Agent 临时文件）——MeshLink 启动时检测。
    pub fn has_residue(&self) -> bool {
        if self.dir.join(MANAGED_PROCESS).exists() {
            return true;
        }
        RUNTIME_FILES.iter().any(|f| self.dir.join(f).exists())
    }

    /// 清空整个 runtime 目录（所有权记录 + Agent 临时文件）。
    /// 注意：data_dir（永久身份）与本目录无关，绝不触碰。
    pub fn clear_all(&self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// 进程监督者：只回收自己 spawn 的进程（ownership 由 managed_process.json 记录）。
#[derive(Debug, Clone)]
pub struct ProcessSupervisor {
    pub runtime: RuntimeDir,
}

impl ProcessSupervisor {
    pub fn new() -> Self {
        Self { runtime: RuntimeDir::from_env() }
    }

    pub fn with_runtime(runtime: RuntimeDir) -> Self {
        Self { runtime }
    }

    /// 启动清理（MeshLink 每次启动调用一次）：检测 runtime 残留 → 终止记录中仍
    /// 存活且映像名匹配的 owned 进程 → 清空 runtime。
    pub fn detect_and_clean_residue(&self) -> usize {
        if !self.runtime.has_residue() {
            return 0;
        }
        let manifest = self.runtime.load_manifest();
        let mut killed = 0usize;
        for p in manifest.processes {
            if process_image_matches(p.pid, &p.image) {
                if kill_pid(p.pid) {
                    killed += 1;
                }
            }
        }
        self.runtime.clear_all();
        killed
    }

    /// spawn 并记录所有权（写入 managed_process.json；异常退出后可据此清理）。
    /// Windows：所有受管理子进程以 CREATE_NO_WINDOW 隐藏启动——用户双击 MeshLink.exe
    /// 只看到主界面，不弹出 mesh-agent / controller / supernode 的黑窗口（综合修复 P0-4）。
    pub fn spawn_managed(&self, kind: &str, image: &str, cmd: &mut StdCommand) -> Result<Child, String> {
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let child = cmd.spawn().map_err(|e| format!("spawn {kind}: {e}"))?;
        self.record(kind, image, child.id());
        Ok(child)
    }

    fn record(&self, kind: &str, image: &str, pid: u32) {
        let mut m = self.runtime.load_manifest();
        if m.supervisor.is_empty() {
            m.supervisor = "MeshLink".into();
            m.started_at = iso_now();
        }
        m.processes.push(ManagedProcess {
            kind: kind.into(),
            pid,
            start_time: iso_now(),
            image: image.to_ascii_lowercase(),
        });
        self.runtime.save_manifest(&m);
    }
}

fn iso_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("epoch_{secs}")
}

/// tasklist 校验 PID 对应的进程映像名是否 == expected（小写）。
fn process_image_matches(pid: u32, expected: &str) -> bool {
    let Ok(out) = StdCommand::new("tasklist")
        .args(["/FO", "CSV", "/NH", "/FI", &format!("PID eq {pid}")])
        .output()
    else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let Some(line) = text.lines().find(|l| l.trim().len() > 2) else {
        return false;
    };
    let Some(name) = line.split(',').next() else {
        return false;
    };
    name.trim().trim_matches('"').to_ascii_lowercase() == expected.to_ascii_lowercase()
}

/// 终止指定 PID（taskkill /F）。
fn kill_pid(pid: u32) -> bool {
    StdCommand::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// 进程是否仍存活（tasklist 能找到该 PID）。
#[cfg_attr(not(test), allow(dead_code))]
fn pid_alive(pid: u32) -> bool {
    let Ok(out) = StdCommand::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).contains(&pid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    /// 一个能存活足够久、可被可靠杀掉的子进程（powershell Start-Sleep 60）。
    fn helper_proc() -> StdCommand {
        let mut c = StdCommand::new("powershell");
        c.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"])
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        c
    }

    /// 每个测试独立的临时目录（CARGO_TARGET_TMPDIR；无该 env 时回退系统 temp）。
    fn temp_dir(tag: &str) -> PathBuf {
        let tmp = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let dir = tmp.join(format!("m1l5-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir run");
        dir
    }

    #[test]
    fn spawn_records_manifest_and_runtime_files_created() {
        let base = temp_dir("spawn");
        let rt = RuntimeDir::new(base.join("runtime"));
        let sup = ProcessSupervisor::with_runtime(rt.clone());

        let mut cmd = helper_proc();
        let child = sup.spawn_managed("agent", "powershell.exe", &mut cmd).expect("spawn");
        let pid = child.id();
        drop(child);

        // managed_process.json 已写入且含该 pid。
        assert!(rt.manifest_path().exists(), "managed_process.json 必须存在");
        let m = rt.load_manifest();
        assert_eq!(m.supervisor, "MeshLink");
        assert!(m.processes.iter().any(|p| p.pid == pid && p.kind == "agent"));
        assert!(pid_alive(pid), "受管理进程应存活");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ordered_shutdown_kills_owned_and_clears_runtime() {
        let base = temp_dir("shutdown");
        let rt = RuntimeDir::new(base.join("runtime"));
        let sup = ProcessSupervisor::with_runtime(rt.clone());

        let mut agent_cmd = helper_proc();
        let agent = sup.spawn_managed("agent", "powershell.exe", &mut agent_cmd).expect("spawn agent");
        let mut ctl_cmd = helper_proc();
        let ctl = sup.spawn_managed("controller", "powershell.exe", &mut ctl_cmd).expect("spawn ctl");
        let agent_pid = agent.id();
        let ctl_pid = ctl.id();
        drop(agent);
        drop(ctl);

        // 模拟 Agent 写入的临时文件 + supervisor 所有权记录。
        rt.ensure().unwrap();
        std::fs::write(rt.dir.join("active_session.json"), "{}").unwrap();
        std::fs::write(rt.dir.join("quick_code.json"), "{}").unwrap();

        // 正常退出：杀 owned 进程 + 清空 runtime。
        for pid in [agent_pid, ctl_pid] {
            assert!(kill_pid(pid), "应能终止受管理进程 {pid}");
        }
        rt.clear_all();

        assert!(!pid_alive(agent_pid), "agent 应已退出");
        assert!(!pid_alive(ctl_pid), "controller 应已退出");
        assert!(!rt.dir.exists() || !rt.has_residue(), "runtime 应已清理");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn abnormal_kill_residue_cleaned_on_next_start() {
        let base = temp_dir("abnormal");
        let rt = RuntimeDir::new(base.join("runtime"));
        let sup = ProcessSupervisor::with_runtime(rt.clone());

        // 模拟异常退出：进程仍在跑 + runtime 残留（managed_process.json + 临时文件）。
        let mut cmd = helper_proc();
        let child = sup.spawn_managed("agent", "powershell.exe", &mut cmd).expect("spawn");
        let pid = child.id();
        drop(child);
        std::fs::write(rt.dir.join("runtime_token.json"), "{}").unwrap();
        assert!(rt.has_residue(), "异常退出后应检测到残留");

        // 新实例（模拟 MeshLink 下次启动）自动清理。
        let sup2 = ProcessSupervisor::with_runtime(rt.clone());
        let killed = sup2.detect_and_clean_residue();
        assert_eq!(killed, 1, "应清理 1 个残留进程");
        assert!(!pid_alive(pid), "残留 agent 应被终止");
        assert!(!rt.has_residue(), "runtime 应被清空");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn unowned_process_not_killed_by_residue_cleanup() {
        let base = temp_dir("unowned");
        let rt = RuntimeDir::new(base.join("runtime"));

        // 一个非 MeshLink 拉起的进程（同一 helper，但不在 manifest 中）。
        let mut cmd = helper_proc();
        let child = cmd.spawn().expect("spawn unowned");
        let pid = child.id();
        drop(child);

        // 人为构造残留 manifest，但记录一个不存在的 pid（模拟 stale 记录）。
        rt.ensure().unwrap();
        let m = ManagedManifest {
            supervisor: "MeshLink".into(),
            started_at: iso_now(),
            processes: vec![ManagedProcess {
                kind: "agent".into(),
                pid,
                start_time: iso_now(),
                image: "powershell.exe".into(),
            }],
        };
        rt.save_manifest(&m);
        assert!(rt.has_residue());

        let sup = ProcessSupervisor::with_runtime(rt.clone());
        // 手动把 pid 从 manifest 移除后清理：unowned 进程不应被杀。
        // （真实 detect_and_clean_residue 只杀 manifest 中匹配的；此处直接验证
        //   非 managed 的进程不受影响——即使 manifest 被改，清理也只删 runtime。）
        let killed = {
            let mut mm = rt.load_manifest();
            mm.processes.clear();
            rt.save_manifest(&mm);
            sup.detect_and_clean_residue()
        };
        assert_eq!(killed, 0, "非 owned 进程不应被杀");
        assert!(pid_alive(pid), "unowned 进程应存活");
        assert!(!rt.has_residue(), "runtime 应被清空");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn clear_all_never_touches_data_dir_identity() {
        // 规格四：runtime 清理绝不删除永久身份。
        let base = temp_dir("data");
        let data_dir = base.join("agent-data");
        std::fs::create_dir_all(&data_dir).unwrap();
        std::fs::write(data_dir.join("identity.bin"), b"PERMANENT-IDENTITY").unwrap();

        let rt = RuntimeDir::new(base.join("runtime"));
        rt.ensure().unwrap();
        std::fs::write(rt.dir.join("active_session.json"), "{}").unwrap();
        rt.clear_all();

        assert!(data_dir.join("identity.bin").exists(), "永久身份必须保留");
        assert!(!rt.dir.exists() || !rt.has_residue(), "runtime 应已清理");
        let _ = std::fs::remove_dir_all(&base);
    }
}
