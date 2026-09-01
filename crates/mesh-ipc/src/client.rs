//! Named Pipe 客户端（UI / 测试 ↔ Agent）。
//!
//! 同步阻塞模型（UI 侧在独立线程轮询事件；请求-响应一次一行）。
//! 请求等待响应期间收到的事件缓存在 pending 队列（`take_pending_events`
//! 取走），不丢失。

#![allow(non_snake_case, non_camel_case_types)]

use crate::proto::{decode_line, encode_line, Event, Request, Response, ServerMessage};
use mesh_common::{ErrorCode, MeshError};
use std::ffi::OsStr;
use std::os::raw::{c_int, c_void};
use std::os::windows::ffi::OsStrExt;
use std::time::{Duration, Instant};

type HANDLE = *mut c_void;
type BOOL = c_int;
type PCWSTR = *const u16;

const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const OPEN_EXISTING: u32 = 3;
const ERROR_PIPE_BUSY: u32 = 231;
const INVALID_HANDLE_VALUE: isize = -1;

extern "system" {
    fn CreateFileW(
        lpFileName: PCWSTR,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *mut c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
    fn WaitNamedPipeW(lpNamedPipeName: PCWSTR, nTimeOut: u32) -> BOOL;
    fn ReadFile(hFile: HANDLE, lpBuffer: *mut u8, nNumberOfBytesToRead: u32, lpNumberOfBytesRead: *mut u32, lpOverlapped: *mut c_void) -> BOOL;
    fn WriteFile(hFile: HANDLE, lpBuffer: *const u8, nNumberOfBytesToWrite: u32, lpNumberOfBytesWritten: *mut u32, lpOverlapped: *mut c_void) -> BOOL;
    fn PeekNamedPipe(hNamedPipe: HANDLE, lpBuffer: *mut u8, nBufferSize: u32, lpBytesRead: *mut u32, lpTotalBytesAvail: *mut u32, lpBytesLeftThisMessage: *mut u32) -> BOOL;
    fn CloseHandle(hObject: HANDLE) -> BOOL;
    fn GetLastError() -> u32;
}

fn to_wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// 命中并清理 CRLF / 尾部空白。
fn trim(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    while end > 0 && (line[end - 1] == b'\r' || line[end - 1] == b' ') {
        end -= 1;
    }
    &line[..end]
}

/// 管道客户端。
pub struct PipeClient {
    pipe: HANDLE,
    /// 跨行装配缓冲
    line_buf: Vec<u8>,
    /// 等待响应期间到达的事件（按序保留）
    pending: std::collections::VecDeque<ServerMessage>,
    closed: bool,
}

impl PipeClient {
    /// 连接管道（`\\.\pipe\...`）。忙时（ERROR_PIPE_BUSY）等待重试直到超时。
    pub fn connect(name: &str, timeout: Duration) -> Result<Self, MeshError> {
        if !name.starts_with(r"\\.\pipe\") {
            return Err(MeshError::new(ErrorCode::Internal, format!("管道名非法: {name}")));
        }
        let deadline = Instant::now() + timeout;
        loop {
            let wide = to_wide(name);
            let pipe = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if pipe as isize != INVALID_HANDLE_VALUE {
                return Ok(Self { pipe, line_buf: Vec::new(), pending: Default::default(), closed: false });
            }
            let err = unsafe { GetLastError() };
            if err != ERROR_PIPE_BUSY {
                return Err(MeshError::new(
                    ErrorCode::Internal,
                    format!("连接管道失败（WinError {err}）: {name}"),
                ));
            }
            if Instant::now() >= deadline {
                return Err(MeshError::new(ErrorCode::Internal, format!("管道忙超时: {name}")));
            }
            let wide = to_wide(name);
            unsafe { WaitNamedPipeW(wide.as_ptr(), 100) };
        }
    }

    /// 发送请求并等待响应（期间事件进入 pending）。默认 15s 超时。
    pub fn request(&mut self, req: &Request) -> Result<Response, MeshError> {
        self.request_timeout(req, Duration::from_secs(15))
    }

    pub fn request_timeout(&mut self, req: &Request, timeout: Duration) -> Result<Response, MeshError> {
        self.write_message(&encode_line(req)?)?;
        let deadline = Instant::now() + timeout;
        loop {
            // 先扫 pending：只取响应；事件按序保留（服务端事件与响应共用写
            // 通道，事件可能先于响应到达——弹出检查会静默丢弃事件）。
            if let Some(pos) = self
                .pending
                .iter()
                .position(|m| matches!(m, ServerMessage::Response(_)))
            {
                match self.pending.remove(pos) {
                    Some(ServerMessage::Response(r)) => return Ok(r),
                    _ => unreachable!("position 匹配已保证为响应"),
                }
            }
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return Err(MeshError::new(ErrorCode::Internal, "等待响应超时"));
            }
            match self.poll_read(remain)? {
                Some(msg) => {
                    if let ServerMessage::Response(r) = msg {
                        return Ok(r);
                    }
                    self.pending.push_back(msg);
                }
                None => continue,
            }
        }
    }

    /// 阻塞等待下一条服务端消息（响应或事件）；超时返回 None。
    pub fn wait_message(&mut self, timeout: Duration) -> Option<ServerMessage> {
        if let Some(msg) = self.pending.pop_front() {
            return Some(msg);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let remain = deadline.saturating_duration_since(Instant::now());
            if remain.is_zero() {
                return None;
            }
            match self.poll_read(remain) {
                Ok(Some(msg)) => return Some(msg),
                Ok(None) => continue,
                Err(_) => {
                    self.closed = true;
                    return None;
                }
            }
        }
    }

    /// 取走 pending 事件（请求期间到达的）。
    pub fn take_pending_events(&mut self) -> Vec<Event> {
        self.pending
            .drain(..)
            .filter_map(|m| match m {
                ServerMessage::Event(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// 诊断/测试用：裸管道句柄值（GetSecurityInfo 查询管道 DACL）。
    pub fn raw_handle(&self) -> usize {
        self.pipe as usize
    }

    /// 写一条原始行（含 `\n`；测试注入坏行 / 协议探测用）。
    pub fn write_message(&mut self, line: &[u8]) -> Result<(), MeshError> {
        let mut off = 0usize;
        while off < line.len() {
            let mut written: u32 = 0;
            let ok = unsafe {
                WriteFile(self.pipe, line[off..].as_ptr(), (line.len() - off) as u32, &mut written, std::ptr::null_mut())
            };
            if ok == 0 || written == 0 {
                self.closed = true;
                return Err(MeshError::new(ErrorCode::Internal, "管道写入失败（Agent 已断开）"));
            }
            off += written as usize;
        }
        Ok(())
    }

    /// 轮询读：无数据返回 Ok(None)；断开返回 Err。
    fn poll_read(&mut self, timeout: Duration) -> Result<Option<ServerMessage>, MeshError> {
        let deadline = Instant::now() + timeout;
        let mut chunk = [0u8; 8192];
        loop {
            // 已有完整行？
            while let Some((line, used)) = decode_line(&self.line_buf)? {
                let line = trim(line).to_vec();
                self.line_buf.drain(..used);
                if line.is_empty() {
                    continue;
                }
                let msg = parse_message(&line)?;
                return Ok(Some(msg));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            let mut avail: u32 = 0;
            let ok = unsafe {
                PeekNamedPipe(self.pipe, std::ptr::null_mut(), 0, std::ptr::null_mut(), &mut avail, std::ptr::null_mut())
            };
            if ok == 0 {
                self.closed = true;
                return Err(MeshError::new(ErrorCode::Internal, "管道已断开"));
            }
            if avail == 0 {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            let want = avail.min(chunk.len() as u32);
            let mut got: u32 = 0;
            let ok = unsafe { ReadFile(self.pipe, chunk.as_mut_ptr(), want, &mut got, std::ptr::null_mut()) };
            if ok == 0 || got == 0 {
                self.closed = true;
                return Err(MeshError::new(ErrorCode::Internal, "管道读取失败"));
            }
            self.line_buf.extend_from_slice(&chunk[..got as usize]);
        }
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        if !self.pipe.is_null() {
            unsafe { CloseHandle(self.pipe) };
        }
    }
}

fn parse_message(line: &[u8]) -> Result<ServerMessage, MeshError> {
    let v: serde_json::Value = serde_json::from_slice(line).map_err(|e| {
        MeshError::new(ErrorCode::Internal, format!("IPC 消息解析失败: {e}"))
    })?;
    if v.get("event").is_some() {
        let ev: Event = serde_json::from_value(v).map_err(|e| {
            MeshError::new(ErrorCode::Internal, format!("事件解析失败: {e}"))
        })?;
        Ok(ServerMessage::Event(ev))
    } else {
        let r: Response = serde_json::from_value(v).map_err(|e| {
            MeshError::new(ErrorCode::Internal, format!("响应解析失败: {e}"))
        })?;
        Ok(ServerMessage::Response(r))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::Command;

    #[test]
    fn connect_missing_pipe_fails() {
        let err = PipeClient::connect(r"\\.\pipe\meshlink-ipc-nonexistent-xyz", Duration::from_millis(300));
        assert!(err.is_err(), "不存在的管道应连接失败");
    }

    #[test]
    fn invalid_pipe_name_rejected() {
        assert!(PipeClient::connect("not-a-pipe", Duration::from_millis(100)).is_err());
    }

    // server.rs 的集成测试覆盖往返/事件/ACL；此处仅客户端纯逻辑。
    #[test]
    fn trim_handles_crlf() {
        assert_eq!(trim(b"{\"a\":1}\r"), b"{\"a\":1}");
        assert_eq!(trim(b"{\"a\":1}"), b"{\"a\":1}");
        assert_eq!(trim(b""), b"");
    }

    #[test]
    fn parse_event_and_response() {
        let msg = parse_message(
            br#"{"event":"Connected","peer_device_id":"dev-b","local_overlay_ip":"10.88.7.1","peer_overlay_ip":"10.88.7.2"}"#,
        )
        .expect("parse");
        match msg {
            ServerMessage::Response(_) => panic!("应为事件"),
            ServerMessage::Event(Event::Connected { peer_device_id: _, local_overlay_ip: _, peer_overlay_ip: _, path: _ }) => {}
            ServerMessage::Event(_) => panic!("应为 Connected"),
        }
        let msg = parse_message(br#"{"id":9,"ok":true}"#).expect("parse");
        match msg {
            ServerMessage::Response(r) => {
                assert_eq!(r.id, 9);
                assert!(r.ok);
            }
            _ => panic!("应为响应"),
        }
        assert!(parse_message(b"garbage").is_err());
        let _ = Command::GetStatus;
    }
}
