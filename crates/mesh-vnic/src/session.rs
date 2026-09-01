//! WintunSession RAII + 收发包封装（M0-3 要求六/八/九/十）。
//!
//! - `WintunSession` 持有 `Arc<WintunAdapter>`，Drop = WintunEndSession；
//!   Adapter Close 与 DLL FreeLibrary 必然晚于 Session End（所有权链保证）。
//! - `ReceivedPacketRef` RAII guard：无论解析成败，guard 离开作用域即
//!   `WintunReleaseReceivePacket`，杜绝泄漏（要求九）。
//! - Ring 满不 panic：`allocate_send_packet` 失败映射 `SendRingFull`（要求十）。

use crate::adapter::WintunAdapter;
use crate::api::{
    win, Handle, WintunSessionHandle, ERROR_BUFFER_OVERFLOW, ERROR_NO_MORE_ITEMS,
};
use crate::error::VnicError;
use std::sync::Arc;

/// 已启动的收发 Session。
#[derive(Debug)]
pub struct WintunSession {
    handle: WintunSessionHandle,
    /// 持 Adapter 引用：保证 EndSession 前 Adapter 不关闭、DLL 不释放（要求六）
    adapter: Arc<WintunAdapter>,
}

impl WintunSession {
    /// 启动 Session。`capacity` 必须先经 [`WintunLibrary::validate_ring_capacity`]。
    pub fn start(adapter: &Arc<WintunAdapter>, capacity: u32) -> Result<Self, VnicError> {
        let library = adapter.library();
        let handle = unsafe { (library.f.start_session)(adapter.handle(), capacity) };
        if handle.is_null() {
            let os = unsafe { win::GetLastError() };
            tracing::error!(target: "vnic", "WintunStartSession 失败 (os={os}, capacity=0x{capacity:X})");
            return Err(VnicError::SessionStartFailed { os });
        }
        tracing::info!(target: "vnic", "Wintun session 已启动 (capacity=0x{capacity:X})");
        Ok(Self { handle, adapter: Arc::clone(adapter) })
    }

    pub(crate) fn handle(&self) -> WintunSessionHandle {
        self.handle
    }

    /// ReadWaitEvent 句柄（归属 Wintun Session，**禁止 CloseHandle**，要求八）。
    pub fn read_wait_event(&self) -> Handle {
        unsafe { (self.adapter.library().f.get_read_wait_event)(self.handle) }
    }

    /// 取一个待处理包。返回 `Ok(None)` 表示 ring 空（ERROR_NO_MORE_ITEMS）。
    /// DLL 输出的 `size` 严格夹到 [0, 0xFFFF]——无上限会导致 `to_vec()` 读越界触发 AV。
    pub fn receive_packet(&self) -> Result<Option<ReceivedPacketRef<'_>>, VnicError> {
        let mut size: u32 = 0;
        let ptr = unsafe { (self.adapter.library().f.receive_packet)(self.handle, &mut size) };
        if !ptr.is_null() {
            if size > 0xFFFF {
                // size 异常：必须先 ReleaseReceivePacket 归还 slot（否则 ring meta 错乱 AV）
                unsafe { (self.adapter.library().f.release_receive_packet)(self.handle, ptr) };
                return Err(VnicError::ReceiveInvalidData);
            }
            return Ok(Some(ReceivedPacketRef { session: self, ptr, size }));
        }
        match unsafe { win::GetLastError() } {
            ERROR_NO_MORE_ITEMS => Ok(None),
            os => Err(VnicError::ReceiveOther { os }),
        }
    }

    /// 分配发送包缓冲（copy 进 ring）。Ring 满 -> `SendRingFull`（不 panic）。
    /// 输入 `size` 必须 ≤ 0xFFFF（Wintun 单包上限），否则拒绝（不 panic / 不传给 DLL）。
    pub fn allocate_send_packet(&self, size: u32) -> Result<*mut u8, VnicError> {
        if size > 0xFFFF {
            return Err(VnicError::SendInvalidPacket);
        }
        let ptr = unsafe { (self.adapter.library().f.allocate_send_packet)(self.handle, size) };
        if ptr.is_null() {
            let os = unsafe { win::GetLastError() };
            return Err(if os == ERROR_BUFFER_OVERFLOW {
                VnicError::SendRingFull
            } else {
                VnicError::SendOther { os }
            });
        }
        Ok(ptr)
    }

    /// 提交发送（allocate 的缓冲）。官方语义不返回错误：size 由 allocate 时确定，
    /// 此处只需传 buffer 指针（与 wintun.h 0.14.1 的二参签名一致）。
    ///
    /// # Safety
    /// `ptr` 必须是本 session `allocate_send_packet` 返回且尚未 send 的缓冲。
    pub unsafe fn send_packet(&self, ptr: *const u8) {
        (self.adapter.library().f.send_packet)(self.handle, ptr);
    }
}

impl Drop for WintunSession {
    fn drop(&mut self) {
        // 要求六：调用方必须已停掉 RX/TX worker（worker 持有本结构 Arc，
        // 本 Drop 触发即意味着最后一个引用释放，worker 必然已退出）。
        unsafe { (self.adapter.library().f.end_session)(self.handle) };
        tracing::debug!(target: "vnic", "Wintun session 已结束");
    }
}

/// RAII 接收包 guard（要求九 + M0-3.1-2 边界冻结）。
///
/// `Deref<Target = [u8]>` 供校验/拷贝；离开作用域自动 Release。
/// **接口契约（M0-3.1-2 冻结）：**
/// - `pub(crate)`：仅 mesh-vnic crate 内部可见，绝不泄漏到 Overlay
///   Router / DirectLink / N2N / Cloudflare 层。
/// - RX worker 内部必须先 `to_vec()` 拷贝为 Owned `PacketBuffer`，
///   再立即 `drop(guard)` 归还 ring slot，然后才允许把 `PacketBuffer`
///   交给上层。
/// - 禁止把 guard、内部 ring raw pointer、或从 guard deref 得到的
///   `&[u8]` borrow 通过任何 channel / callback / `TransportProvider`
///   API 传出去。Zero-copy 未来如果重提，必须走独立 ADR 重新设计。
pub(crate) struct ReceivedPacketRef<'a> {
    session: &'a WintunSession,
    ptr: *mut u8,
    size: u32,
}

// SAFETY：Wintun 0.14.1 官方头文件注明 Receive/Send/Release 等 API 线程安全；
// session 句柄跨线程调用受官方支持（RX/TX worker 分线程工作，要求十九）。
unsafe impl Send for WintunSession {}
unsafe impl Sync for WintunSession {}

impl ReceivedPacketRef<'_> {
    /// 拷贝为受控 PacketBuffer（拷贝后立即 release，要求九：M0 优先正确性）。
    pub(crate) fn to_vec(&self) -> Vec<u8> {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size as usize).to_vec() }
    }

    pub(crate) fn len(&self) -> u32 {
        self.size
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.size == 0
    }
}

impl std::ops::Deref for ReceivedPacketRef<'_> {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.size as usize) }
    }
}

impl Drop for ReceivedPacketRef<'_> {
    fn drop(&mut self) {
        // 无论解析成功/失败都必须 release（要求九）。
        // WARNING：第二参数是 Packet 指针（void*），不是 size！传错立刻 AV 0xC0000005。
        unsafe { (self.session.adapter.library().f.release_receive_packet)(self.session.handle, self.ptr) };
    }
}
