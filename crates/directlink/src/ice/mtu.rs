//! 路径 MTU 探测（M0-4 要求：DirectLink MTU 探测）。
//!
//! PoC 采用 UDP 载荷阶梯回显法：probe 端发递增大小的回显请求，对端原样回显，
//! 最大被确认尺寸即路径可承载的 UDP 载荷上限（不含 IP/UDP 头 28 字节）。
//!
//! 说明：UDP 无 DF 位语义（Windows 上 IP_DONTFRAGMENT 可用但依赖平台），
//! 阶梯法在 PMTU 丢包场景下依赖超时判负——PoC 用「连续失败即降档」策略，
//! 精确 PLPMTUD（RFC 8899）属 M1 生产化范围。

use std::net::SocketAddrV4;
use std::time::Duration;

/// 默认探测阶梯（UDP 载荷字节数）：覆盖常见路径 1472（1500 MTU）与隧道开销。
pub const DEFAULT_LADDER: &[u16] = &[1200, 1400, 1450, 1472, 1500];

/// MTU 探测错误。
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MtuError {
    #[error("所有探测档位均失败（连最小档 {min} 都不可达）")]
    AllFailed { min: u16 },
    #[error("io: {0}")]
    Io(String),
}

/// 探测结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MtuProbe {
    /// 最大被确认的 UDP 载荷字节数
    pub payload_max: u16,
    /// 对应 IP 层 MTU（载荷 + 28 字节 IP/UDP 头）
    pub path_mtu: u16,
    /// 每一档（载荷大小，是否确认）——ADR 记录用
    pub ladder_results: Vec<(u16, bool)>,
}

/// 注入式回显探测：`send`/`recv` 与 STUN 客户端同构，可复用打洞 socket。
///
/// 回显帧格式（Track B 私有，M0-5 将被 Noise 帧取代）：
/// `[magic u16 = 0x4D54][payload_len u16][payload ...]`，对端整帧回显。
pub fn probe_mtu_with<F, G>(
    peer: SocketAddrV4,
    ladder: &[u16],
    mut send: F,
    mut recv: G,
    timeout: Duration,
) -> Result<MtuProbe, MtuError>
where
    F: FnMut(&[u8], SocketAddrV4) -> std::io::Result<usize>,
    G: FnMut(Duration) -> Option<(SocketAddrV4, Vec<u8>)>,
{
    let mut confirmed: Option<u16> = None;
    let mut ladder_results = Vec::with_capacity(ladder.len());

    for &size in ladder {
        let mut pkt = Vec::with_capacity(4 + size as usize);
        pkt.extend_from_slice(&0x4D54u16.to_be_bytes());
        pkt.extend_from_slice(&size.to_be_bytes());
        pkt.resize(4 + size as usize, 0xAB);

        if send(&pkt, peer).is_err() {
            ladder_results.push((size, false));
            continue;
        }
        // 等回显：匹配 magic + 长度（非回显流量按噪音忽略）
        let deadline_ok = loop {
            match recv(timeout) {
                Some((from, buf)) if from == peer && buf.len() >= 4
                    && buf[0..2] == [0x4D, 0x54]
                    && u16::from_be_bytes([buf[2], buf[3]]) as usize == buf.len() - 4 =>
                {
                    break true;
                }
                Some(_) => continue,
                None => break false,
            }
        };
        if deadline_ok {
            confirmed = Some(size);
            ladder_results.push((size, true));
        } else {
            ladder_results.push((size, false));
        }
    }

    match confirmed {
        Some(payload_max) => Ok(MtuProbe { payload_max, path_mtu: payload_max + 28, ladder_results }),
        None => Err(MtuError::AllFailed { min: *ladder.iter().min().unwrap_or(&1200) }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    #[test]
    fn ladder_confirms_partial() {
        let peer = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000);
        // 假对端：payload > 1450 的包不回（模拟路径 MTU 1478）
        let last: RefCell<Option<Vec<u8>>> = RefCell::new(None);
        let result = probe_mtu_with(
            peer,
            &[1200, 1400, 1450, 1472],
            |pkt, _to| {
                let size = u16::from_be_bytes([pkt[2], pkt[3]]);
                let ok = size <= 1450;
                *last.borrow_mut() = ok.then(|| pkt.to_vec());
                Ok(pkt.len())
            },
            |_| last.borrow().clone().map(|b| (peer, b)),
            Duration::from_millis(5),
        )
        .expect("至少最小档必须确认");
        assert_eq!(result.payload_max, 1450);
        assert_eq!(result.path_mtu, 1450 + 28);
        assert_eq!(
            result.ladder_results,
            vec![(1200, true), (1400, true), (1450, true), (1472, false)]
        );
    }

    #[test]
    fn all_failed_is_error() {
        let peer = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 5000);
        let err = probe_mtu_with(
            peer,
            &[1200, 1400],
            |pkt, _to| Ok(pkt.len()),
            |_| None,
            Duration::from_millis(1),
        )
        .unwrap_err();
        assert_eq!(err, MtuError::AllFailed { min: 1200 });
    }
}
