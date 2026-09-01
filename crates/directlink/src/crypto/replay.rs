//! Anti-Replay 滑动窗口（directlink_frame_v1.md 修正一）。
//!
//! 接收顺序不可颠倒：
//! 1. `precheck(seq)` —— 重复 / 过旧直接丢弃（**不解密**）；
//! 2. 以 seq 为 nonce 解密；
//! 3. AEAD 校验成功 → `commit(seq)` 正式提交窗口。
//!
//! 伪造包（过不了 AEAD）永远走不到 commit——不得污染 replay window。

/// 窗口大小（位）：2^11 = 2048，接受 `[highest-2047, highest]` 及任意更靠后的 seq。
pub const WINDOW_BITS: u64 = 2048;
const WORDS: usize = (WINDOW_BITS / 64) as usize;

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// 已提交的最高 seq（None = 尚无任何提交）
    highest: Option<u64>,
    /// 位图：bit (highest - seq) = 1 表示 seq 已接收
    bitmap: [u64; WORDS],
    /// 丢弃计数（诊断输出用）
    pub dropped_dup: u64,
    pub dropped_stale: u64,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self { highest: None, bitmap: [0; WORDS], dropped_dup: 0, dropped_stale: 0 }
    }
}

impl ReplayWindow {
    /// 预检查：该 seq 是否**可能**合法（解密前调用）。
    /// - 无任何记录 → 允许（首帧）；
    /// - seq > highest → 允许（超前，窗口将前移）；
    /// - 窗口内且未出现过 → 允许；
    /// - 窗口内且已出现 → 重复，拒绝；
    /// - seq ≤ highest - WINDOW_BITS → 过旧，拒绝。
    pub fn precheck(&self, seq: u64) -> bool {
        match self.highest {
            None => true,
            Some(h) => {
                if seq > h {
                    return true;
                }
                if seq + WINDOW_BITS - 1 < h {
                    return false; // 过旧（计数由调用方在丢弃路径统计）
                }
                let offset = (h - seq) as usize;
                if offset >= WINDOW_BITS as usize {
                    return false;
                }
                self.bitmap[offset / 64] & (1u64 << (offset % 64)) == 0
            }
        }
    }

    /// 解密成功后提交（幂等：重复/过旧提交为 no-op）。
    pub fn commit(&mut self, seq: u64) {
        match self.highest {
            None => {
                self.highest = Some(seq);
                self.bitmap = [0; WORDS];
                self.bitmap[0] = 1;
            }
            Some(h) if seq > h => {
                let shift = seq - h;
                if shift >= WINDOW_BITS {
                    self.bitmap = [0; WORDS];
                } else {
                    // 位图整体左移 shift 位：offset = highest - seq，highest 前移
                    // 后同一 seq 的 offset 增大，位位置 p → p + shift。
                    let s = shift as usize;
                    let word_shift = s / 64;
                    let bit_shift = s % 64;
                    let mut new_map = [0u64; WORDS];
                    for i in 0..WORDS {
                        let src = i as isize - word_shift as isize;
                        if src < 0 {
                            continue;
                        }
                        let mut v = self.bitmap[src as usize] << bit_shift;
                        if bit_shift > 0 && src >= 1 {
                            v |= self.bitmap[(src - 1) as usize] >> (64 - bit_shift);
                        }
                        new_map[i] = v;
                    }
                    self.bitmap = new_map;
                }
                self.highest = Some(seq);
                self.bitmap[0] |= 1;
            }
            Some(h) => {
                if seq + WINDOW_BITS - 1 >= h {
                    let offset = (h - seq) as usize;
                    if offset < WINDOW_BITS as usize {
                        self.bitmap[offset / 64] |= 1u64 << (offset % 64);
                    }
                }
            }
        }
    }

    /// 记录一次重复丢弃（诊断计数）。
    pub fn note_dup(&mut self) {
        self.dropped_dup += 1;
    }
    /// 记录一次过旧丢弃（诊断计数）。
    pub fn note_stale(&mut self) {
        self.dropped_stale += 1;
    }

    pub fn highest(&self) -> Option<u64> {
        self.highest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_frame_accepted() {
        let mut w = ReplayWindow::default();
        assert!(w.precheck(0));
        w.commit(0);
        assert_eq!(w.highest(), Some(0));
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::default();
        for seq in 0..3 {
            assert!(w.precheck(seq));
            w.commit(seq);
        }
        assert!(!w.precheck(2), "重复 seq 必须拒绝");
        assert!(!w.precheck(0));
        w.note_dup();
        assert_eq!(w.dropped_dup, 1);
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let mut w = ReplayWindow::default();
        // 先提交 10，再补收乱序的 0..9
        assert!(w.precheck(10));
        w.commit(10);
        for seq in (0..10).rev() {
            assert!(w.precheck(seq), "窗口内乱序 seq={seq} 应接受");
            w.commit(seq);
        }
        // 全部提交后重复再拒
        assert!(!w.precheck(5));
    }

    #[test]
    fn too_old_rejected() {
        let mut w = ReplayWindow::default();
        assert!(w.precheck(WINDOW_BITS + 100));
        w.commit(WINDOW_BITS + 100);
        assert!(!w.precheck(0), "落后整窗的 seq 必须拒绝");
        w.note_stale();
        assert_eq!(w.dropped_stale, 1);
    }

    #[test]
    fn window_edge_semantics() {
        // highest = 3000；窗口 = [3000-2047, 3000] = [953, 3000]
        let mut w = ReplayWindow::default();
        w.commit(3000);
        assert!(w.precheck(953), "窗口下边缘应接受");
        assert!(!w.precheck(952), "窗口下边缘-1 应拒绝");
        assert!(w.precheck(3001), "超前应接受");
    }

    /// 伪造包不得污染窗口：precheck 通过的"超前" seq 若解密失败不 commit，
    /// 之后合法帧携带同一 seq 到达仍可被接受。
    #[test]
    fn forged_frame_does_not_pollute_window() {
        let mut w = ReplayWindow::default();
        w.commit(2);
        // 攻击者伪造 seq=100：precheck 放行（超前），但解密失败 → 不 commit
        assert!(w.precheck(100));
        // 窗口未被前移：合法的乱序 3..=10 仍全部可收
        for seq in 3..=10 {
            assert!(w.precheck(seq));
            w.commit(seq);
        }
        // 合法的 seq=100 稍后到达 → 仍可接受（未被伪造帧占用）
        assert!(w.precheck(100));
        w.commit(100);
        assert!(!w.precheck(100), "提交后重复才拒绝");
    }

    /// 跳跃超整窗的 commit 清空位图（旧位全部失效）。
    #[test]
    fn big_jump_clears_bitmap() {
        let mut w = ReplayWindow::default();
        w.commit(0);
        w.commit(1);
        w.commit(WINDOW_BITS + 5000);
        assert_eq!(w.highest(), Some(WINDOW_BITS + 5000));
        assert!(w.precheck(WINDOW_BITS + 5000 + 1));
        assert!(!w.precheck(1), "整窗之前的历史 seq 全部过旧");
    }
}
