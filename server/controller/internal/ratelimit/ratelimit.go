// 6 位码加入限流（用户规格十三）：
// - 6 位码仅 1e6 组合，join 接口必须防高速遍历（000000/000001/...）；
// - per-IP + per-device 双维度固定窗口失败计数，基础阈值 10 次失败/分钟；
// - 超阈值 → SESSION_RATE_LIMITED（429），窗口滑动自动解锁；
// - 成功 join 重置该 IP/device 的失败计数。

package ratelimit

import (
	"sync"
	"time"
)

// Config 限流参数（默认值来自用户规格）。
type Config struct {
	Window   time.Duration // 固定窗口长度（默认 1 分钟）
	MaxFails int           // 窗口内允许的最大失败次数（默认 10）
}

func (c Config) withDefaults() Config {
	if c.Window <= 0 {
		c.Window = time.Minute
	}
	if c.MaxFails <= 0 {
		c.MaxFails = 10
	}
	return c
}

type counter struct {
	windowStart time.Time
	fails       int
}

// Tracker 并发安全的失败计数器（per-IP + per-device）。
type Tracker struct {
	cfg Config

	mu    sync.Mutex
	byIP  map[string]*counter
	byDev map[string]*counter
}

// NewTracker 创建限流器。
func NewTracker(cfg Config) *Tracker {
	return &Tracker{
		cfg:   cfg.withDefaults(),
		byIP:  make(map[string]*counter),
		byDev: make(map[string]*counter),
	}
}

// Allowed 判定当前 join 尝试是否被允许（不记录失败——失败由 RecordFail 记录）。
func (t *Tracker) Allowed(ip, deviceID string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.gcLocked()
	return t.countLocked(t.byIP, ip) < t.cfg.MaxFails &&
		t.countLocked(t.byDev, deviceID) < t.cfg.MaxFails
}

// RecordFail 记录一次 join 失败（无效码/过期/状态非法——认证失败不计入
// join 限流：bearer 无效直接 401，由认证层处理）。
func (t *Tracker) RecordFail(ip, deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.bumpLocked(t.byIP, ip, now)
	t.bumpLocked(t.byDev, deviceID, now)
}

// RecordSuccess 成功 join：重置该 IP/device 计数。
func (t *Tracker) RecordSuccess(ip, deviceID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.byIP, ip)
	delete(t.byDev, deviceID)
}

func (t *Tracker) countLocked(m map[string]*counter, key string) int {
	c, ok := m[key]
	if !ok || time.Since(c.windowStart) >= t.cfg.Window {
		return 0
	}
	return c.fails
}

func (t *Tracker) bumpLocked(m map[string]*counter, key string, now time.Time) {
	c, ok := m[key]
	if !ok || now.Sub(c.windowStart) >= t.cfg.Window {
		c = &counter{windowStart: now}
		m[key] = c
	}
	c.fails++
}

// gcLocked 清理过期条目（防内存无限增长；调用方持锁）。
func (t *Tracker) gcLocked() {
	now := time.Now()
	for k, c := range t.byIP {
		if now.Sub(c.windowStart) >= t.cfg.Window {
			delete(t.byIP, k)
		}
	}
	for k, c := range t.byDev {
		if now.Sub(c.windowStart) >= t.cfg.Window {
			delete(t.byDev, k)
		}
	}
}
