// 设备事件总线：候选交换与会话加入的推送通道（WSS /v1/events 与
// long-poll 共用）。第一版内存实现（单进程 Controller），协议语义
// 与未来分布式部署兼容：事件按 device 订阅投递，无业务数据。

package events

import (
	"sync"
	"time"
)

// Event 推送给订阅设备的事件（信令通知，非数据面内容）。
type Event struct {
	Seq       int64          `json:"seq"`
	Type      string         `json:"type"` // session_joined | candidates_updated | connection_request | ...
	SessionID string         `json:"session_id"`
	DeviceID  string         `json:"device_id,omitempty"` // 事件产生方（对端）
	Payload   map[string]any `json:"payload,omitempty"`   // 附加数据（from_name 等）
	At        time.Time      `json:"at"`
}

// 常量事件类型。
const (
	TypeSessionJoined     = "session_joined"
	TypeCandidatesUpdated = "candidates_updated"
	TypeConnectionRequest = "connection_request"
	TypeRequestRejected   = "connection_request_rejected"
	TypeFriendPending     = "friend_pending"
	TypeFriendAccepted    = "friend_accepted"
	TypeFriendRemoved     = "friend_removed"
)

// 每设备保留事件上限（轮询拉取窗口）。
const RetainPerDevice = 256

// Bus 进程内 pub/sub + 每设备保留日志（供 /v1/events/poll 轮询）。
// WSS 是加速器；轮询是正确性权威通道——慢消费者丢弃仅影响加速。
type Bus struct {
	mu    sync.Mutex
	subs  map[string]map[chan Event]struct{}
	log   map[string][]Event // deviceID → 保留事件（seq 递增）
	high  int64              // 全局单调 seq
}

// NewBus 创建总线。
func NewBus() *Bus {
	return &Bus{subs: make(map[string]map[chan Event]struct{}), log: make(map[string][]Event)}
}

// Subscribe 订阅某设备的事件。返回通道与取消函数。
func (b *Bus) Subscribe(deviceID string) (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	if b.subs[deviceID] == nil {
		b.subs[deviceID] = make(map[chan Event]struct{})
	}
	b.subs[deviceID][ch] = struct{}{}
	b.mu.Unlock()
	cancel := func() {
		b.mu.Lock()
		if set, ok := b.subs[deviceID]; ok {
			delete(set, ch)
			if len(set) == 0 {
				delete(b.subs, deviceID)
			}
		}
		b.mu.Unlock()
		close(ch)
	}
	return ch, cancel
}

// Publish 向 deviceID 投递事件（满缓冲 → 丢弃，轮询兜底；同时写入保留日志）。
func (b *Bus) Publish(deviceID string, ev Event) {
	ev.At = time.Now().UTC()
	b.mu.Lock()
	b.high++
	ev.Seq = b.high
	set := b.subs[deviceID]
	chans := make([]chan Event, 0, len(set))
	for ch := range set {
		chans = append(chans, ch)
	}
	b.log[deviceID] = append(b.log[deviceID], ev)
	if len(b.log[deviceID]) > RetainPerDevice {
		b.log[deviceID] = b.log[deviceID][len(b.log[deviceID])-RetainPerDevice:]
	}
	b.mu.Unlock()
	for _, ch := range chans {
		select {
		case ch <- ev:
		default: // 慢消费者：丢弃（轮询是权威通道）
		}
	}
}

// Poll 拉取某设备 seq 之后的事件（含新到事件）。返回 (事件列表, 最新 seq)。
// 无新事件时返回空列表（调用方自行决定轮询间隔）。
func (b *Bus) Poll(deviceID string, sinceSeq int64) ([]Event, int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Event, 0)
	for _, ev := range b.log[deviceID] {
		if ev.Seq > sinceSeq {
			out = append(out, ev)
		}
	}
	return out, b.high
}
