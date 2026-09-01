// WSS 事件通道：GET /v1/events（bearer 认证 + WebSocket 升级）。
//
// 定位：仅是加速器（候选上传 / 会话加入即时通知），正确性依赖 GET 轮询——
// 慢消费者事件丢弃，客户端必须支持轮询兜底。

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
)

// handleEvents GET /v1/events（auth）：升级为 WebSocket，推送设备事件。
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request, dev model.Device) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		OriginPatterns: []string{"*"}, // DEV：localhost 客户端无 Origin 约束；生产由 TLS 层收敛
	})
	if err != nil {
		return // 升级失败已由库写响应
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	ch, cancel := s.bus.Subscribe(dev.DeviceID)
	defer cancel()

	ctx := r.Context()
	errCh := make(chan error, 2)

	// 读循环：排空客户端帧（ping/pong 由库自动处理；客户端消息一律忽略）。
	go func() {
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				errCh <- err
				return
			}
		}
	}()
	// 写循环：转发事件（JSON）。
	go func() {
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			case ev, ok := <-ch:
				if !ok {
					errCh <- nil
					return
				}
				blob, _ := json.Marshal(ev)
				wt, err := conn.Writer(ctx, websocket.MessageText)
				if err != nil {
					errCh <- err
					return
				}
				if _, err := wt.Write(blob); err != nil {
					wt.Close()
					errCh <- err
					return
				}
				if err := wt.Close(); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	// 保活：服务端 ping 防中间设备空闲断连。
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := conn.Ping(ctx); err != nil {
					errCh <- err
					return
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
	case <-errCh:
	}
}

// handleEventsPoll GET /v1/events/poll?since=<seq>（auth）：
// HTTP 轮询事件（权威通道，不依赖 WSS）。返回 seq 之后的新事件 + 最新 seq。
// 客户端应携带上一轮返回的 seq 增量拉取；无新事件返回空列表（调用方定间隔）。
func (s *Server) handleEventsPoll(w http.ResponseWriter, r *http.Request, dev model.Device) {
	since := int64(0)
	if v := r.URL.Query().Get("since"); v != "" {
		n, err := parseInt64(v)
		if err != nil || n < 0 {
			writeError(w, errValidation("since 参数非法"))
			return
		}
		since = n
	}
	evs, seq := s.bus.Poll(dev.DeviceID, since)
	if evs == nil {
		evs = []events.Event{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": evs, "seq": seq})
}

func parseInt64(s string) (int64, error) {
	var n int64
	var err error
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("非数字")
		}
		n = n*10 + int64(c-'0')
		if n < 0 {
			return 0, fmt.Errorf("溢出")
		}
	}
	return n, err
}
