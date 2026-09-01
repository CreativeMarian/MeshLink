// 6 位码快速连接会话 API（创建 / 加入 / 查询）。

package api

import (
	"net/http"
	"strings"

	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
)

// createSessionRequest POST /v1/sessions 请求体。
type createSessionRequest struct {
	NetworkID     string `json:"network_id,omitempty"`
	PreferredCode string `json:"preferred_code,omitempty"` // 可选：指定 6 位码（固定宽度字符串，保留前导零）
}

// sessionView 会话视图（含成员公钥快照——身份分发的核心通道；
// overlay_subnet/overlay_ip 为 IPAM 下发，客户端据此配置 Wintun）。
type sessionView struct {
	SessionID     string                `json:"session_id"`
	Code          string                `json:"code,omitempty"` // 仅创建者可见完整码
	NetworkID     string                `json:"network_id"`
	Status        string                `json:"status"`
	CreatedAt     string                `json:"created_at"`
	ExpiresAt     string                `json:"expires_at"`
	OverlaySubnet string                `json:"overlay_subnet,omitempty"`
	Members       []model.SessionMember `json:"members"`
}

func newSessionView(sess model.ConnectionSession, members []model.SessionMember, withCode bool) sessionView {
	v := sessionView{
		SessionID:     sess.SessionID,
		NetworkID:     sess.NetworkID,
		Status:        string(sess.Status),
		CreatedAt:     sess.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		ExpiresAt:     sess.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"),
		OverlaySubnet: sess.OverlaySubnet,
		Members:       members,
	}
	if withCode {
		v.Code = sess.Code
	}
	return v
}

// handleCreateSession POST /v1/sessions（auth）：创建 WAITING 会话，
// Controller 原子分配 6 位码（默认 10 分钟有效）。
func (s *Server) handleCreateSession(w http.ResponseWriter, r *http.Request, dev model.Device) {
	var req createSessionRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	networkID := req.NetworkID
	if networkID == "" {
		networkID = "default"
	}
	if len(networkID) > 128 || strings.ContainsAny(networkID, "\x00\r\n") {
		writeError(w, errValidation("network_id 非法（≤128，无控制字符）"))
		return
	}
	// preferred_code：可选指定码，必须是 6 位数字字符串（保留前导零）。
	if req.PreferredCode != "" && (len(req.PreferredCode) != 6 || !isAllDigits(req.PreferredCode)) {
		writeError(w, errValidation("preferred_code 须为 6 位数字"))
		return
	}

	sess, err := s.store.CreateSessionPreferred(r.Context(), dev.DeviceID, networkID, model.SessionTTLDefault, req.PreferredCode)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	members, err := s.store.Members(r.Context(), sess.SessionID)
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	s.logger.Info("session created", "session_id", sess.SessionID,
		"code", sess.Code, "creator", dev.DeviceID, "expires_at", sess.ExpiresAt)
	writeJSON(w, http.StatusOK, newSessionView(sess, members, true))
}

// handleJoinSession POST /v1/sessions/{code}/join（auth）：凭 6 位码加入。
//
// 限流（per-IP + per-device 失败计数）先行；join 成功响应含 creator 公钥——
// **joiner 获得 creator 公钥的唯一可信来源是本响应**（Controller 注册表），
// 6 位码不承载任何公钥 / 认证语义。
func (s *Server) handleJoinSession(w http.ResponseWriter, r *http.Request, dev model.Device) {
	code := r.PathValue("code")
	if len(code) != 6 || !isAllDigits(code) {
		// 格式非法按限流失败计数（防遍历）。
		s.limiter.RecordFail(s.clientIP(r), dev.DeviceID)
		writeError(w, errValidation("连接码须为 6 位数字"))
		return
	}

	ip := s.clientIP(r)
	if !s.limiter.Allowed(ip, dev.DeviceID) {
		writeError(w, &apiError{Code: "SESSION_RATE_LIMITED",
			Message: "尝试过于频繁，请稍后再试", Status: http.StatusTooManyRequests})
		return
	}

	sess, members, err := s.store.JoinSession(r.Context(), code, dev.DeviceID)
	if err != nil {
		s.limiter.RecordFail(ip, dev.DeviceID)
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	s.limiter.RecordSuccess(ip, dev.DeviceID)

	// 通知 creator：joiner 已加入（WSS 加速；轮询为权威通道）。
	s.bus.Publish(sess.CreatorDeviceID, newEvent(events.TypeSessionJoined, sess.SessionID, dev.DeviceID))

	s.logger.Info("session joined", "session_id", sess.SessionID,
		"creator", sess.CreatorDeviceID, "joiner", dev.DeviceID)
	// joiner 无需看到码本身（会话已建立），withCode=false。
	writeJSON(w, http.StatusOK, newSessionView(sess, members, false))
}

// handleGetSession GET /v1/sessions/{session_id}（auth 成员）：
// creator 轮询发现 joiner + 双方公钥快照。
func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request, dev model.Device) {
	sess, members, ok := s.loadSessionForMember(w, r, dev, r.PathValue("session_id"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, newSessionView(sess, members, dev.DeviceID == sess.CreatorDeviceID))
}

// loadSessionForMember 读取会话并校验请求者是成员（否则 SESSION_NOT_MEMBER）。
func (s *Server) loadSessionForMember(w http.ResponseWriter, r *http.Request, dev model.Device, sessionID string) (model.ConnectionSession, []model.SessionMember, bool) {
	sess, err := s.store.Session(r.Context(), sessionID)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
		} else {
			writeError(w, errInternal(err))
		}
		return model.ConnectionSession{}, nil, false
	}
	members, err := s.store.Members(r.Context(), sessionID)
	if err != nil {
		writeError(w, errInternal(err))
		return model.ConnectionSession{}, nil, false
	}
	isMember := false
	for _, m := range members {
		if m.DeviceID == dev.DeviceID {
			isMember = true
			break
		}
	}
	if !isMember {
		writeError(w, &apiError{Code: "SESSION_NOT_MEMBER", Message: "非会话成员",
			Status: http.StatusForbidden})
		return model.ConnectionSession{}, nil, false
	}
	return sess, members, true
}

func newEvent(evType, sessionID, deviceID string) events.Event {
	return events.Event{Type: evType, SessionID: sessionID, DeviceID: deviceID}
}

func isAllDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
