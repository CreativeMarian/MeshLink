// 好友关系 + 好友直连 + 设备/在线状态 API（M1-1）。
//
// 设计要点（用户 M1-1 规格）：
// - 好友关系建立在 Device Identity 之上（模型层预留多设备用户）；
// - 好友邀请 → redeem 建立 PENDING 好友关系（与 Online Session 分离）；
//   accept → ACCEPTED 后好友列表出现对方；
// - 好友直连（ConnectFriend）：Controller 创建 target 指定会话并通知对端，
//   对端接受后才 JOINED（复用既有 session/candidate/noise 链路）；
// - 删除好友 = 撤销 Friend Authorization（friendship → REMOVED），并立即
//   关闭双方之间的好友直连会话（FRIEND_AUTH_REVOKED）；
// - 在线状态：由 last_seen_at 新鲜度判定（auth 中间件 + 心跳）。

package api

import (
	"net/http"
	"strings"

	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
)

// ---- 好友关系视图 ----

// friendshipView 好友关系视图（含对端设备 + 在线状态）。
type friendshipView struct {
	FriendshipID string              `json:"friendship_id"`
	Status       string              `json:"status"`
	CreatedAt    string              `json:"created_at"`
	Peer         model.DeviceWithPresence `json:"peer"`
}

func newFriendshipView(fs model.Friendship, peer model.DeviceWithPresence) friendshipView {
	v := friendshipView{
		FriendshipID: fs.FriendshipID,
		Status:       string(fs.Status),
		CreatedAt:    fs.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		Peer:         peer,
	}
	return v
}

// friendshipViewForDevice 以 deviceID 视角生成好友视图（对端 = 另一设备）。
func (s *Server) friendshipViewForDevice(r *http.Request, fs model.Friendship, deviceID string) (friendshipView, error) {
	peerID := fs.DeviceB
	if peerID == deviceID {
		peerID = fs.DeviceA
	}
	peer, err := s.store.DeviceWithPresence(r.Context(), peerID)
	if err != nil {
		return friendshipView{}, err
	}
	return newFriendshipView(fs, peer), nil
}

// handleListFriendships GET /v1/friendships（auth）：我的好友列表（含对端设备+在线）。
func (s *Server) handleListFriendships(w http.ResponseWriter, r *http.Request, dev model.Device) {
	views, err := s.store.FriendViews(r.Context(), dev.DeviceID)
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	if views == nil {
		views = []model.FriendView{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"friendships": views})
}

// handleGetFriendship GET /v1/friendships/{friendship_id}（auth 成员）：详情。
func (s *Server) handleGetFriendship(w http.ResponseWriter, r *http.Request, dev model.Device) {
	fs, ok := s.loadFriendshipForMember(w, r, dev, r.PathValue("friendship_id"))
	if !ok {
		return
	}
	v, err := s.friendshipViewForDevice(r, fs, dev.DeviceID)
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// loadFriendshipForMember 读取好友关系并校验请求者是成员。
func (s *Server) loadFriendshipForMember(w http.ResponseWriter, r *http.Request, dev model.Device, friendshipID string) (model.Friendship, bool) {
	fs, err := s.store.Friendship(r.Context(), friendshipID)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
		} else {
			writeError(w, errInternal(err))
		}
		return model.Friendship{}, false
	}
	if dev.DeviceID != fs.DeviceA && dev.DeviceID != fs.DeviceB {
		writeError(w, &apiError{Code: "FRIENDSHIP_NOT_MEMBER", Message: "非关系成员",
			Status: http.StatusForbidden})
		return model.Friendship{}, false
	}
	return fs, true
}

// handleAcceptFriendship POST /v1/friendships/{id}/accept（auth 成员）：
// 接受好友请求 → ACCEPTED（好友列表出现对方；不建立任何连接会话）。
func (s *Server) handleAcceptFriendship(w http.ResponseWriter, r *http.Request, dev model.Device) {
	fs, ok := s.loadFriendshipForMember(w, r, dev, r.PathValue("friendship_id"))
	if !ok {
		return
	}
	updated, err := s.store.SetFriendshipStatus(r.Context(), fs.FriendshipID, dev.DeviceID, model.FriendshipAccepted)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	// 通知双方：好友关系已建立（含对端设备名）。
	notifyFriendship(r, s, updated, events.TypeFriendAccepted, dev.DeviceID)
	v, err := s.friendshipViewForDevice(r, updated, dev.DeviceID)
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	s.logger.Info("friendship accepted", "friendship_id", fs.FriendshipID,
		"a", fs.DeviceA, "b", fs.DeviceB, "accepted_by", dev.DeviceID)
	writeJSON(w, http.StatusOK, v)
}

// handleRejectFriendship POST /v1/friendships/{id}/reject（auth 成员）：拒绝 → REMOVED。
func (s *Server) handleRejectFriendship(w http.ResponseWriter, r *http.Request, dev model.Device) {
	fs, ok := s.loadFriendshipForMember(w, r, dev, r.PathValue("friendship_id"))
	if !ok {
		return
	}
	updated, err := s.store.SetFriendshipStatus(r.Context(), fs.FriendshipID, dev.DeviceID, model.FriendshipRemoved)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	s.logger.Info("friendship rejected", "friendship_id", fs.FriendshipID,
		"a", fs.DeviceA, "b", fs.DeviceB, "by", dev.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "removed"})
	_ = updated
}

// handleRevokeFriendship POST /v1/friendships/{id}/revoke（auth 成员）：
// 删除好友 = 撤销授权（→ REMOVED + revoked_at），并立即关闭双方之间活跃的
// 好友直连会话（FRIEND_AUTH_REVOKED）。
func (s *Server) handleRevokeFriendship(w http.ResponseWriter, r *http.Request, dev model.Device) {
	fs, ok := s.loadFriendshipForMember(w, r, dev, r.PathValue("friendship_id"))
	if !ok {
		return
	}
	updated, err := s.store.SetFriendshipStatus(r.Context(), fs.FriendshipID, dev.DeviceID, model.FriendshipRemoved)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	// 立即断开双方之间的好友直连会话。
	closed, err := s.store.CloseFriendSessions(r.Context(), fs.DeviceA, fs.DeviceB)
	if err != nil {
		s.logger.Warn("close friend sessions failed", "err", err)
	}
	notifyFriendship(r, s, updated, events.TypeFriendRemoved, dev.DeviceID)
	for _, sid := range closed {
		s.logger.Info("[SESSION CLOSE]", "session_id", sid, "reason", "friendship_removed",
			"by", dev.DeviceID)
		s.bus.Publish(dev.DeviceID, newEvent(events.TypeRequestRejected, sid, ""))
		other := fs.DeviceA
		if other == dev.DeviceID {
			other = fs.DeviceB
		}
		s.bus.Publish(other, newEvent(events.TypeRequestRejected, sid, dev.DeviceID))
	}
	s.logger.Info("friendship revoked", "friendship_id", fs.FriendshipID,
		"a", fs.DeviceA, "b", fs.DeviceB, "by", dev.DeviceID, "closed_sessions", len(closed))
	writeJSON(w, http.StatusOK, map[string]any{"status": "removed"})
}

// notifyFriendship 向关系双方发布好友事件（payload 含对端设备名/设备 ID）。
func notifyFriendship(r *http.Request, s *Server, fs model.Friendship, evType string, actor string) {
	for _, id := range []string{fs.DeviceA, fs.DeviceB} {
		if id == "" {
			continue
		}
		peerID := fs.DeviceA
		if peerID == id {
			peerID = fs.DeviceB
		}
		payload := map[string]any{"friendship_id": fs.FriendshipID, "peer_device_id": peerID}
		if peer, err := s.store.Device(r.Context(), peerID); err == nil {
			payload["peer_name"] = peer.DeviceName
		}
		s.bus.Publish(id, events.Event{Type: evType, SessionID: "", DeviceID: actor, Payload: payload})
	}
}

// ---- 好友直连（连接请求信令） ----

// friendConnectRequest POST /v1/friends/{device_id}/connect 请求体。
type friendConnectRequest struct {
	NetworkID string `json:"network_id,omitempty"`
}

// handleFriendConnect POST /v1/friends/{device_id}/connect（auth）：
// 向已建立好友关系的对端发起直连请求 → 创建 target 指定会话并通知对端。
// 对端接受后走既有 DirectLink/Noise/Overlay 链路（复用 6 位码会话机制）。
func (s *Server) handleFriendConnect(w http.ResponseWriter, r *http.Request, dev model.Device) {
	targetID := r.PathValue("device_id")
	if targetID == dev.DeviceID {
		writeError(w, &apiError{Code: "SELF_CONNECT", Message: "不能连接自己",
			Status: http.StatusBadRequest})
		return
	}
	var req friendConnectRequest
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

	sess, err := s.store.CreateFriendSession(r.Context(), dev.DeviceID, targetID, networkID)
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
	// 通知目标设备：A 想连接你。
	fromName := dev.DeviceName
	s.bus.Publish(targetID, events.Event{
		Type:      events.TypeConnectionRequest,
		SessionID: sess.SessionID,
		DeviceID:  dev.DeviceID,
		Payload: map[string]any{
			"from_device_id": dev.DeviceID,
			"from_name":      fromName,
		},
	})
	s.logger.Info("friend connect request", "session_id", sess.SessionID,
		"from", dev.DeviceID, "to", targetID)
	// creator 视角（target 尚未接受 → 仅 creator 成员）。
	writeJSON(w, http.StatusOK, newSessionView(sess, members, false))
}

// handleAcceptConnectionRequest POST /v1/sessions/{session_id}/accept-request（auth）：
// 目标设备接受好友直连请求 → 作为 joiner 加入（JOINED），响应含双方公钥快照。
func (s *Server) handleAcceptConnectionRequest(w http.ResponseWriter, r *http.Request, dev model.Device) {
	sess, members, err := s.store.AcceptConnectionRequest(r.Context(), r.PathValue("session_id"), dev.DeviceID)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	// 通知 creator：目标已接受（加速；creator 也轮询会话状态兜底）。
	s.bus.Publish(sess.CreatorDeviceID, newEvent(events.TypeSessionJoined, sess.SessionID, dev.DeviceID))
	s.logger.Info("connection request accepted", "session_id", sess.SessionID,
		"target", dev.DeviceID, "creator", sess.CreatorDeviceID)
	writeJSON(w, http.StatusOK, newSessionView(sess, members, false))
}

// handleRejectConnectionRequest POST /v1/sessions/{session_id}/reject-request（auth）：
// 目标设备拒绝好友直连请求 → 会话 CLOSED，通知 creator。
func (s *Server) handleRejectConnectionRequest(w http.ResponseWriter, r *http.Request, dev model.Device) {
	if err := s.store.RejectConnectionRequest(r.Context(), r.PathValue("session_id"), dev.DeviceID); err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	creator, _, _, err := s.store.SessionTarget(r.Context(), r.PathValue("session_id"))
	if err == nil && creator != "" {
		s.bus.Publish(creator, newEvent(events.TypeRequestRejected, r.PathValue("session_id"), dev.DeviceID))
	}
	s.logger.Info("[SESSION CLOSE]", "session_id", r.PathValue("session_id"),
		"reason", "connection_request_rejected", "target", dev.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "rejected"})
}

// ---- 设备 / 在线状态 ----

// handleDeviceGet GET /v1/devices/{device_id}（auth）：
// 设备详情（含公钥指纹）。仅本人或好友可查（防枚举）。
func (s *Server) handleDeviceGet(w http.ResponseWriter, r *http.Request, dev model.Device) {
	deviceID := r.PathValue("device_id")
	if deviceID == dev.DeviceID {
		// 本人。
	} else {
		friends, err := s.store.AreFriends(r.Context(), dev.DeviceID, deviceID)
		if err != nil {
			writeError(w, errInternal(err))
			return
		}
		if !friends {
			writeError(w, &apiError{Code: "DEVICE_NOT_FOUND", Message: "设备未注册",
				Status: http.StatusNotFound})
			return
		}
	}
	dp, err := s.store.DeviceWithPresence(r.Context(), deviceID)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	writeJSON(w, http.StatusOK, dp)
}

// handlePresenceHeartbeat POST /v1/presence/heartbeat（auth）：
// 刷新 last_seen（在线判定依据；auth 中间件已 touch，本端点显式保活）。
func (s *Server) handlePresenceHeartbeat(w http.ResponseWriter, r *http.Request, dev model.Device) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "device_id": dev.DeviceID})
}
