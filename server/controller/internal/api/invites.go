// 好友邀请 API（与 6 位码完全独立的长期授权）。
//
// 规则（用户规格十）：
// - invite 携带 invite_token（一次性下发，hash 入库）；
// - 支持永久 / 24 小时 / 7 天 / 单次 / 多次；
// - 邀请过期后（>10 分钟）仍可凭邀请创建新的 Connection Session；
// - 不保存旧 6 位码实现邀请。

package api

import (
	"net/http"
	"time"

	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
	"meshlink/server/controller/internal/store"
)

// createInviteRequest POST /v1/invites 请求体。
type createInviteRequest struct {
	NetworkID string `json:"network_id,omitempty"`
	TTL       string `json:"ttl,omitempty"`      // "permanent"(默认) | "24h" | "7d"
	MaxUses   int64  `json:"max_uses,omitempty"` // 0 = 不限次；1 = 单次
}

// inviteView 邀请视图（token 仅创建响应出现一次；查询响应不含 token）。
type inviteView struct {
	InviteID    string                   `json:"invite_id"`
	InviteToken string                   `json:"invite_token,omitempty"` // 仅创建响应
	NetworkID   string                   `json:"network_id"`
	ExpiresAt   *string                  `json:"expires_at,omitempty"` // nil = 永久
	MaxUses     int64                    `json:"max_uses"`
	UsedCount   int64                    `json:"used_count"`
	Status      string                   `json:"status"`
	CreatedAt   string                   `json:"created_at"`
	Redemptions []model.InviteRedemption `json:"redemptions,omitempty"`
}

// handleCreateInvite POST /v1/invites（auth）：创建好友邀请。
func (s *Server) handleCreateInvite(w http.ResponseWriter, r *http.Request, dev model.Device) {
	var req createInviteRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	networkID := req.NetworkID
	if networkID == "" {
		networkID = "default"
	}
	if len(networkID) > 128 {
		writeError(w, errValidation("network_id 过长"))
		return
	}

	var expiresAt *time.Time
	switch req.TTL {
	case "", "permanent":
		// 永久
	case "24h":
		t := time.Now().UTC().Add(model.InviteTTL24h)
		expiresAt = &t
	case "7d":
		t := time.Now().UTC().Add(model.InviteTTL7d)
		expiresAt = &t
	default:
		writeError(w, errValidation("ttl 非法（permanent|24h|7d）"))
		return
	}
	if req.MaxUses < 0 || req.MaxUses > 1000 {
		writeError(w, errValidation("max_uses 非法（0..1000，0=不限）"))
		return
	}

	token := store.NewInviteToken()
	inv, err := s.store.CreateInvite(r.Context(), dev.DeviceID, networkID,
		store.HashToken(token), expiresAt, req.MaxUses)
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	v := inviteView{
		InviteID:    inv.InviteID,
		InviteToken: token,
		NetworkID:   inv.NetworkID,
		MaxUses:     inv.MaxUses,
		Status:      string(inv.Status),
		CreatedAt:   inv.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if inv.ExpiresAt != nil {
		et := inv.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
		v.ExpiresAt = &et
	}
	s.logger.Info("invite created", "invite_id", inv.InviteID, "creator", dev.DeviceID, "ttl", req.TTL)
	writeJSON(w, http.StatusOK, v)
}

// handleGetInvite GET /v1/invites/{invite_id}（auth）：邀请方轮询状态 + 兑换记录
// （发现新 session_id → GET /v1/sessions 拿对方公钥与候选）。
func (s *Server) handleGetInvite(w http.ResponseWriter, r *http.Request, dev model.Device) {
	inv, err := s.store.Invite(r.Context(), r.PathValue("invite_id"))
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	if inv.CreatorDeviceID != dev.DeviceID {
		// 非创建者只能看到存在性（不暴露邀请元数据）。
		writeError(w, &apiError{Code: "INVITE_NOT_FOUND", Message: "邀请不存在",
			Status: http.StatusNotFound})
		return
	}
	v := inviteView{
		InviteID:  inv.InviteID,
		NetworkID: inv.NetworkID,
		MaxUses:   inv.MaxUses,
		UsedCount: inv.UsedCount,
		Status:    string(inv.Status),
		CreatedAt: inv.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	if inv.ExpiresAt != nil {
		et := inv.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
		v.ExpiresAt = &et
	}
	if rds, err := s.store.InviteRedemptions(r.Context(), inv.InviteID); err == nil && len(rds) > 0 {
		v.Redemptions = rds
	}
	writeJSON(w, http.StatusOK, v)
}

// redeemRequest POST /v1/invites/{invite_id}/redeem 请求体。
type redeemRequest struct {
	InviteToken string `json:"invite_token"`
}

// redeemView 兑换响应：PENDING 好友关系 + 邀请方设备信息（UI 显示"来自"）。
type redeemView struct {
	FriendshipID string                  `json:"friendship_id"`
	Status       string                  `json:"status"`
	Creator      model.DeviceWithPresence `json:"creator"`
}

// handleRedeemInvite POST /v1/invites/{invite_id}/redeem（auth，M1-1）：
// 验证 token / 有效期 / 次数 → 建立 PENDING 好友关系（不再创建连接会话）。
// 响应含邀请方设备信息（用于 UI 展示"收到来自 X 的好友邀请"）。
func (s *Server) handleRedeemInvite(w http.ResponseWriter, r *http.Request, dev model.Device) {
	var req redeemRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.InviteToken == "" {
		writeError(w, errValidation("invite_token 不能为空"))
		return
	}

	fs, creatorID, err := s.store.RedeemInvite(r.Context(), r.PathValue("invite_id"),
		store.HashToken(req.InviteToken), dev.DeviceID)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	creator, _ := s.store.DeviceWithPresence(r.Context(), creatorID)
	// 通知双方：好友请求待接受（PENDING）。
	s.bus.Publish(creatorID, events.Event{Type: events.TypeFriendPending,
		SessionID: "", DeviceID: dev.DeviceID,
		Payload: map[string]any{"friendship_id": fs.FriendshipID, "peer_device_id": dev.DeviceID, "peer_name": dev.DeviceName}})
	s.bus.Publish(dev.DeviceID, events.Event{Type: events.TypeFriendPending,
		SessionID: "", DeviceID: creatorID,
		Payload: map[string]any{"friendship_id": fs.FriendshipID, "peer_device_id": creatorID, "peer_name": creator.DeviceName}})
	s.logger.Info("invite redeemed → friendship", "invite_id", r.PathValue("invite_id"),
		"friendship_id", fs.FriendshipID, "creator", creatorID, "joiner", dev.DeviceID)
	writeJSON(w, http.StatusOK, redeemView{
		FriendshipID: fs.FriendshipID,
		Status:       string(fs.Status),
		Creator:      creator,
	})
}

// handleListInvites GET /v1/invites（auth）：我的邀请列表（含状态/使用情况）。
func (s *Server) handleListInvites(w http.ResponseWriter, r *http.Request, dev model.Device) {
	invites, err := s.store.InvitesForDevice(r.Context(), dev.DeviceID)
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	out := make([]inviteView, 0, len(invites))
	for _, inv := range invites {
		v := inviteView{
			InviteID:  inv.InviteID,
			NetworkID: inv.NetworkID,
			MaxUses:   inv.MaxUses,
			UsedCount: inv.UsedCount,
			Status:    string(inv.Status),
			CreatedAt: inv.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		}
		if inv.ExpiresAt != nil {
			et := inv.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z")
			v.ExpiresAt = &et
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": out})
}

// handleRevokeInvite POST /v1/invites/{invite_id}/revoke（auth 创建者）：
// 撤销邀请 → REVOKED，旧 token 立即不可再兑换。
func (s *Server) handleRevokeInvite(w http.ResponseWriter, r *http.Request, dev model.Device) {
	if err := s.store.RevokeInvite(r.Context(), r.PathValue("invite_id"), dev.DeviceID); err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	s.logger.Info("invite revoked", "invite_id", r.PathValue("invite_id"), "creator", dev.DeviceID)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked"})
}
