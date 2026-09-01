// 最近连接 API（M1-1.5）。
//
// 本地历史，与好友关系完全分离：
// - 6 位码临时连接成功后 Agent 调用 PUT 记录一条 recent_connection；
// - 对端名称与指纹快照必须来自 Controller Device Registry（store 内部读取），
//   客户端不可自报——防止客户端伪造对端身份；
// - 只保存必要显示信息（名称/指纹快照/overlay IP/路径/次数/时间），
//   不保存公网 IP / 完整 candidate / STUN（隐私要求：高级诊断另存）；
// - DELETE 只删本机历史记录，不影响好友关系。

package api

import (
	"net/http"

	"meshlink/server/controller/internal/model"
	"meshlink/server/controller/internal/store"
)

// recentUpsertRequest PUT /v1/devices/me/recent-connections/{device_id} 请求体。
type recentUpsertRequest struct {
	OverlayIP string `json:"overlay_ip,omitempty"` // 本机在该会话中的 overlay IP
	Path      string `json:"path,omitempty"`       // directlink | n2n
}

// handleListRecentConnections GET /v1/devices/me/recent-connections（认证）。
func (s *Server) handleListRecentConnections(w http.ResponseWriter, r *http.Request, dev model.Device) {
	list, err := s.store.ListRecentConnections(r.Context(), dev.DeviceID)
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	if list == nil {
		list = []model.RecentConnection{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"recent_connections": list})
}

// handleUpsertRecentConnection PUT /v1/devices/me/recent-connections/{device_id}（认证）。
// Agent 在 CONNECTED（规格十二 8 条件全满足）后调用；对端指纹/名称由 store 从
// Registry 读取，客户端只上传 overlay_ip 与 path。
func (s *Server) handleUpsertRecentConnection(w http.ResponseWriter, r *http.Request, dev model.Device) {
	remoteID := r.PathValue("device_id")
	if !store.ValidDeviceID(remoteID) {
		writeError(w, errValidation("device_id 非法（空/超长/含不可见字符）"))
		return
	}
	var req recentUpsertRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Path != "" && req.Path != "directlink" && req.Path != "n2n" {
		writeError(w, errValidation("path 必须是 directlink / n2n"))
		return
	}
	rc, err := s.store.UpsertRecentConnection(r.Context(), dev.DeviceID, remoteID, req.OverlayIP, req.Path)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}
	writeJSON(w, http.StatusOK, rc)
}

// handleDeleteRecentConnection DELETE /v1/devices/me/recent-connections/{device_id}（认证）。
// 只删除本机历史记录，不影响好友关系（规格十一）。
func (s *Server) handleDeleteRecentConnection(w http.ResponseWriter, r *http.Request, dev model.Device) {
	remoteID := r.PathValue("device_id")
	if !store.ValidDeviceID(remoteID) {
		writeError(w, errValidation("device_id 非法（空/超长/含不可见字符）"))
		return
	}
	if err := s.store.DeleteRecentConnection(r.Context(), dev.DeviceID, remoteID); err != nil {
		writeError(w, errInternal(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true})
}
