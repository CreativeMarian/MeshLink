// 设备注册与公钥绑定 API。

package api

import (
	"net/http"

	"meshlink/server/controller/internal/model"
	"meshlink/server/controller/internal/store"
)

// registerRequest POST /v1/devices 请求体。
type registerRequest struct {
	DeviceID       string `json:"device_id"`
	NoisePublicKey string `json:"noise_public_key"` // hex 64（X25519 静态公钥）
	DeviceName     string `json:"device_name,omitempty"`
}

// registerResponse 注册响应。首次注册返回一次性 credential（仅此一次下发，
// Controller 只保存其 SHA-256 hash）；幂等重放（同公钥再注册）不再下发。
type registerResponse struct {
	DeviceID       string `json:"device_id"`
	NoisePublicKey string `json:"noise_public_key"`
	DeviceName     string `json:"device_name,omitempty"`
	Status         string `json:"status"`               // registered | existing
	Credential     string `json:"credential,omitempty"` // 仅首次注册出现
}

// handleRegisterDevice POST /v1/devices（无需认证）。
//
// 公钥绑定规则：第一次合法注册建立 device_id → noise_public_key 绑定；
// 之后同 device_id 公钥相同 → 允许（幂等）；公钥变化 → DEVICE_KEY_MISMATCH
// 禁止自动覆盖。客户端上传新 k 时 Controller 绝不静默覆盖旧 k。
func (s *Server) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if !store.ValidDeviceID(req.DeviceID) {
		writeError(w, errValidation("device_id 非法（空/超长/含不可见字符）"))
		return
	}
	if !store.ValidPublicKeyHex(req.NoisePublicKey) {
		writeError(w, errValidation("noise_public_key 非法（须为 hex 64 字符的 X25519 公钥）"))
		return
	}
	if len(req.DeviceName) > 128 {
		writeError(w, errValidation("device_name 过长（≤128）"))
		return
	}

	credential := store.NewCredential()
	credHash := store.HashToken(credential)

	dev, created, err := s.store.RegisterDevice(r.Context(), req.DeviceID,
		req.NoisePublicKey, req.DeviceName, credHash)
	if err != nil {
		if ae := mapStoreError(err); ae != nil {
			writeError(w, ae)
			return
		}
		writeError(w, errInternal(err))
		return
	}

	resp := registerResponse{
		DeviceID:       dev.DeviceID,
		NoisePublicKey: dev.NoisePublicKey,
		DeviceName:     dev.DeviceName,
		Status:         "existing",
	}
	if created {
		resp.Status = "registered"
		resp.Credential = credential // 一次性下发；客户端必须 DPAPI 保存
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleDeviceMe GET /v1/devices/me（认证）：查询本设备注册信息。
func (s *Server) handleDeviceMe(w http.ResponseWriter, r *http.Request, dev model.Device) {
	writeJSON(w, http.StatusOK, model.Device{
		DeviceID:       dev.DeviceID,
		NoisePublicKey: dev.NoisePublicKey,
		DeviceName:     dev.DeviceName,
		Status:         dev.Status,
		CreatedAt:      dev.CreatedAt,
		LastSeenAt:     dev.LastSeenAt,
	})
}
