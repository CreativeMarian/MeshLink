// HTTP API 层（Controller MVP）：路由 + bearer 认证 + 错误映射。
//
// 硬性边界：
// - Controller 只做 Identity / Signaling / Session / Invite / Candidate，
//   禁止任何数据面转发（文件 / Overlay packet / UDP relay 均不在本包出现）；
// - 生产模式只允许经 TLS 终结层（如 Cloudflare Tunnel）暴露 HTTPS/WSS；
//   本实现监听明文 HTTP，DEV MODE 启动横幅强制声明 localhost-only；
// - 6 位码只是索引：绝不作为认证 secret、绝不派生 Noise 密钥。

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
	"meshlink/server/controller/internal/ratelimit"
	"meshlink/server/controller/internal/store"
)

// Server Controller HTTP 服务（挂载全部 /v1 路由）。
type Server struct {
	store      *store.Store
	limiter    *ratelimit.Tracker
	bus        *events.Bus
	trustProxy bool // 信任 X-Forwarded-For（仅在 TLS 终结代理后开启）
	logger     *slog.Logger
}

// NewServer 构建 Controller API 服务。
func NewServer(st *store.Store, lim *ratelimit.Tracker, bus *events.Bus, trustProxy bool, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{store: st, limiter: lim, bus: bus, trustProxy: trustProxy, logger: logger}
}

// Handler 返回完整路由的 http.Handler。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealthz)

	// 设备注册（无需认证：首次注册建立绑定；幂等重放校验公钥一致）。
	mux.HandleFunc("POST /v1/devices", s.handleRegisterDevice)
	mux.HandleFunc("GET /v1/devices/me", s.auth(s.handleDeviceMe))

	// 6 位码快速连接。
	mux.HandleFunc("POST /v1/sessions", s.auth(s.handleCreateSession))
	mux.HandleFunc("POST /v1/sessions/{code}/join", s.auth(s.handleJoinSession))
	mux.HandleFunc("GET /v1/sessions/{session_id}", s.auth(s.handleGetSession))

	// 候选交换。
	mux.HandleFunc("PUT /v1/sessions/{session_id}/candidates", s.auth(s.handlePutCandidates))
	mux.HandleFunc("GET /v1/sessions/{session_id}/candidates", s.auth(s.handleGetCandidates))

	// 好友邀请。
	mux.HandleFunc("POST /v1/invites", s.auth(s.handleCreateInvite))
	mux.HandleFunc("GET /v1/invites", s.auth(s.handleListInvites))
	mux.HandleFunc("GET /v1/invites/{invite_id}", s.auth(s.handleGetInvite))
	mux.HandleFunc("POST /v1/invites/{invite_id}/redeem", s.auth(s.handleRedeemInvite))
	mux.HandleFunc("POST /v1/invites/{invite_id}/revoke", s.auth(s.handleRevokeInvite))

	// 好友关系（M1-1）。
	mux.HandleFunc("GET /v1/friendships", s.auth(s.handleListFriendships))
	mux.HandleFunc("GET /v1/friendships/{friendship_id}", s.auth(s.handleGetFriendship))
	mux.HandleFunc("POST /v1/friendships/{friendship_id}/accept", s.auth(s.handleAcceptFriendship))
	mux.HandleFunc("POST /v1/friendships/{friendship_id}/reject", s.auth(s.handleRejectFriendship))
	mux.HandleFunc("POST /v1/friendships/{friendship_id}/revoke", s.auth(s.handleRevokeFriendship))

	// 好友直连（连接请求信令）。
	mux.HandleFunc("POST /v1/friends/{device_id}/connect", s.auth(s.handleFriendConnect))
	mux.HandleFunc("POST /v1/sessions/{session_id}/accept-request", s.auth(s.handleAcceptConnectionRequest))
	mux.HandleFunc("POST /v1/sessions/{session_id}/reject-request", s.auth(s.handleRejectConnectionRequest))

	// 设备 / 在线状态。
	mux.HandleFunc("GET /v1/devices/{device_id}", s.auth(s.handleDeviceGet))
	mux.HandleFunc("POST /v1/presence/heartbeat", s.auth(s.handlePresenceHeartbeat))

	// M1-1.5：最近连接历史（本机历史，与好友关系分离）。
	mux.HandleFunc("GET /v1/devices/me/recent-connections", s.auth(s.handleListRecentConnections))
	mux.HandleFunc("PUT /v1/devices/me/recent-connections/{device_id}", s.auth(s.handleUpsertRecentConnection))
	mux.HandleFunc("DELETE /v1/devices/me/recent-connections/{device_id}", s.auth(s.handleDeleteRecentConnection))

	// WSS 事件通道（客户端亦可纯轮询，事件仅为加速）。
	mux.HandleFunc("GET /v1/events", s.auth(s.handleEvents))
	mux.HandleFunc("GET /v1/events/poll", s.auth(s.handleEventsPoll))

	// M1-2：Supernode Registry（Agent 拉取池 + Supernode 自注册/心跳）。
	mux.HandleFunc("GET /v1/supernodes", s.auth(s.handleSupernodesList))
	mux.HandleFunc("POST /v1/supernodes", s.auth(s.handleSupernodeRegister))
	mux.HandleFunc("POST /v1/supernodes/{id}/heartbeat", s.auth(s.handleSupernodeHeartbeat))

	return mux
}

// ---- API 错误模型 ----

// apiError 结构化 JSON 错误（code 与客户端错误提示约定一致，message 不泄露内部细节）。
type apiError struct {
	Code    string
	Message string
	Status  int
}

func (e *apiError) Error() string { return e.Code + ": " + e.Message }

func errValidation(msg string) *apiError {
	return &apiError{Code: "VALIDATION_INVALID", Message: msg, Status: http.StatusBadRequest}
}
func errAuthRequired() *apiError {
	return &apiError{Code: "AUTH_REQUIRED", Message: "缺少认证凭据", Status: http.StatusUnauthorized}
}
func errAuthInvalid() *apiError {
	return &apiError{Code: "AUTH_INVALID", Message: "认证凭据无效", Status: http.StatusUnauthorized}
}
func errInternal(err error) *apiError {
	return &apiError{Code: "INTERNAL", Message: "内部错误", Status: http.StatusInternalServerError}
}

// mapStoreError store 哨兵错误 → API 错误（用户可见语义）。
func mapStoreError(err error) *apiError {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae
	}
	switch {
	case errors.Is(err, store.ErrDeviceKeyMismatch):
		// 公钥变化：绝不自动覆盖——需要显式重新注册 / key rotation 流程。
		return &apiError{Code: "DEVICE_KEY_MISMATCH",
			Message: "设备公钥与注册绑定不一致，禁止自动覆盖；需重新注册或走密钥轮换流程",
			Status:  http.StatusConflict}
	case errors.Is(err, store.ErrSessionNotFound):
		return &apiError{Code: "SESSION_CODE_INVALID", Message: "连接码对应的会话不存在",
			Status: http.StatusNotFound}
	case errors.Is(err, store.ErrSessionExpired):
		return &apiError{Code: "SESSION_EXPIRED", Message: "会话已过期（10 分钟有效期）",
			Status: http.StatusGone}
	case errors.Is(err, store.ErrSessionStateInvalid):
		return &apiError{Code: "SESSION_STATE_INVALID", Message: "会话状态不允许该操作",
			Status: http.StatusConflict}
	case errors.Is(err, store.ErrCodeTaken):
		return &apiError{Code: "QUICK_CODE_TAKEN", Message: "指定的连接码已被占用，请换一个",
			Status: http.StatusConflict}
	case errors.Is(err, store.ErrNotMember):
		return &apiError{Code: "SESSION_NOT_MEMBER", Message: "非会话成员",
			Status: http.StatusForbidden}
	case errors.Is(err, store.ErrInviteNotFound):
		return &apiError{Code: "INVITE_NOT_FOUND", Message: "邀请不存在",
			Status: http.StatusNotFound}
	case errors.Is(err, store.ErrInviteTokenInvalid):
		return &apiError{Code: "INVITE_INVALID_TOKEN", Message: "邀请码无效",
			Status: http.StatusForbidden}
	case errors.Is(err, store.ErrInviteExpired):
		return &apiError{Code: "INVITE_EXPIRED", Message: "邀请已过期", Status: http.StatusGone}
	case errors.Is(err, store.ErrInviteExhausted):
		return &apiError{Code: "INVITE_EXHAUSTED", Message: "邀请次数已用尽",
			Status: http.StatusConflict}
	case errors.Is(err, store.ErrInviteRedeemed):
		return &apiError{Code: "INVITE_REDEEMED", Message: "该设备已兑换过此邀请",
			Status: http.StatusConflict}
	case errors.Is(err, store.ErrFriendshipNotFound):
		return &apiError{Code: "FRIENDSHIP_NOT_FOUND", Message: "好友关系不存在",
			Status: http.StatusNotFound}
	case errors.Is(err, store.ErrFriendshipExists):
		return &apiError{Code: "FRIENDSHIP_EXISTS", Message: "与该设备已是好友或已有待处理请求",
			Status: http.StatusConflict}
	case errors.Is(err, store.ErrFriendshipState):
		return &apiError{Code: "FRIENDSHIP_STATE_INVALID", Message: "好友关系状态不允许该操作",
			Status: http.StatusConflict}
	case errors.Is(err, store.ErrNotFriends):
		return &apiError{Code: "NOT_FRIENDS", Message: "对方不是好友，无法发起直连",
			Status: http.StatusForbidden}
	case errors.Is(err, store.ErrNotTarget):
		return &apiError{Code: "NOT_TARGET", Message: "非该直连请求的目标设备",
			Status: http.StatusForbidden}
	case errors.Is(err, store.ErrSelfConnect):
		return &apiError{Code: "SELF_CONNECT", Message: "不能连接自己",
			Status: http.StatusBadRequest}
	case errors.Is(err, store.ErrDeviceNotFound):
		return &apiError{Code: "DEVICE_NOT_FOUND", Message: "设备未注册", Status: http.StatusNotFound}
	case errors.Is(err, store.ErrOverlayPoolExhausted):
		// 池耗尽属运维层问题（容量规划），不是客户端可重试错误。
		return &apiError{Code: "OVERLAY_POOL_EXHAUSTED",
			Message: "虚拟网段地址池已耗尽，请联系管理员扩容 overlay 地址池",
			Status:  http.StatusServiceUnavailable}
	default:
		return nil
	}
}

// writeError 输出 JSON 错误（message 固定文案，details 只进日志）。
func writeError(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		mapped := mapStoreError(err)
		if mapped == nil {
			ae = errInternal(err)
			slog.Error("controller internal error", "err", err)
		} else {
			ae = mapped
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(ae.Status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": ae.Code, "message": ae.Message},
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // 空 body 视作空 JSON 对象（必填字段由各 handler 校验）
		}
		return errValidation("请求体不是合法 JSON（或超过 64KB）")
	}
	return nil
}

// ---- 认证 ----

type ctxKey int

const deviceKey ctxKey = 1

// auth bearer 认证中间件：Authorization: Bearer <credential>。
// credential 为注册时一次性下发的高熵凭据；Controller 只存 SHA-256 hash。
func (s *Server) auth(next func(w http.ResponseWriter, r *http.Request, dev model.Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if header == "" {
			writeError(w, errAuthRequired())
			return
		}
		const prefix = "Bearer "
		if !strings.HasPrefix(header, prefix) {
			writeError(w, errAuthInvalid())
			return
		}
		credential := strings.TrimSpace(header[len(prefix):])
		if credential == "" {
			writeError(w, errAuthInvalid())
			return
		}
		dev, err := s.store.DeviceByCredential(r.Context(), store.HashToken(credential))
		if err != nil {
			writeError(w, errAuthInvalid())
			return
		}
		s.store.TouchDevice(r.Context(), dev.DeviceID)
		next(w, r.WithContext(context.WithValue(r.Context(), deviceKey, dev)), dev)
	}
}

// deviceFromContext 认证中间件注入的设备。
func deviceFromContext(r *http.Request) (model.Device, bool) {
	dev, ok := r.Context().Value(deviceKey).(model.Device)
	return dev, ok
}

// clientIP 提取限流用 IP（TRUST_PROXY=1 时优先 X-Forwarded-For 首值）。
func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if i := strings.IndexByte(xff, ','); i > 0 {
				return strings.TrimSpace(xff[:i])
			}
			return strings.TrimSpace(xff)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---- healthz ----

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"service": "meshlink-controller",
		"version": "0.2.0-m0-controller-mvp",
		"now":     time.Now().UTC().Format(time.RFC3339),
	})
}
