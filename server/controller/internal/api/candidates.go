// 候选交换 API：A 上传 candidates / B 上传 candidates，双方分别拉取对端。
// Controller 只交换信令候选；数据路径仍是 A ↔ DirectLink UDP + Noise ↔ B。

package api

import (
	"net"
	"net/http"
	"strconv"
	"time"

	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
)

// putCandidatesRequest PUT /v1/sessions/{id}/candidates 请求体。
type putCandidatesRequest struct {
	Candidates []model.Candidate `json:"candidates"`
}

// handlePutCandidates PUT /v1/sessions/{session_id}/candidates（auth 成员）：
// 上传本端候选集（UPSERT），成功后向其他成员推送 candidates_updated。
func (s *Server) handlePutCandidates(w http.ResponseWriter, r *http.Request, dev model.Device) {
	sess, members, ok := s.loadSessionForMember(w, r, dev, r.PathValue("session_id"))
	if !ok {
		return
	}
	var req putCandidatesRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, err)
		return
	}
	if len(req.Candidates) > model.MaxCandidatesPerPut {
		writeError(w, errValidation("候选数量超限"))
		return
	}
	for i, c := range req.Candidates {
		if c.Kind != model.CandidateKindHost && c.Kind != model.CandidateKindSrflx {
			writeError(w, errValidation("候选 kind 非法（host|srflx）"))
			return
		}
		ip := net.ParseIP(c.IP)
		if ip == nil || ip.To4() == nil {
			writeError(w, errValidation("候选 ip 须为合法 IPv4"))
			return
		}
		if c.Port == 0 {
			writeError(w, errValidation("候选 port 非法"))
			return
		}
		_ = i
	}

	if err := s.store.PutCandidates(r.Context(), sess.SessionID, dev.DeviceID, req.Candidates); err != nil {
		writeError(w, errInternal(err))
		return
	}
	// 通知对端（除上传者外的成员）。
	for _, m := range members {
		if m.DeviceID != dev.DeviceID {
			s.bus.Publish(m.DeviceID, newEvent(events.TypeCandidatesUpdated, sess.SessionID, dev.DeviceID))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "count": len(req.Candidates)})
}

// peerCandidatesResponse GET 响应：对端候选聚合。
type peerCandidatesResponse struct {
	SessionID string           `json:"session_id"`
	Peers     []peerCandidates `json:"peers"`
}

type peerCandidates struct {
	DeviceID   string            `json:"device_id"`
	Candidates []model.Candidate `json:"candidates"`
	UpdatedAt  string            `json:"updated_at"`
}

// handleGetCandidates GET /v1/sessions/{session_id}/candidates（auth 成员）：
// 拉取对端候选。支持 ?wait_ms=N 长轮询（等待对端上传，最多 30s）——
// 轮询是权威通道；WSS /v1/events 仅是加速器。
func (s *Server) handleGetCandidates(w http.ResponseWriter, r *http.Request, dev model.Device) {
	sess, members, ok := s.loadSessionForMember(w, r, dev, r.PathValue("session_id"))
	if !ok {
		return
	}
	waitMs := 0
	if q := r.URL.Query().Get("wait_ms"); q != "" {
		n, err := strconv.Atoi(q)
		if err != nil || n < 0 || n > 30_000 {
			writeError(w, errValidation("wait_ms 非法（0..30000）"))
			return
		}
		waitMs = n
	}

	peers := peersWithCandidates(r, s, sess.SessionID, dev.DeviceID, members)
	if len(peers) == 0 && waitMs > 0 {
		deadline := time.Now().Add(time.Duration(waitMs) * time.Millisecond)
		for time.Now().Before(deadline) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(400 * time.Millisecond):
			}
			peers = peersWithCandidates(r, s, sess.SessionID, dev.DeviceID, members)
			if len(peers) > 0 {
				break
			}
		}
	}
	if peers == nil {
		peers = []peerCandidates{}
	}
	writeJSON(w, http.StatusOK, peerCandidatesResponse{SessionID: sess.SessionID, Peers: peers})
}

func peersWithCandidates(r *http.Request, s *Server, sessionID, selfDevice string, members []model.SessionMember) []peerCandidates {
	var peers []peerCandidates
	for _, m := range members {
		if m.DeviceID == selfDevice {
			continue
		}
		cands, updated, err := s.store.Candidates(r.Context(), sessionID, m.DeviceID)
		if err != nil || len(cands) == 0 {
			continue // 对端尚未上传
		}
		peers = append(peers, peerCandidates{
			DeviceID:   m.DeviceID,
			Candidates: cands,
			UpdatedAt:  updated.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	return peers
}
