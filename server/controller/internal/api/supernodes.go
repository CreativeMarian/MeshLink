package api

import (
	"net/http"
	"time"

	"meshlink/server/controller/internal/model"
)

// Supernode Registry API（M1-2）：
//   - GET    /v1/supernodes         列表（Agent 启动/刷新时拉取 → N2N 池）；
//   - POST   /v1/supernodes         注册/更新（Supernode 进程自注册）；
//   - POST   /v1/supernodes/{id}/heartbeat  健康心跳。
//
// 列表鉴权沿用设备 credential；注册端点也要求已注册设备（凭证一致）。

type supernodeBody struct {
	ID       string `json:"id"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Priority int    `json:"priority"`
}

func (s *Server) handleSupernodesList(w http.ResponseWriter, r *http.Request, _ model.Device) {
	sns, err := s.store.Supernodes(r.Context())
	if err != nil {
		writeError(w, errInternal(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"supernodes": sns})
}

func (s *Server) handleSupernodeRegister(w http.ResponseWriter, r *http.Request, _ model.Device) {
	var body supernodeBody
	if err := decodeJSON(w, r, &body); err != nil {
		writeError(w, errValidation("请求体 JSON 解析失败"))
		return
	}
	if body.ID == "" || body.Host == "" || body.Port <= 0 || body.Port > 65535 {
		writeError(w, errValidation("id/host/port 非法"))
		return
	}
	if body.Priority <= 0 {
		body.Priority = 100
	}
	sn := model.Supernode{
		ID:       body.ID,
		Host:     body.Host,
		Port:     body.Port,
		Priority: body.Priority,
		Healthy:  true,
		LastSeen: time.Now().UTC(),
	}
	if err := s.store.UpsertSupernode(r.Context(), sn); err != nil {
		writeError(w, errInternal(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"registered": true, "supernode": sn})
}

func (s *Server) handleSupernodeHeartbeat(w http.ResponseWriter, r *http.Request, _ model.Device) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, errValidation("缺少 supernode id"))
		return
	}
	if err := s.store.TouchSupernode(r.Context(), id); err != nil {
		writeError(w, &apiError{Code: "SUPERNODE_NOT_FOUND", Message: "supernode 不存在", Status: http.StatusNotFound})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"healthy": true})
}
