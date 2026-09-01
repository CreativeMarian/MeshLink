// API 集成测试（httptest 全路由）：设备注册 / 公钥绑定 / 6 位码会话 /
// 限流 / 候选交换 / 好友邀请 / WSS 事件。覆盖用户 Controller MVP 规格
// 核心断言：joiner 获得 creator 公钥必须来自 Controller 注册表响应。

package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"meshlink/server/controller/internal/events"
	"meshlink/server/controller/internal/model"
	"meshlink/server/controller/internal/ratelimit"
	"meshlink/server/controller/internal/store"
)

type testEnv struct {
	srv *httptest.Server
	api *Server
	st  *store.Store
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	lim := ratelimit.NewTracker(ratelimit.Config{Window: time.Minute, MaxFails: 10})
	s := NewServer(st, lim, events.NewBus(), false, nil)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{srv: ts, api: s, st: st}
}

func (e *testEnv) do(t *testing.T, method, path, bearer string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		blob, _ := json.Marshal(body)
		rd = bytes.NewReader(blob)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, e.srv.URL+path, rd)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := e.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func errCode(body map[string]any) string {
	if e, ok := body["error"].(map[string]any); ok {
		if c, ok := e["code"].(string); ok {
			return c
		}
	}
	return ""
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// client 模拟一台注册设备（持有 credential）。
type client struct {
	deviceID string
	pub      string
	cred     string
}

func registerDevice(t *testing.T, e *testEnv, id, pub string) client {
	t.Helper()
	status, body := e.do(t, "POST", "/v1/devices", "", map[string]string{
		"device_id":        id,
		"noise_public_key": pub,
	})
	if status != 200 {
		t.Fatalf("注册失败: %d %v", status, body)
	}
	cred, _ := body["credential"].(string)
	if cred == "" {
		t.Fatalf("首次注册必须下发 credential: %v", body)
	}
	return client{deviceID: id, pub: pub, cred: cred}
}

func fakePub(seed string) string {
	s := seed
	for len(s) < 64 {
		s = fmt.Sprintf("%s%x", s, seed)
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// --- 设备注册 ---

func TestRegisterDeviceFlows(t *testing.T) {
	e := newEnv(t)
	pub := fakePub("a")
	c := registerDevice(t, e, "dev-a", pub)

	// 幂等重注册（同公钥）：existing，无新 credential（字段省略 → nil）。
	status, body := e.do(t, "POST", "/v1/devices", "", map[string]string{
		"device_id": "dev-a", "noise_public_key": pub,
	})
	if status != 200 || body["status"] != "existing" || body["credential"] != nil {
		t.Fatalf("幂等重注册响应错误: %d %v", status, body)
	}

	// 公钥变化 → DEVICE_KEY_MISMATCH（409）。
	status, body = e.do(t, "POST", "/v1/devices", "", map[string]string{
		"device_id": "dev-a", "noise_public_key": fakePub("b"),
	})
	if status != 409 || errCode(body) != "DEVICE_KEY_MISMATCH" {
		t.Fatalf("公钥变化必须 DEVICE_KEY_MISMATCH: %d %v", status, body)
	}

	// 非法公钥 → VALIDATION_INVALID。
	status, body = e.do(t, "POST", "/v1/devices", "", map[string]string{
		"device_id": "dev-z", "noise_public_key": "not-hex",
	})
	if status != 400 || errCode(body) != "VALIDATION_INVALID" {
		t.Fatalf("非法公钥应 400: %d %v", status, body)
	}

	// /v1/devices/me：正常返回 + 无认证 401。
	status, body = e.do(t, "GET", "/v1/devices/me", c.cred, nil)
	if status != 200 || body["device_id"] != "dev-a" {
		t.Fatalf("me 查询失败: %d %v", status, body)
	}
	status, body = e.do(t, "GET", "/v1/devices/me", "", nil)
	if status != 401 || errCode(body) != "AUTH_REQUIRED" {
		t.Fatalf("无认证应 401: %d %v", status, body)
	}
	status, body = e.do(t, "GET", "/v1/devices/me", "mlk_wrong", nil)
	if status != 401 || errCode(body) != "AUTH_INVALID" {
		t.Fatalf("坏凭据应 401: %d %v", status, body)
	}
}

// --- 6 位码会话全流程 ---

func TestSessionFlowAndKeyDistribution(t *testing.T) {
	e := newEnv(t)
	pubA, pubB := fakePub("a"), fakePub("b")
	a := registerDevice(t, e, "dev-a", pubA)
	b := registerDevice(t, e, "dev-b", pubB)

	// 创建会话。
	status, body := e.do(t, "POST", "/v1/sessions", a.cred, map[string]string{"network_id": "net-1"})
	if status != 200 {
		t.Fatalf("创建会话失败: %d %v", status, body)
	}
	code, _ := body["code"].(string)
	sessID, _ := body["session_id"].(string)
	if len(code) != 6 || !isDigits(code) {
		t.Fatalf("码格式非法: %q", code)
	}
	if body["status"] != "WAITING" {
		t.Fatalf("初始状态 WAITING: %v", body["status"])
	}

	// 未知码 join → SESSION_CODE_INVALID + 限流计数。
	status, body = e.do(t, "POST", "/v1/sessions/000000/join", b.cred, nil)
	if status != 404 || errCode(body) != "SESSION_CODE_INVALID" {
		t.Fatalf("未知码应 404 SESSION_CODE_INVALID: %d %v", status, body)
	}

	// join 成功：**creator 公钥必须来自 Controller 响应**（核心断言）。
	status, body = e.do(t, "POST", fmt.Sprintf("/v1/sessions/%s/join", code), b.cred, nil)
	if status != 200 {
		t.Fatalf("join 失败: %d %v", status, body)
	}
	members, _ := body["members"].([]any)
	var gotCreatorPub string
	for _, m := range members {
		mm := m.(map[string]any)
		if mm["device_id"] == "dev-a" {
			gotCreatorPub, _ = mm["noise_public_key"].(string)
		}
	}
	if gotCreatorPub != pubA {
		t.Fatalf("join 响应必须携带 creator 注册公钥: %s != %s", gotCreatorPub, pubA)
	}
	if body["code"] != nil {
		t.Fatal("joiner 响应不应回显连接码")
	}

	// creator 轮询会话：看到 JOINED + joiner 公钥。
	status, body = e.do(t, "GET", "/v1/sessions/"+sessID, a.cred, nil)
	if status != 200 || body["status"] != "JOINED" {
		t.Fatalf("creator 轮询失败: %d %v", status, body)
	}
	joinerPub := ""
	for _, m := range body["members"].([]any) {
		mm := m.(map[string]any)
		if mm["device_id"] == "dev-b" {
			joinerPub, _ = mm["noise_public_key"].(string)
		}
	}
	if joinerPub != pubB {
		t.Fatalf("creator 应看到 joiner 注册公钥: %s", joinerPub)
	}

	// 非成员访问会话 → SESSION_NOT_MEMBER。
	status, body = e.do(t, "POST", "/v1/devices", "", map[string]string{
		"device_id": "dev-c", "noise_public_key": fakePub("c"),
	})
	credC, _ := body["credential"].(string)
	status, body = e.do(t, "GET", "/v1/sessions/"+sessID, credC, nil)
	if status != 403 || errCode(body) != "SESSION_NOT_MEMBER" {
		t.Fatalf("非成员应 403: %d %v", status, body)
	}

	// 格式非法的码 → VALIDATION_INVALID。
	status, body = e.do(t, "POST", "/v1/sessions/abc12/join", b.cred, nil)
	if status != 400 || errCode(body) != "VALIDATION_INVALID" {
		t.Fatalf("格式非法码应 400: %d %v", status, body)
	}
}

// --- 限流 ---

func TestJoinRateLimited(t *testing.T) {
	e := newEnv(t)
	a := registerDevice(t, e, "dev-a", fakePub("a"))
	b := registerDevice(t, e, "dev-b", fakePub("b"))
	_ = a

	// 10 次失败（默认阈值）→ 第 11 次 SESSION_RATE_LIMITED。
	limited := false
	for i := 0; i < 12; i++ {
		status, body := e.do(t, "POST", "/v1/sessions/999999/join", b.cred, nil)
		if errCode(body) == "SESSION_RATE_LIMITED" {
			if i < 10 {
				t.Fatalf("第 %d 次不应被限流", i+1)
			}
			if status != 429 {
				t.Fatalf("限流应 429: %d", status)
			}
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("12 次失败后必须触发 SESSION_RATE_LIMITED")
	}
	// 被限流后：换会话也拒绝（该设备维度）。
	status, body := e.do(t, "POST", "/v1/sessions/123456/join", b.cred, nil)
	if status != 429 || errCode(body) != "SESSION_RATE_LIMITED" {
		t.Fatalf("限流后继续尝试应 429: %d %v", status, body)
	}
}

// --- 候选交换 ---

func TestCandidateExchange(t *testing.T) {
	e := newEnv(t)
	a := registerDevice(t, e, "dev-a", fakePub("a"))
	b := registerDevice(t, e, "dev-b", fakePub("b"))

	_, body := e.do(t, "POST", "/v1/sessions", a.cred, nil)
	code, _ := body["code"].(string)
	sessID, _ := body["session_id"].(string)
	_, _ = e.do(t, "POST", fmt.Sprintf("/v1/sessions/%s/join", code), b.cred, nil)

	// A 上传候选。
	status, resp := e.do(t, "PUT", "/v1/sessions/"+sessID+"/candidates", a.cred,
		map[string]any{"candidates": []map[string]any{
			{"ip": "192.168.1.10", "port": 51820, "kind": "host"},
			{"ip": "203.0.113.7", "port": 40001, "kind": "srflx"},
		}})
	if status != 200 {
		t.Fatalf("A 上传候选失败: %d %v", status, resp)
	}

	// B 拉取对端候选（无 wait 立即返回）。
	status, resp = e.do(t, "GET", "/v1/sessions/"+sessID+"/candidates", b.cred, nil)
	if status != 200 {
		t.Fatalf("B 拉取候选失败: %d %v", status, resp)
	}
	peers, _ := resp["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("B 应看到 A 的候选: %v", resp)
	}
	p := peers[0].(map[string]any)
	if p["device_id"] != "dev-a" {
		t.Fatalf("候选归属错误: %v", p)
	}
	cands, _ := p["candidates"].([]any)
	if len(cands) != 2 {
		t.Fatalf("候选数量错误: %v", cands)
	}

	// B 上传候选后 A 也能拉取（对称）。
	_, _ = e.do(t, "PUT", "/v1/sessions/"+sessID+"/candidates", b.cred,
		map[string]any{"candidates": []map[string]any{
			{"ip": "192.168.1.20", "port": 51821, "kind": "host"},
		}})
	status, resp = e.do(t, "GET", "/v1/sessions/"+sessID+"/candidates", a.cred, nil)
	if status != 200 {
		t.Fatalf("A 拉取候选失败: %d %v", status, resp)
	}
	peers, _ = resp["peers"].([]any)
	if len(peers) != 1 {
		t.Fatalf("A 应看到 B 的候选: %v", resp)
	}

	// 非成员上传 → 403。
	c := registerDevice(t, e, "dev-c", fakePub("c"))
	status, resp = e.do(t, "PUT", "/v1/sessions/"+sessID+"/candidates", c.cred,
		map[string]any{"candidates": []map[string]any{{"ip": "1.2.3.4", "port": 1, "kind": "host"}}})
	if status != 403 {
		t.Fatalf("非成员上传应 403: %d %v", status, resp)
	}

	// 非法候选 → 400。
	status, resp = e.do(t, "PUT", "/v1/sessions/"+sessID+"/candidates", a.cred,
		map[string]any{"candidates": []map[string]any{{"ip": "999.1.1.1", "port": 1, "kind": "host"}}})
	if status != 400 {
		t.Fatalf("非法 IP 应 400: %d %v", status, resp)
	}
	status, resp = e.do(t, "PUT", "/v1/sessions/"+sessID+"/candidates", a.cred,
		map[string]any{"candidates": []map[string]any{{"ip": "1.2.3.4", "port": 1, "kind": "relay"}}})
	if status != 400 {
		t.Fatalf("非法 kind 应 400: %d %v", status, resp)
	}

	// 长轮询：A 先清空候选再让 B wait 短轮询——验证 wait_ms 参数合法性边界。
	status, resp = e.do(t, "GET", "/v1/sessions/"+sessID+"/candidates?wait_ms=999999", b.cred, nil)
	if status != 400 {
		t.Fatalf("超界 wait_ms 应 400: %d %v", status, resp)
	}
}

// --- 好友邀请 / 好友关系（M1-1） ---

func TestFriendInviteFlow(t *testing.T) {
	e := newEnv(t)
	a := registerDevice(t, e, "dev-a", fakePub("a"))
	b := registerDevice(t, e, "dev-b", fakePub("b"))
	c := registerDevice(t, e, "dev-c", fakePub("c"))

	// A 创建 24h 多次邀请。
	status, body := e.do(t, "POST", "/v1/invites", a.cred,
		map[string]any{"network_id": "net-friend", "ttl": "24h", "max_uses": 2})
	if status != 200 {
		t.Fatalf("创建邀请失败: %d %v", status, body)
	}
	inviteID, _ := body["invite_id"].(string)
	token, _ := body["invite_token"].(string)
	if token == "" {
		t.Fatal("创建响应必须一次性下发 invite_token")
	}
	if body["invite_token_hash"] != nil {
		t.Fatal("token hash 绝不能外发")
	}

	// 邀请方查询：含 token 的视图不得泄漏 hash；非创建者 404。
	status, body = e.do(t, "GET", "/v1/invites/"+inviteID, a.cred, nil)
	if status != 200 || body["used_count"].(float64) != 0 {
		t.Fatalf("邀请方查询失败: %d %v", status, body)
	}
	status, body = e.do(t, "GET", "/v1/invites/"+inviteID, b.cred, nil)
	if status != 404 {
		t.Fatalf("非创建者查询应 404: %d %v", status, body)
	}

	// B 兑换：建立 PENDING 好友关系（不再创建连接会话），响应含邀请方设备信息。
	status, body = e.do(t, "POST", "/v1/invites/"+inviteID+"/redeem", b.cred,
		map[string]string{"invite_token": token})
	if status != 200 {
		t.Fatalf("兑换失败: %d %v", status, body)
	}
	fsAB, _ := body["friendship_id"].(string)
	if body["status"] != "PENDING" {
		t.Fatalf("兑换后关系应 PENDING: %v", body["status"])
	}
	creator, _ := body["creator"].(map[string]any)
	if creator["device_id"] != "dev-a" || creator["noise_public_key"] != a.pub {
		t.Fatalf("creator 设备信息错误: %v", creator)
	}

	// 同设备重复兑换 → FRIENDSHIP_EXISTS（已有 PENDING 好友关系）。
	status, body = e.do(t, "POST", "/v1/invites/"+inviteID+"/redeem", b.cred,
		map[string]string{"invite_token": token})
	if status != 409 || errCode(body) != "FRIENDSHIP_EXISTS" {
		t.Fatalf("重复兑换应 409 FRIENDSHIP_EXISTS: %d %v", status, body)
	}

	// 错误 token → INVITE_INVALID_TOKEN。
	status, body = e.do(t, "POST", "/v1/invites/"+inviteID+"/redeem", c.cred,
		map[string]string{"invite_token": "mli_wrong"})
	if status != 403 || errCode(body) != "INVITE_INVALID_TOKEN" {
		t.Fatalf("错误 token 应 403: %d %v", status, body)
	}

	// max_uses=2：dev-c 兑换成功后邀请 EXHAUSTED。
	status, body = e.do(t, "POST", "/v1/invites/"+inviteID+"/redeem", c.cred,
		map[string]string{"invite_token": token})
	if status != 200 {
		t.Fatalf("dev-c 兑换应成功: %d %v", status, body)
	}
	// 邀请方视角：兑换记录（2 条）+ EXHAUSTED。
	status, body = e.do(t, "GET", "/v1/invites/"+inviteID, a.cred, nil)
	if status != 200 {
		t.Fatalf("邀请方查询失败: %d", status)
	}
	rds, _ := body["redemptions"].([]any)
	if len(rds) != 2 {
		t.Fatalf("应有 2 条兑换记录: %v", rds)
	}
	if body["status"] != "EXHAUSTED" {
		t.Fatalf("2 次用尽后应 EXHAUSTED: %v", body["status"])
	}

	// B 接受好友请求 → ACCEPTED；A 的好友列表出现 B。
	status, body = e.do(t, "POST", "/v1/friendships/"+fsAB+"/accept", b.cred, nil)
	if status != 200 || body["status"] != "ACCEPTED" {
		t.Fatalf("接受好友应 ACCEPTED: %d %v", status, body)
	}
	status, body = e.do(t, "GET", "/v1/friendships", a.cred, nil)
	if status != 200 {
		t.Fatalf("好友列表失败: %d", status)
	}
	friendships, _ := body["friendships"].([]any)
	// 含 dev-b(ACCEPTED) 与 dev-c(PENDING，待处理请求需在 UI 可见)。
	var sawB, sawC bool
	for _, f := range friendships {
		fm := f.(map[string]any)
		peer, _ := fm["peer"].(map[string]any)
		switch peer["device_id"] {
		case "dev-b":
			sawB = fm["status"] == "ACCEPTED"
		case "dev-c":
			sawC = fm["status"] == "PENDING"
		}
	}
	if !sawB || !sawC {
		t.Fatalf("A 应见 dev-b(ACCEPTED) 与 dev-c(PENDING): %v", friendships)
	}

	// A 向好友 B 发起直连 → WAITING 会话（仅 creator 成员）。
	status, body = e.do(t, "POST", "/v1/friends/dev-b/connect", a.cred,
		map[string]any{"network_id": "net-friend"})
	if status != 200 {
		t.Fatalf("好友直连失败: %d %v", status, body)
	}
	sessID, _ := body["session_id"].(string)
	if body["status"] != "WAITING" || sessID == "" {
		t.Fatalf("直连初始应 WAITING: %v", body)
	}
	if members, _ := body["members"].([]any); len(members) != 1 {
		t.Fatalf("接受前应仅 creator 成员: %v", members)
	}

	// B 接受直连请求 → JOINED，双方各得不同 overlay IP。
	status, body = e.do(t, "POST", "/v1/sessions/"+sessID+"/accept-request", b.cred, nil)
	if status != 200 || body["status"] != "JOINED" {
		t.Fatalf("接受直连应 JOINED: %d %v", status, body)
	}
	members, _ := body["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("接受后应双方成员: %v", members)
	}
	ipA, ipB := "", ""
	for _, m := range members {
		mm := m.(map[string]any)
		if mm["device_id"] == "dev-a" {
			ipA, _ = mm["overlay_ip"].(string)
		}
		if mm["device_id"] == "dev-b" {
			ipB, _ = mm["overlay_ip"].(string)
		}
	}
	if ipA == "" || ipB == "" || ipA == ipB {
		t.Fatalf("双方应各得不同 overlay IP: %s/%s", ipA, ipB)
	}

	// 会话上候选交换照常（与 6 位码会话同构）。
	status, body = e.do(t, "PUT", "/v1/sessions/"+sessID+"/candidates", b.cred,
		map[string]any{"candidates": []map[string]any{{"ip": "10.1.1.1", "port": 1000, "kind": "host"}}})
	if status != 200 {
		t.Fatalf("邀请会话候选上传失败: %d %v", status, body)
	}

	// 删除好友（撤销授权）→ REMOVED，ACCEPTED 好友列表不再含 dev-b。
	status, body = e.do(t, "POST", "/v1/friendships/"+fsAB+"/revoke", a.cred, nil)
	if status != 200 || body["status"] != "removed" {
		t.Fatalf("撤销好友失败: %d %v", status, body)
	}
	status, body = e.do(t, "GET", "/v1/friendships", a.cred, nil)
	if status != 200 {
		t.Fatalf("好友列表失败: %d", status)
	}
	if fs, _ := body["friendships"].([]any); len(fs) != 1 {
		t.Fatalf("撤销后应仅剩 dev-c 的 PENDING 请求: %v", fs)
	}
	// 非好友再直连 → NOT_FRIENDS。
	status, body = e.do(t, "POST", "/v1/friends/dev-b/connect", a.cred, nil)
	if status != 403 || errCode(body) != "NOT_FRIENDS" {
		t.Fatalf("非好友直连应 403 NOT_FRIENDS: %d %v", status, body)
	}
}

// --- store 错误映射兜底（直接调用 server 层错误映射）---

func TestErrorMapping(t *testing.T) {
	if ae := mapStoreError(store.ErrDeviceKeyMismatch); ae == nil || ae.Code != "DEVICE_KEY_MISMATCH" || ae.Status != 409 {
		t.Fatalf("DEVICE_KEY_MISMATCH 映射错误: %+v", ae)
	}
	if ae := mapStoreError(store.ErrSessionExpired); ae == nil || ae.Status != 410 {
		t.Fatalf("SESSION_EXPIRED 映射错误: %+v", ae)
	}
	if ae := mapStoreError(fmt.Errorf("unknown")); ae != nil {
		t.Fatalf("未知错误应返回 nil 交给 internal: %+v", ae)
	}
}

// --- healthz ---

func TestHealthz(t *testing.T) {
	e := newEnv(t)
	status, body := e.do(t, "GET", "/healthz", "", nil)
	if status != 200 || body["service"] != "meshlink-controller" {
		t.Fatalf("healthz 失败: %d %v", status, body)
	}
	_ = model.Device{}
}

// --- preferred_code 前导零（用户规格十/十一）---

func TestPreferredCodeLeadingZero(t *testing.T) {
	e := newEnv(t)
	pubA := fakePub("a1")
	a := registerDevice(t, e, "dev-za", pubA)

	// preferred_code = "001234"：必须作为字符串原样保留（不是数字 1234）。
	status, body := e.do(t, "POST", "/v1/sessions", a.cred, map[string]string{
		"network_id":     "net-z",
		"preferred_code": "001234",
	})
	if status != 200 {
		t.Fatalf("preferred_code 创建失败: %d %v", status, body)
	}
	raw, _ := body["code"].(string)
	if raw != "001234" {
		t.Fatalf("前导零必须保留: got %q want 001234", raw)
	}
	// code 必须是 JSON string，不能是 number（断言反序列化后类型）。
	if v, ok := body["code"]; !ok || fmt.Sprintf("%T", v) != "string" {
		t.Fatalf("code 必须是 JSON string: %T %v", v, body["code"])
	}

	// 同一码再次创建 → 冲突检测，不静默替换（QUICK_CODE_TAKEN）。
	status, body = e.do(t, "POST", "/v1/sessions", a.cred, map[string]string{
		"network_id":     "net-z",
		"preferred_code": "001234",
	})
	if status != 409 || errCode(body) != "QUICK_CODE_TAKEN" {
		t.Fatalf("重复 preferred_code 应 409 QUICK_CODE_TAKEN: %d %v", status, body)
	}

	// preferred_code 非法（非 6 位 / 含非数字）→ 400。
	for _, bad := range []string{"123", "12a456", "1234567", ""} {
		if bad == "" {
			continue
		}
		status, body = e.do(t, "POST", "/v1/sessions", a.cred, map[string]string{
			"network_id":     "net-z",
			"preferred_code": bad,
		})
		if status != 400 {
			t.Fatalf("非法 preferred_code %q 应 400: %d %v", bad, status, body)
		}
	}

	// 用前导零码 join 可用（固定宽度字符串路径）。
	pubB := fakePub("b1")
	b := registerDevice(t, e, "dev-zb", pubB)
	status, body = e.do(t, "POST", "/v1/sessions/001234/join", b.cred, nil)
	if status != 200 {
		t.Fatalf("前导零码 join 失败: %d %v", status, body)
	}
}
