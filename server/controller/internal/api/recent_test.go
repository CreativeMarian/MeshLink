// M1-1.5：最近连接历史 API 测试。
//
// 覆盖：
// - 6 位码连接成功后 PUT 记录 recent_connection；
// - 对端指纹必须来自 Registry（= 注册时的公钥），未注册对端 → DEVICE_NOT_FOUND；
// - 重复连接累加 connection_count / 刷新 last_connected_at；
// - GET 列表 / DELETE 本地历史；
// - DELETE recent 不影响好友关系（规格十一）。

package api

import (
	"testing"
)

func TestRecentConnections(t *testing.T) {
	e := newEnv(t)
	pubA := fakePub("aa")
	pubB := fakePub("ab")
	a := registerDevice(t, e, "dev-ra", pubA)
	b := registerDevice(t, e, "dev-rb", pubB)

	// 未注册对端 upsert → DEVICE_NOT_FOUND（指纹只来自 Registry，不自信任）。
	status, body := e.do(t, "PUT", "/v1/devices/me/recent-connections/dev-ghost", a.cred,
		map[string]string{"overlay_ip": "10.88.1.2", "path": "directlink"})
	if status != 404 || errCode(body) != "DEVICE_NOT_FOUND" {
		t.Fatalf("未注册对端应 DEVICE_NOT_FOUND: %d %v", status, body)
	}

	// A 记录与 B 的连接：指纹必须 = B 的注册公钥（来自 Registry，非客户端自报）。
	status, body = e.do(t, "PUT", "/v1/devices/me/recent-connections/dev-rb", a.cred,
		map[string]string{"overlay_ip": "10.88.1.2", "path": "directlink"})
	if status != 200 {
		t.Fatalf("upsert recent 失败: %d %v", status, body)
	}
	if fp, _ := body["remote_fingerprint"].(string); fp != pubB {
		t.Fatalf("指纹必须来自 Registry(=B 公钥): %v", body["remote_fingerprint"])
	}
	if body["remote_name"] != "" || body["connection_count"].(float64) != 1 {
		t.Fatalf("首条 recent 字段错误: %v", body)
	}

	// 重复连接 → connection_count 累加 + last_connected_at 刷新。
	status, body = e.do(t, "PUT", "/v1/devices/me/recent-connections/dev-rb", a.cred,
		map[string]string{"overlay_ip": "10.88.1.2", "path": "n2n"})
	if status != 200 || body["connection_count"].(float64) != 2 || body["last_path"] != "n2n" {
		t.Fatalf("重复连接应累加并更新路径: %v", body)
	}

	// B 侧也记录一条（recent 是本地视角，互不影响）。
	status, body = e.do(t, "PUT", "/v1/devices/me/recent-connections/dev-ra", b.cred,
		map[string]string{"overlay_ip": "10.88.1.1", "path": "directlink"})
	if status != 200 {
		t.Fatalf("B 记录失败: %d %v", status, body)
	}

	// A 列表：应 1 条，且指纹正确。
	status, body = e.do(t, "GET", "/v1/devices/me/recent-connections", a.cred, nil)
	if status != 200 {
		t.Fatalf("列表失败: %d %v", status, body)
	}
	list, _ := body["recent_connections"].([]any)
	if len(list) != 1 {
		t.Fatalf("A 应恰有 1 条 recent: %v", list)
	}
	first := list[0].(map[string]any)
	if first["remote_device_id"] != "dev-rb" || first["connection_count"].(float64) != 2 {
		t.Fatalf("列表项字段错误: %v", first)
	}

	// 非法 path → VALIDATION_INVALID。
	status, body = e.do(t, "PUT", "/v1/devices/me/recent-connections/dev-rb", a.cred,
		map[string]string{"path": "weird"})
	if status != 400 || errCode(body) != "VALIDATION_INVALID" {
		t.Fatalf("非法 path 应 400: %d %v", status, body)
	}

	// 未认证 → 401。
	status, body = e.do(t, "GET", "/v1/devices/me/recent-connections", "", nil)
	if status != 401 || errCode(body) != "AUTH_REQUIRED" {
		t.Fatalf("未认证应 401: %d %v", status, body)
	}

	// DELETE：只删本机历史。
	status, body = e.do(t, "DELETE", "/v1/devices/me/recent-connections/dev-rb", a.cred, nil)
	if status != 200 || body["deleted"] != true {
		t.Fatalf("删除失败: %d %v", status, body)
	}
	status, body = e.do(t, "GET", "/v1/devices/me/recent-connections", a.cred, nil)
	list, _ = body["recent_connections"].([]any)
	if status != 200 || len(list) != 0 {
		t.Fatalf("删除后 A 应无 recent: %d %v", status, body)
	}
	// B 侧不受影响（本地历史隔离）。
	status, body = e.do(t, "GET", "/v1/devices/me/recent-connections", b.cred, nil)
	list, _ = body["recent_connections"].([]any)
	if status != 200 || len(list) != 1 {
		t.Fatalf("B 的 recent 不受 A 删除影响: %d %v", status, body)
	}
}

// TestRecentConnectionFriendIndependence：删除 recent 不影响好友关系（规格十一）。
func TestRecentConnectionFriendIndependence(t *testing.T) {
	e := newEnv(t)
	a := registerDevice(t, e, "dev-fa", fakePub("ba"))
	b := registerDevice(t, e, "dev-fb", fakePub("bb"))

	// 建立好友关系（走邀请-兑换-接受）。
	status, body := e.do(t, "POST", "/v1/invites", a.cred,
		map[string]any{"ttl": "permanent", "max_uses": 5})
	if status != 200 {
		t.Fatalf("创建邀请失败: %d %v", status, body)
	}
	inviteID, _ := body["invite_id"].(string)
	token, _ := body["invite_token"].(string)
	status, body = e.do(t, "POST", "/v1/invites/"+inviteID+"/redeem", b.cred,
		map[string]any{"invite_token": token})
	if status != 200 {
		t.Fatalf("兑换邀请失败: %d %v", status, body)
	}
	fsID, _ := body["friendship_id"].(string)
	status, body = e.do(t, "POST", "/v1/friendships/"+fsID+"/accept", b.cred, nil)
	if status != 200 {
		t.Fatalf("接受好友失败: %d %v", status, body)
	}

	// 同时记录 recent。
	status, body = e.do(t, "PUT", "/v1/devices/me/recent-connections/dev-fb", a.cred,
		map[string]string{"overlay_ip": "10.88.1.2", "path": "directlink"})
	if status != 200 {
		t.Fatalf("upsert recent 失败: %d %v", status, body)
	}

	// 删除 recent → 好友关系不受影响（ACCEPTED 仍在）。
	status, _ = e.do(t, "DELETE", "/v1/devices/me/recent-connections/dev-fb", a.cred, nil)
	if status != 200 {
		t.Fatalf("删除 recent 失败: %d", status)
	}
	status, body = e.do(t, "GET", "/v1/friendships", a.cred, nil)
	if status != 200 {
		t.Fatalf("好友列表失败: %d", status)
	}
	fs, _ := body["friendships"].([]any)
	if len(fs) != 1 {
		t.Fatalf("删除 recent 后好友应仍保留: %v", fs)
	}
	fm := fs[0].(map[string]any)
	if fm["status"] != "ACCEPTED" {
		t.Fatalf("好友状态应仍 ACCEPTED: %v", fm)
	}

	// 删除好友 → recent 不受影响（历史记录独立于好友授权）。
	// 先重新记录一条 recent（上一步已删）。
	status, _ = e.do(t, "PUT", "/v1/devices/me/recent-connections/dev-fb", a.cred,
		map[string]string{"path": "n2n"})
	if status != 200 {
		t.Fatalf("重新记录失败: %d", status)
	}
	status, _ = e.do(t, "POST", "/v1/friendships/"+fsID+"/revoke", a.cred, nil)
	if status != 200 {
		t.Fatalf("撤销好友失败: %d", status)
	}
	status, body = e.do(t, "GET", "/v1/devices/me/recent-connections", a.cred, nil)
	list, _ := body["recent_connections"].([]any)
	if status != 200 || len(list) != 1 {
		t.Fatalf("删除好友后 recent 应仍存在: %d %v", status, body)
	}
}
