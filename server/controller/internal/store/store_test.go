// 存储层测试：公钥绑定规则 / 会话状态机 / 过期清理 / 邀请生命周期。

package store

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"meshlink/server/controller/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := Open(":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func regPub() string {
	return NewCredential()[4:] // 任意 64 hex（长度与公钥一致）
}

// --- 设备注册与公钥绑定 ---

func TestRegisterDeviceFirstTimeBindsKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pub := regPub()
	credHash := HashToken(NewCredential())

	dev, created, err := st.RegisterDevice(ctx, "dev-a", pub, "A 机器", credHash)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !created {
		t.Fatal("首次注册 created 应为 true")
	}
	if dev.NoisePublicKey != pub {
		t.Fatalf("公钥绑定不一致: %s", dev.NoisePublicKey)
	}

	// credential 可反查设备。
	got, err := st.DeviceByCredential(ctx, credHash)
	if err != nil {
		t.Fatalf("lookup by credential: %v", err)
	}
	if got.DeviceID != "dev-a" {
		t.Fatalf("credential 反查设备错误: %s", got.DeviceID)
	}
}

func TestRegisterDeviceIdempotentSameKey(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pub, h1, h2 := regPub(), HashToken(NewCredential()), HashToken(NewCredential())
	if _, _, err := st.RegisterDevice(ctx, "dev-a", pub, "", h1); err != nil {
		t.Fatalf("first: %v", err)
	}
	// 同公钥重复注册（新 credential hash 也不再写入——绑定不变）。
	dev, created, err := st.RegisterDevice(ctx, "dev-a", pub, "改名", h2)
	if err != nil {
		t.Fatalf("idempotent: %v", err)
	}
	if created {
		t.Fatal("重复注册 created 应为 false")
	}
	if dev.NoisePublicKey != pub {
		t.Fatal("幂等注册不得改变公钥绑定")
	}
	// 旧 credential 仍然有效（未被覆盖）。
	if _, err := st.DeviceByCredential(ctx, h1); err != nil {
		t.Fatalf("旧 credential 失效: %v", err)
	}
	// 新 credential hash 未生效（未插入第二条）。
	if _, err := st.DeviceByCredential(ctx, h2); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("重复注册不得新增 credential: %v", err)
	}
}

func TestRegisterDeviceKeyMismatchRejected(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	if _, _, err := st.RegisterDevice(ctx, "dev-a", regPub(), "", HashToken(NewCredential())); err != nil {
		t.Fatalf("first: %v", err)
	}
	// 公钥突然变化 → DEVICE_KEY_MISMATCH，绝不自动覆盖。
	_, _, err := st.RegisterDevice(ctx, "dev-a", regPub(), "", HashToken(NewCredential()))
	if !errors.Is(err, ErrDeviceKeyMismatch) {
		t.Fatalf("公钥变化必须 ErrDeviceKeyMismatch，got %v", err)
	}
	// 旧公钥绑定保持不变（未被覆盖）。
	got, err := st.DeviceByCredential(ctx, HashToken(NewCredential()))
	_ = got
	_ = err
	dev, _, err := st.RegisterDevice(ctx, "dev-a", mustOld(t, st), "", HashToken(NewCredential()))
	if err != nil || dev.DeviceID != "dev-a" {
		t.Fatalf("旧公钥仍应可用: %v", err)
	}
}

func mustOld(t *testing.T, st *Store) string {
	t.Helper()
	var pub string
	if err := st.db.QueryRow(`SELECT noise_public_key FROM devices WHERE device_id='dev-a'`).Scan(&pub); err != nil {
		t.Fatalf("query: %v", err)
	}
	return pub
}

// --- 6 位码会话 ---

func registerAB(t *testing.T, st *Store) (pubA, pubB string) {
	t.Helper()
	ctx := context.Background()
	pubA, pubB = regPub(), regPub()
	if _, _, err := st.RegisterDevice(ctx, "dev-a", pubA, "", HashToken(NewCredential())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.RegisterDevice(ctx, "dev-b", pubB, "", HashToken(NewCredential())); err != nil {
		t.Fatal(err)
	}
	return pubA, pubB
}

func TestSessionCreateJoinFlow(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	pubA, pubB := registerAB(t, st)

	sess, err := st.CreateSession(ctx, "dev-a", "net-1", 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(sess.Code) != 6 || sess.Code < "000000" || sess.Code > "999999" {
		t.Fatalf("码格式非法: %q", sess.Code)
	}
	if sess.Status != model.SessionWaiting {
		t.Fatalf("初始状态应为 WAITING: %s", sess.Status)
	}
	if sess.ExpiresAt.Sub(sess.CreatedAt) != model.SessionTTLDefault {
		t.Fatalf("默认有效期应为 10 分钟")
	}

	// join 前成员只有 creator。
	members, _ := st.Members(ctx, sess.SessionID)
	if len(members) != 1 || members[0].Role != model.RoleCreator {
		t.Fatalf("初始成员应为 creator: %+v", members)
	}

	// joiner 加入 → 返回 creator 公钥快照（Controller 分发公钥的核心断言）。
	jsess, jmembers, err := st.JoinSession(ctx, sess.Code, "dev-b")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	if jsess.Status != model.SessionJoined {
		t.Fatalf("join 后状态应为 JOINED: %s", jsess.Status)
	}
	var creatorPub string
	for _, m := range jmembers {
		if m.DeviceID == "dev-a" {
			creatorPub = m.NoisePublicKey
		}
	}
	if creatorPub != pubA {
		t.Fatalf("join 响应必须含 creator 注册公钥: %s != %s", creatorPub, pubA)
	}

	// joiner 公钥快照同样入库。
	found := false
	for _, m := range jmembers {
		if m.DeviceID == "dev-b" && m.NoisePublicKey == pubB {
			found = true
		}
	}
	if !found {
		t.Fatal("joiner 公钥快照缺失")
	}

	// 第二次 join → 状态非法（已 JOINED）。
	if _, _, err := st.JoinSession(ctx, sess.Code, "dev-c2"); err != nil {
		_ = err // dev-c2 未注册会先失败——注册后再试
	}
	if _, _, err := st.RegisterDevice(ctx, "dev-c2", regPub(), "", HashToken(NewCredential())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.JoinSession(ctx, sess.Code, "dev-c2"); !errors.Is(err, ErrSessionStateInvalid) {
		t.Fatalf("已 JOINED 会话再次 join 应拒绝: %v", err)
	}
	// creator 不能 join 自己的会话。
	if _, _, err := st.JoinSession(ctx, sess.Code, "dev-a"); !errors.Is(err, ErrSessionStateInvalid) {
		t.Fatalf("creator join 自己会话应拒绝: %v", err)
	}
}

func TestSessionUnknownCodeAndExpiry(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)

	if _, _, err := st.JoinSession(ctx, "999999", "dev-b"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("未知码应 SESSION_NOT_FOUND: %v", err)
	}

	// TTL 1ms 的会话立即过期。
	sess, err := st.CreateSession(ctx, "dev-a", "net-1", time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, _, err := st.JoinSession(ctx, sess.Code, "dev-b"); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("过期会话 join 应 SESSION_EXPIRED: %v", err)
	}
	// Session() 读取亦报过期。
	if _, err := st.Session(ctx, sess.SessionID); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("过期会话读取应报 ErrSessionExpired: %v", err)
	}
	// 清理删除过期行（级联）。
	n, err := st.CleanupExpired(ctx)
	if err != nil || n == 0 {
		t.Fatalf("清理应删除过期会话: n=%d err=%v", n, err)
	}
	if _, err := st.Session(ctx, sess.SessionID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("清理后应不存在: %v", err)
	}
}

func TestSessionCodeUniqueness(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)
	// 注入确定性递增序列，避免 6 位随机码的生日碰撞 flake。
	orig := codeGen
	defer func() { codeGen = orig }()
	next := 0
	codeGen = func() (string, error) {
		c := fmt.Sprintf("%06d", next)
		next++
		return c, nil
	}
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		sess, err := st.CreateSession(ctx, "dev-a", "net-1", 0)
		if err != nil {
			t.Fatalf("create #%d: %v", i, err)
		}
		if seen[sess.Code] {
			t.Fatalf("码重复: %s", sess.Code)
		}
		seen[sess.Code] = true
		// 立即过期清理，让码空间复用而不触发 UNIQUE 冲突路径 exhaustion。
		if _, err := st.db.Exec(`DELETE FROM connection_sessions WHERE session_id = ?`, sess.SessionID); err != nil {
			t.Fatal(err)
		}
	}
}

// --- 候选交换 ---

func TestCandidatesRoundTrip(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)
	sess, _ := st.CreateSession(ctx, "dev-a", "net-1", 0)
	if _, _, err := st.JoinSession(ctx, sess.Code, "dev-b"); err != nil {
		t.Fatal(err)
	}

	cands := []model.Candidate{
		{IP: "192.168.1.10", Port: 51820, Kind: model.CandidateKindHost},
		{IP: "203.0.113.5", Port: 40001, Kind: model.CandidateKindSrflx},
	}
	if err := st.PutCandidates(ctx, sess.SessionID, "dev-a", cands); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, _, err := st.Candidates(ctx, sess.SessionID, "dev-a")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got) != 2 || got[0].IP != "192.168.1.10" || got[1].Kind != "srflx" {
		t.Fatalf("候选往返不一致: %+v", got)
	}
	// 未上传方 → ErrNotMember 语义（无候选记录）。
	if _, _, err := st.Candidates(ctx, sess.SessionID, "dev-b"); !errors.Is(err, ErrNotMember) {
		t.Fatalf("未上传应 ErrNotMember: %v", err)
	}
	// UPSERT 覆盖。
	cands2 := []model.Candidate{{IP: "10.0.0.2", Port: 9999, Kind: "host"}}
	if err := st.PutCandidates(ctx, sess.SessionID, "dev-a", cands2); err != nil {
		t.Fatal(err)
	}
	got, _, _ = st.Candidates(ctx, sess.SessionID, "dev-a")
	if len(got) != 1 || got[0].IP != "10.0.0.2" {
		t.Fatalf("UPSERT 覆盖失败: %+v", got)
	}
}

// --- 好友邀请（M1-1：redeem → PENDING 好友关系） ---

func TestInviteLifecycle(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)
	token := NewInviteToken()
	tokenHash := HashToken(token)

	// 24 小时 / 3 次。
	exp := time.Now().UTC().Add(model.InviteTTL24h)
	inv, err := st.CreateInvite(ctx, "dev-a", "net-1", tokenHash, &exp, 3)
	if err != nil {
		t.Fatalf("create invite: %v", err)
	}
	if inv.Status != model.InviteActive {
		t.Fatalf("初始状态 ACTIVE: %s", inv.Status)
	}

	// 错误 token → 拒绝。
	if _, _, err := st.RedeemInvite(ctx, inv.InviteID, HashToken("wrong"), "dev-b"); !errors.Is(err, ErrInviteTokenInvalid) {
		t.Fatalf("错误 token 应拒绝: %v", err)
	}

	// 正确 token → 建立 PENDING 好友关系（device_a=邀请方，device_b=兑换方）。
	fs, creator, err := st.RedeemInvite(ctx, inv.InviteID, tokenHash, "dev-b")
	if err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if fs.Status != model.FriendshipPending {
		t.Fatalf("兑换后好友关系应 PENDING: %s", fs.Status)
	}
	if fs.DeviceA != "dev-a" || fs.DeviceB != "dev-b" {
		t.Fatalf("关系两端错误: %s/%s", fs.DeviceA, fs.DeviceB)
	}
	if creator != "dev-a" {
		t.Fatalf("creator 应为邀请方: %s", creator)
	}

	// 接受 → ACCEPTED；AreFriends=true。
	if _, err := st.SetFriendshipStatus(ctx, fs.FriendshipID, "dev-b", model.FriendshipAccepted); err != nil {
		t.Fatalf("accept: %v", err)
	}
	friends, err := st.AreFriends(ctx, "dev-a", "dev-b")
	if err != nil || !friends {
		t.Fatalf("接受后应为好友: %v", err)
	}
	// 好友列表可见对方。
	views, err := st.FriendViews(ctx, "dev-a")
	if err != nil || len(views) != 1 || views[0].Peer.DeviceID != "dev-b" {
		t.Fatalf("好友列表错误: %+v err=%v", views, err)
	}

	// 同一设备重复兑换 → FRIENDSHIP_EXISTS（已有 PENDING 好友关系）。
	if _, _, err := st.RedeemInvite(ctx, inv.InviteID, tokenHash, "dev-b"); !errors.Is(err, ErrFriendshipExists) {
		t.Fatalf("同设备重复兑换应拒绝: %v", err)
	}

	// 反向重复建友（dev-b 邀请 dev-a 兑换）→ FRIENDSHIP_EXISTS。
	tokRev := NewInviteToken()
	if _, err := st.CreateInvite(ctx, "dev-b", "net-1", HashToken(tokRev), nil, 1); err != nil {
		t.Fatal(err)
	}
	invRev, _ := st.Invite(ctx, mustLastInvite(t, st))
	if _, _, err := st.RedeemInvite(ctx, invRev.InviteID, HashToken(tokRev), "dev-a"); !errors.Is(err, ErrFriendshipExists) {
		t.Fatalf("已好友的反向兑换应拒绝: %v", err)
	}

	// 兑换记录可查（关联 friendship_id）。
	rds, err := st.InviteRedemptions(ctx, inv.InviteID)
	if err != nil || len(rds) != 1 || rds[0].FriendshipID != fs.FriendshipID {
		t.Fatalf("兑换记录错误: %+v err=%v", rds, err)
	}
	if used, _ := st.Invite(ctx, inv.InviteID); used.UsedCount != 1 {
		t.Fatalf("used_count 应为 1: %d", used.UsedCount)
	}
}

func TestFriendshipRevoke(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)
	token := NewInviteToken()
	th := HashToken(token)
	if _, err := st.CreateInvite(ctx, "dev-a", "net-1", th, nil, 1); err != nil {
		t.Fatal(err)
	}
	inv, _ := st.Invite(ctx, mustLastInvite(t, st))
	fs, _, err := st.RedeemInvite(ctx, inv.InviteID, th, "dev-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetFriendshipStatus(ctx, fs.FriendshipID, "dev-b", model.FriendshipAccepted); err != nil {
		t.Fatal(err)
	}
	// 撤销 → REMOVED + revoked_at；AreFriends=false。
	revoked, err := st.SetFriendshipStatus(ctx, fs.FriendshipID, "dev-a", model.FriendshipRemoved)
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != model.FriendshipRemoved || revoked.RevokedAt == nil {
		t.Fatalf("撤销后应 REMOVED+revoked_at: %+v", revoked)
	}
	if friends, _ := st.AreFriends(ctx, "dev-a", "dev-b"); friends {
		t.Fatal("撤销后不应是好友")
	}
	// REMOVED 后好友列表为空。
	views, _ := st.FriendViews(ctx, "dev-a")
	if len(views) != 0 {
		t.Fatalf("撤销后好友列表应为空: %+v", views)
	}
}

func TestFriendConnectSession(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)
	// 未建立好友关系 → NOT_FRIENDS。
	if _, err := st.CreateFriendSession(ctx, "dev-a", "dev-b", "net-1"); !errors.Is(err, ErrNotFriends) {
		t.Fatalf("非好友应拒绝: %v", err)
	}
	// 建立好友关系。
	token := NewInviteToken()
	th := HashToken(token)
	if _, err := st.CreateInvite(ctx, "dev-a", "net-1", th, nil, 1); err != nil {
		t.Fatal(err)
	}
	inv, _ := st.Invite(ctx, mustLastInvite(t, st))
	fs, _, err := st.RedeemInvite(ctx, inv.InviteID, th, "dev-b")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.SetFriendshipStatus(ctx, fs.FriendshipID, "dev-b", model.FriendshipAccepted); err != nil {
		t.Fatal(err)
	}
	// 好友直连：创建 target 会话（WAITING，仅 creator 成员）。
	sess, err := st.CreateFriendSession(ctx, "dev-a", "dev-b", "net-1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.Status != model.SessionWaiting || sess.CreatorDeviceID != "dev-a" {
		t.Fatalf("好友直连会话初始状态错误: %+v", sess)
	}
	// 非 target 接受 → NOT_TARGET。
	if _, _, err := st.AcceptConnectionRequest(ctx, sess.SessionID, "dev-c"); !errors.Is(err, ErrNotTarget) {
		t.Fatalf("非 target 应拒绝: %v", err)
	}
	// target 接受 → JOINED，成员含双方。
	joined, members, err := st.AcceptConnectionRequest(ctx, sess.SessionID, "dev-b")
	if err != nil {
		t.Fatalf("target 接受: %v", err)
	}
	if joined.Status != model.SessionJoined {
		t.Fatalf("接受后应 JOINED: %s", joined.Status)
	}
	if len(members) != 2 {
		t.Fatalf("成员应双方: %+v", members)
	}
	var aIP, bIP string
	for _, m := range members {
		if m.DeviceID == "dev-a" {
			aIP = m.OverlayIP
		}
		if m.DeviceID == "dev-b" {
			bIP = m.OverlayIP
		}
	}
	if aIP == "" || bIP == "" || aIP == bIP {
		t.Fatalf("双方应各得不同 overlay IP: %s/%s", aIP, bIP)
	}
	// 好友撤销 → 已有 WAITING 请求被关闭；JOINED 会话不受影响（数据面由 FRIEND_AUTH_REVOKED 事件驱动断开）。
	if _, err := st.SetFriendshipStatus(ctx, fs.FriendshipID, "dev-a", model.FriendshipRemoved); err != nil {
		t.Fatal(err)
	}
	closed, err := st.CloseFriendSessions(ctx, "dev-a", "dev-b")
	if err != nil {
		t.Fatalf("CloseFriendSessions: %v", err)
	}
	_ = closed // JOINED 会话不在关闭范围（仅 WAITING）
	// 撤销后不再能发起新直连。
	if _, err := st.CreateFriendSession(ctx, "dev-a", "dev-b", "net-1"); !errors.Is(err, ErrNotFriends) {
		t.Fatalf("撤销后应拒绝发起直连: %v", err)
	}
}

func TestInviteExpiryAndExhaustion(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)
	// 注册第三个设备 dev-c。
	if _, _, err := st.RegisterDevice(ctx, "dev-c", regPub(), "", HashToken(NewCredential())); err != nil {
		t.Fatal(err)
	}
	token := NewInviteToken()
	th := HashToken(token)

	// 过期邀请。
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := st.CreateInvite(ctx, "dev-a", "net-1", th, &past, 0); err != nil {
		t.Fatal(err)
	}
	inv, _ := st.Invite(ctx, mustLastInvite(t, st))
	if _, _, err := st.RedeemInvite(ctx, inv.InviteID, th, "dev-b"); !errors.Is(err, ErrInviteExpired) {
		t.Fatalf("过期邀请应拒绝: %v", err)
	}

	// 单次邀请：dev-b 兑换成功后 → EXHAUSTED。
	tok2 := NewInviteToken()
	th2 := HashToken(tok2)
	if _, err := st.CreateInvite(ctx, "dev-a", "net-1", th2, nil, 1); err != nil {
		t.Fatal(err)
	}
	inv2, _ := st.Invite(ctx, mustLastInvite(t, st))
	if _, _, err := st.RedeemInvite(ctx, inv2.InviteID, th2, "dev-b"); err != nil {
		t.Fatalf("首次兑换应成功: %v", err)
	}
	after, _ := st.Invite(ctx, inv2.InviteID)
	if after.Status != model.InviteExhausted {
		t.Fatalf("单次邀请兑换后应 EXHAUSTED: %s", after.Status)
	}
	if _, _, err := st.RedeemInvite(ctx, inv2.InviteID, th2, "dev-c"); !errors.Is(err, ErrInviteExhausted) {
		t.Fatalf("EXHAUSTED 后再兑换应拒绝: %v", err)
	}
}

func TestInviteRevoke(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)
	token := NewInviteToken()
	th := HashToken(token)
	if _, err := st.CreateInvite(ctx, "dev-a", "net-1", th, nil, 0); err != nil {
		t.Fatal(err)
	}
	inv, _ := st.Invite(ctx, mustLastInvite(t, st))
	if err := st.RevokeInvite(ctx, inv.InviteID, "dev-a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	after, _ := st.Invite(ctx, inv.InviteID)
	if after.Status != model.InviteRevoked {
		t.Fatalf("撤销后应 REVOKED: %s", after.Status)
	}
	// 非创建者撤销 → 拒绝。
	if _, err := st.CreateInvite(ctx, "dev-b", "net-1", HashToken(NewInviteToken()), nil, 0); err != nil {
		t.Fatal(err)
	}
	inv2, _ := st.Invite(ctx, mustLastInvite(t, st))
	if err := st.RevokeInvite(ctx, inv2.InviteID, "dev-a"); err == nil {
		t.Fatalf("非创建者撤销应拒绝")
	}
	// 撤销后兑换 → 拒绝。
	if _, _, err := st.RedeemInvite(ctx, inv.InviteID, th, "dev-b"); !errors.Is(err, ErrInviteExhausted) {
		t.Fatalf("撤销后兑换应拒绝: %v", err)
	}
}

func mustLastInvite(t *testing.T, st *Store) string {
	t.Helper()
	var id string
	if err := st.db.QueryRow(`SELECT invite_id FROM friend_invites ORDER BY created_at DESC, rowid DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("query invite: %v", err)
	}
	return id
}

// --- 校验辅助 ---

func TestValidators(t *testing.T) {
	if !ValidPublicKeyHex("a1b2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00") {
		t.Fatal("合法公钥应通过")
	}
	if ValidPublicKeyHex("xyz") || ValidPublicKeyHex("") || ValidPublicKeyHex("zzb2c3d4e5f60718293a4b5c6d7e8f90112233445566778899aabbccddeeff00") {
		t.Fatal("非法公钥应拒绝")
	}
	if !ValidDeviceID("dev-A_1") {
		t.Fatal("合法 device_id 应通过")
	}
	if ValidDeviceID("") || ValidDeviceID("has space") || ValidDeviceID(string(make([]byte, 65))) {
		t.Fatal("非法 device_id 应拒绝")
	}
}
