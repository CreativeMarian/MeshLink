// Overlay IPAM 测试（规格六）：Controller 分配 / 唯一约束 / 冲突检测 / 池回收。

package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"meshlink/server/controller/internal/model"
)

func TestOverlayIpamAllocatesDistinctSubnetsAndMemberIps(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)

	s1, err := st.CreateSession(ctx, "dev-a", "net-1", 0)
	if err != nil {
		t.Fatalf("create s1: %v", err)
	}
	s2, err := st.CreateSession(ctx, "dev-a", "net-1", 0)
	if err != nil {
		t.Fatalf("create s2: %v", err)
	}
	if s1.OverlaySubnet == "" || s2.OverlaySubnet == "" {
		t.Fatalf("会话必须分配 overlay 子网: %q %q", s1.OverlaySubnet, s2.OverlaySubnet)
	}
	if s1.OverlaySubnet == s2.OverlaySubnet {
		t.Fatalf("active 会话间子网必须互斥: %s", s1.OverlaySubnet)
	}
	if !strings.HasSuffix(s1.OverlaySubnet, "/24") {
		t.Fatalf("子网前缀必须 /24: %s", s1.OverlaySubnet)
	}

	// creator 拿 .1（首个主机地址）。
	m1, _ := st.Members(ctx, s1.SessionID)
	if len(m1) != 1 || m1[0].OverlayIP == "" {
		t.Fatalf("creator 成员必须有 overlay IP: %+v", m1)
	}
	if !strings.HasSuffix(m1[0].OverlayIP, ".1") {
		t.Fatalf("creator 应拿子网内第一个主机地址: %s", m1[0].OverlayIP)
	}

	// joiner 拿下一个地址（顺序分配，非硬编码角色位置）。
	_, jm, err := st.JoinSession(ctx, s1.Code, "dev-b")
	if err != nil {
		t.Fatalf("join: %v", err)
	}
	var joinerIP string
	for _, m := range jm {
		if m.DeviceID == "dev-b" {
			joinerIP = m.OverlayIP
		}
	}
	if joinerIP == "" {
		t.Fatal("joiner 必须分到 overlay IP")
	}
	if joinerIP == m1[0].OverlayIP {
		t.Fatalf("会话内 overlay IP 必须唯一: %s", joinerIP)
	}
	if !strings.HasPrefix(joinerIP, strings.TrimSuffix(s1.OverlaySubnet, "/24")[:strings.LastIndex(s1.OverlaySubnet, ".")]) {
		t.Fatalf("joiner IP 必须落在会话子网内: %s ⊄ %s", joinerIP, s1.OverlaySubnet)
	}
}

func TestOverlaySubnetRecycledAfterExpiry(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	registerAB(t, st)

	s1, err := st.CreateSession(ctx, "dev-a", "net-1", 1*time.Millisecond)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	// 同池再建一个占住下一个子网。
	s2, err := st.CreateSession(ctx, "dev-a", "net-1", 0)
	if err != nil {
		t.Fatalf("create2: %v", err)
	}
	if s1.OverlaySubnet == s2.OverlaySubnet {
		t.Fatal("预备条件失败：两个会话子网不应相同")
	}
	time.Sleep(2 * time.Millisecond)
	// 过期会话清理后，其子网可被新会话复用（子网随行删除回收）。
	s3, err := st.CreateSession(ctx, "dev-a", "net-1", 0)
	if err != nil {
		t.Fatalf("create3: %v", err)
	}
	if s3.OverlaySubnet != s1.OverlaySubnet {
		t.Fatalf("过期清理后子网应回收复用: s3=%s s1=%s", s3.OverlaySubnet, s1.OverlaySubnet)
	}
}

func TestOverlayPoolExhaustion(t *testing.T) {
	// 用极小池（/23 → 2 个 /24 子网）验证耗尽检测与错误语义。
	st, err := OpenWithOverlayPool(":memory:", "10.90.0.0/23")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	registerAB(t, st)

	for i := 0; i < 2; i++ {
		if _, err := st.CreateSession(ctx, "dev-a", "net", 0); err != nil {
			t.Fatalf("第 %d 个会话应成功: %v", i+1, err)
		}
	}
	_, err = st.CreateSession(ctx, "dev-a", "net", 0)
	if !errors.Is(err, ErrOverlayPoolExhausted) {
		t.Fatalf("池耗尽应报 ErrOverlayPoolExhausted: %v", err)
	}
}

func TestOverlayPoolValidation(t *testing.T) {
	cases := []string{
		"10.88.0.0",     // 缺前缀
		"10.88.0.0/7",   // 前缀过短
		"10.88.0.0/25",  // 前缀超过每会话 /24
		"10.88.0.1/16",  // 未对齐
		"0.0.0.0/8",     // 禁止 0.0.0.0
		"not-an-ip/16",  // 非法 IP
	}
	for _, c := range cases {
		if _, err := parseOverlayPool(c); !errors.Is(err, ErrOverlayPoolInvalid) {
			t.Errorf("池 %q 应非法: %v", c, err)
		}
	}
	if _, err := parseOverlayPool(model.OverlayPoolDefault); err != nil {
		t.Fatalf("默认池必须合法: %v", err)
	}
	if _, err := parseOverlayPool("172.31.0.0/16"); err != nil {
		t.Fatalf("自定义池必须合法: %v", err)
	}
}

func TestOverlayPoolConfigurable(t *testing.T) {
	st, err := OpenWithOverlayPool(":memory:", "172.31.0.0/24")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	registerAB(t, st)

	s, err := st.CreateSession(ctx, "dev-a", "net", 0)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if s.OverlaySubnet != "172.31.0.0/24" {
		t.Fatalf("应从自定义池分配: %s", s.OverlaySubnet)
	}
}

func TestOverlayColumnMigrationOnLegacyDb(t *testing.T) {
	// 旧 schema（无 overlay 列）打开后自动补列，不报错。
	dir := t.TempDir()
	dbPath := dir + "\\legacy.db"
	st1, err := Open(dbPath)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	ctx := context.Background()
	registerAB(t, st1)
	if _, err := st1.CreateSession(ctx, "dev-a", "net", 0); err != nil {
		t.Fatalf("create: %v", err)
	}
	st1.Close()
	st2, err := Open(dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { st2.Close() })
	if _, err := st2.CreateSession(ctx, "dev-a", "net", 0); err != nil {
		t.Fatalf("create on reopened: %v", err)
	}
}
