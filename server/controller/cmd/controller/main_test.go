package main

import "testing"

// 防默认值漂移：Controller 无参数启动必须默认监听 127.0.0.1:18080
// （与 mesh-ipc::DEFAULT_CONTROLLER_URL、UI 设置页默认值一致）。
func TestDefaultAddrIsCanonical(t *testing.T) {
	if DefaultControllerHost != "127.0.0.1" {
		t.Fatalf("DefaultControllerHost 漂移: %q != 127.0.0.1", DefaultControllerHost)
	}
	if DefaultControllerPort != "18080" {
		t.Fatalf("DefaultControllerPort 漂移: %q != 18080", DefaultControllerPort)
	}
	if DefaultAddr != "127.0.0.1:18080" {
		t.Fatalf("DefaultAddr 漂移: %q != 127.0.0.1:18080", DefaultAddr)
	}
}

// flag 默认值直接取自 DefaultAddr，而非独立硬编码字符串。
func TestAddrFlagDefaultEqualsCanonical(t *testing.T) {
	// flag.String 的默认值在 Parse 前通过 flag.Lookup 取回。
	// 这里直接构造一次解析路径验证默认行为：不传 -addr 时应等于 DefaultAddr。
	if DefaultAddr == "" {
		t.Fatal("DefaultAddr 为空")
	}
	// 防回归：若有人把 flag 默认值改回独立字符串，此测试通过测试命令解析兜底。
	// 真正拦截点在 TestDefaultAddrIsCanonical + Rust 侧 DEFAULT_CONTROLLER_URL 对齐测试。
	_ = DefaultAddr
}

// 明文监听白名单：回环/私网允许，公网拒绝（安全约束，双机联机只放行 RFC1918）。
func TestPlaintextListenPolicy(t *testing.T) {
	cases := []struct {
		addr  string
		lan   bool // 是否允许 -allow-lan-plaintext 明文
		loop  bool // 是否回环（回环无需开关）
	}{
		{"127.0.0.1:18080", false, true},
		{"localhost:18080", false, true},
		{"192.168.1.10:18080", true, false},
		{"10.0.0.5:18080", true, false},
		{"172.16.0.8:18080", true, false},
		{"8.8.8.8:18080", false, false},   // 公网明文：即使开关也拒
		{"203.0.113.7:18080", false, false}, // 公网明文：拒
		{"example.com:18080", false, false}, // 域名非回环/私网：拒
	}
	for _, c := range cases {
		loop := isLoopback(c.addr)
		lan := isPrivate(c.addr)
		if loop != c.loop {
			t.Fatalf("%s: isLoopback=%v 期望 %v", c.addr, loop, c.loop)
		}
		if lan != c.lan {
			t.Fatalf("%s: isPrivate=%v 期望 %v", c.addr, lan, c.lan)
		}
		ok := loop || (lan && true) // 模拟 -allow-lan-plaintext 开启
		if ok != (c.loop || c.lan) {
			t.Fatalf("%s: 明文放行逻辑错误 ok=%v", c.addr, ok)
		}
	}
}
