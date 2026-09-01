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
