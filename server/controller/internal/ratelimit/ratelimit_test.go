// 限流器测试：窗口计数 / 阈值拒绝 / 成功重置 / 窗口滑动解锁。

package ratelimit

import (
	"testing"
	"time"
)

func TestFailedAttemptsBlock(t *testing.T) {
	tr := NewTracker(Config{Window: time.Minute, MaxFails: 3})
	for i := 0; i < 3; i++ {
		if !tr.Allowed("1.2.3.4", "dev-x") {
			t.Fatalf("第 %d 次失败后仍应允许", i+1)
		}
		tr.RecordFail("1.2.3.4", "dev-x")
	}
	if tr.Allowed("1.2.3.4", "dev-x") {
		t.Fatal("超过阈值应拒绝（per-IP）")
	}
	// 换 IP 但同一设备：仍被拒（per-device 维度独立生效）。
	if tr.Allowed("5.6.7.8", "dev-x") {
		t.Fatal("per-device 维度应拒绝（换 IP 无效）")
	}
	// 其他设备从被限 IP 访问：也被拒（per-IP 维度独立生效）。
	if tr.Allowed("1.2.3.4", "dev-other") {
		t.Fatal("per-IP 维度应拒绝（换设备无效）")
	}
	// 无关 IP + 无关设备不受牵连。
	if !tr.Allowed("5.6.7.8", "dev-other") {
		t.Fatal("无关 IP/设备不应被牵连")
	}
}

func TestSuccessResets(t *testing.T) {
	tr := NewTracker(Config{Window: time.Minute, MaxFails: 3})
	tr.RecordFail("1.2.3.4", "dev-x")
	tr.RecordFail("1.2.3.4", "dev-x")
	tr.RecordSuccess("1.2.3.4", "dev-x")
	if !tr.Allowed("1.2.3.4", "dev-x") {
		t.Fatal("成功后计数应重置")
	}
}

func TestWindowSlides(t *testing.T) {
	tr := NewTracker(Config{Window: 30 * time.Millisecond, MaxFails: 2})
	tr.RecordFail("1.2.3.4", "dev-x")
	tr.RecordFail("1.2.3.4", "dev-x")
	if tr.Allowed("1.2.3.4", "dev-x") {
		t.Fatal("窗口内应拒绝")
	}
	time.Sleep(50 * time.Millisecond)
	if !tr.Allowed("1.2.3.4", "dev-x") {
		t.Fatal("窗口滑过后应解锁")
	}
}
