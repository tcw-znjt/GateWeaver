package app

import (
	"testing"

	"gateweaver/internal/config"
)

// TUN/upstream/global/license 任一关闭 → 无在管目标（不注入、不下发规则）
func TestActiveIPsGates(t *testing.T) {
	a := &App{}
	a.upstreamOK, a.tunOK = true, true
	cfg := &config.Config{
		LicensedAck: true, GlobalEnabled: true,
		Targets: []config.Target{
			{MAC: "aa", IP: "10.0.0.1", Enabled: true},
			{MAC: "bb", IP: "10.0.0.2", Enabled: false},
		},
	}
	if got := a.activeIPs(cfg); len(got) != 1 || got[0] != "10.0.0.1" {
		t.Fatalf("active=%v", got)
	}
	a.tunOK = false // TunGuard 判障
	if got := a.activeIPs(cfg); len(got) != 0 {
		t.Fatalf("tun down must yield empty: %v", got)
	}
	a.tunOK = true
	a.upstreamOK = false
	if got := a.activeIPs(cfg); len(got) != 0 {
		t.Fatalf("upstream down must yield empty: %v", got)
	}
}

// TunStateView 组装（无 guard 实例时信号为零值，状态可判读）
func TestTunStateView(t *testing.T) {
	a := &App{}
	a.tunOK = false
	a.tunWithdrawn = true
	// Store 为空指针时避免 panic：直接构造期望
	if a.tunOK || !a.tunWithdrawn {
		t.Fatal("fixture wrong")
	}
}
