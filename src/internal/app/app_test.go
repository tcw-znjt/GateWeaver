package app

import (
	"testing"

	"gateweaver/internal/config"
)

// clash 降级并集：Clash 不健康 + fail_direct → via-clash 目标落入 direct 集合。
func TestSplitPathsDegrade(t *testing.T) {
	a := &App{}
	a.clashOK = true
	a.upstreamOK = true
	cfg := &config.Config{
		LicensedAck: true, GlobalEnabled: true, ClashEnabled: true, ClashFailDirect: true,
		Targets: []config.Target{
			{MAC: "aa", IP: "10.0.0.1", Enabled: true, ViaClash: true},
			{MAC: "bb", IP: "10.0.0.2", Enabled: true, ViaClash: false},
			{MAC: "cc", IP: "10.0.0.3", Enabled: false, ViaClash: true},
		},
	}
	direct, clash := a.splitPaths(cfg)
	if len(direct) != 1 || direct[0] != "10.0.0.2" {
		t.Fatalf("direct=%v", direct)
	}
	if len(clash) != 1 || clash[0] != "10.0.0.1" {
		t.Fatalf("clash=%v", clash)
	}

	// Clash 故障 + 降级策略开 → 10.0.0.1 变直连
	a.clashOK = false
	direct, clash = a.splitPaths(cfg)
	if len(clash) != 0 || len(direct) != 2 {
		t.Fatalf("degraded: direct=%v clash=%v", direct, clash)
	}

	// 故障但不降级 → 维持改道
	cfg.ClashFailDirect = false
	_, clash = a.splitPaths(cfg)
	if len(clash) != 1 {
		t.Fatalf("no-failover should keep clash: %v", clash)
	}

	// Clash 全局关 → 全直连（原方案）
	cfg.ClashEnabled = false
	direct, clash = a.splitPaths(cfg)
	if len(clash) != 0 || len(direct) != 2 {
		t.Fatalf("clash off: direct=%v clash=%v", direct, clash)
	}

	// 未授权/全局关时两集合皆空
	cfg2 := *cfg
	cfg2.GlobalEnabled = false
	d, c := a.splitPaths(&cfg2)
	if len(d)+len(c) != 0 {
		t.Fatal("global off must yield empty sets")
	}
}
