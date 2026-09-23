package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingGivesDefault(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	s, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	c := s.Snapshot()
	if c.InjectIntervalSec != 20 || c.Port != 9666 || !c.FailOpenOnUpstreamDown {
		t.Fatalf("bad defaults: %+v", c)
	}
}

func TestUpdatePersistAndReload(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	s, _ := Load(p)
	gw := netip.MustParseAddr("192.168.1.1")
	err := s.Update(gw, func(c *Config) error {
		c.Targets = append(c.Targets, Target{MAC: "bb:bb:bb:bb:bb:02", IP: "192.168.1.50", Iface: "eth0", Enabled: true})
		c.InjectIntervalSec = 7
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("file not written: %v", err)
	}
	s2, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	c := s2.Snapshot()
	if c.InjectIntervalSec != 7 || len(c.Targets) != 1 || c.Targets[0].IP != "192.168.1.50" {
		t.Fatalf("reload mismatch: %+v", c)
	}
}

func TestUpdateValidationRejectsBadInput(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	s, _ := Load(p)
	gw := netip.MustParseAddr("192.168.1.1")
	// 目标 = 网关被拒（arp-gateway-takeover spec）
	if err := s.Update(gw, func(c *Config) error {
		c.Targets = append(c.Targets, Target{MAC: "11:22:33:44:55:66", IP: "192.168.1.1", Iface: "eth0"})
		return nil
	}); err == nil {
		t.Fatal("gateway as target must be rejected")
	}
	// 非法间隔
	if err := s.Update(gw, func(c *Config) error { c.InjectIntervalSec = 0; return nil }); err == nil {
		t.Fatal("interval 0 must be rejected")
	}
	// 非法 IP
	if err := s.Update(gw, func(c *Config) error {
		c.Targets = []Target{{MAC: "aa:aa:aa:aa:aa:aa", IP: "999.1.1.1", Iface: "eth0"}}
		return nil
	}); err == nil {
		t.Fatal("bad ip must be rejected")
	}
	// 失败后内存与磁盘均不变
	if _, err := os.Stat(p); err == nil {
		t.Fatal("rejected updates must not persist")
	}
	if len(s.Snapshot().Targets) != 0 {
		t.Fatal("memory mutated on failed update")
	}
}

func TestCorruptFileErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	os.WriteFile(p, []byte("{not json"), 0o600)
	if _, err := Load(p); err == nil {
		t.Fatal("corrupt config must error")
	}
}
