package fwd

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeRun struct {
	mu      sync.Mutex
	calls   []string
	failFn  func(name string, args []string) bool
}

func (f *fakeRun) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, line)
	if f.failFn != nil && f.failFn(name, args) {
		return []byte("boom"), fmt.Errorf("exit")
	}
	if name == "cat" { // sysctl 原值模拟
		return []byte("0\n"), nil
	}
	return nil, nil
}

func (f *fakeRun) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *fakeRun) log() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// 3.1 sysctl：只还原自己改过的键，快照持久化可跨重启
func TestSysctlSaveRestore(t *testing.T) {
	dir := t.TempDir()
	snap := dir + "/sysctl.orig"
	r := &fakeRun{}
	m := NewSysctlMgr(r, snap)
	ctx := context.Background()
	// cat 返回原值 "0"
	r.failFn = func(name string, args []string) bool { return false }
	if err := m.Set(ctx, "net.ipv4.ip_forward", "1"); err != nil {
		t.Fatal(err)
	}
	if got := m.Changed()["net.ipv4.ip_forward"]; got != "0" {
		t.Fatalf("original not recorded: %q", got)
	}
	// 二次 Set 不覆盖原值
	if err := m.Set(ctx, "net.ipv4.ip_forward", "1"); err != nil {
		t.Fatal(err)
	}
	if got := m.Changed()["net.ipv4.ip_forward"]; got != "0" {
		t.Fatalf("original overwritten: %q", got)
	}
	// 重启模拟：新实例加载快照
	m2 := NewSysctlMgr(r, snap)
	if got := m2.Changed()["net.ipv4.ip_forward"]; got != "0" {
		t.Fatalf("snapshot not persisted: %q", got)
	}
	r.reset()
	if err := m2.Restore(ctx); err != nil {
		t.Fatal(err)
	}
	var restored bool
	for _, c := range r.log() {
		if strings.Contains(c, "echo 0 > /proc/sys/net/ipv4/ip_forward") {
			restored = true
		}
	}
	if !restored {
		t.Fatalf("restore command missing: %v", r.log())
	}
	if len(m2.Changed()) != 0 {
		t.Fatal("changed not cleared")
	}
}

// 3.2 规则同步：按目标增删，卸载全拆
func TestRuleSyncAndCleanup(t *testing.T) {
	r := &fakeRun{}
	// 真实语义：-C 检查存在性，规则不存在时返回非零。fake 让所有 -C 失败（=不存在）。
	r.failFn = func(name string, args []string) bool {
		for _, a := range args {
			if a == "-C" {
				return true
			}
		}
		return false
	}
	rm := NewRuleMgr(r)
	ctx := context.Background()
	if err := rm.Sync(ctx, []string{"10.0.0.5"}, false); err != nil {
		t.Fatal(err)
	}
	logged := strings.Join(r.log(), "\n")
	if !strings.Contains(logged, "-A GW_FORWARD -s 10.0.0.5/32") {
		t.Fatalf("forward rule missing:\n%s", logged)
	}
	if strings.Contains(logged, "MASQUERADE -s 10.0.0.5") || strings.Contains(logged, "-A GW_POSTROUTING -s 10.0.0.5") {
		t.Fatalf("route mode must not masquerade:\n%s", logged)
	}
	// masq 模式 + 目标变更：旧目标规则被删
	r.reset()
	if err := rm.Sync(ctx, []string{"10.0.0.6"}, true); err != nil {
		t.Fatal(err)
	}
	logged = strings.Join(r.log(), "\n")
	if !strings.Contains(logged, "-D GW_FORWARD -s 10.0.0.5/32") {
		t.Fatalf("stale target not removed:\n%s", logged)
	}
	if !strings.Contains(logged, "-A GW_POSTROUTING -s 10.0.0.6/32 -j MASQUERADE") {
		t.Fatalf("masq rule not added:\n%s", logged)
	}
	// 幂等：重复 Sync 不重复 -A GW_FORWARD
	r.reset()
	_ = rm.Sync(ctx, []string{"10.0.0.6"}, true)
	for _, c := range r.log() {
		if strings.Contains(c, "-A GW_FORWARD -s 10.0.0.6") {
			t.Fatalf("duplicate forward rule added:\n%s", strings.Join(r.log(), "\n"))
		}
	}
	// cleanup
	r.reset()
	if err := rm.Cleanup(ctx); err != nil {
		t.Fatal(err)
	}
	logged = strings.Join(r.log(), "\n")
	for _, want := range []string{"-D FORWARD -j GW_FORWARD", "-X GW_FORWARD", "-F GW_POSTROUTING", "-X GW_CLASH_TCP", "-D PREROUTING -j GW_CLASH_DNS"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("cleanup missing %q:\n%s", want, logged)
		}
	}
}

func TestHealthFailOpen(t *testing.T) {
	r := &fakeRun{}
	var down, up int
	r.failFn = func(name string, args []string) bool { return true } // 全失败
	h := NewHealth(r, "192.168.1.1", 10*time.Millisecond, 3,
		func() { down++ }, func() { up++ }, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.Start(ctx)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && down == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if down != 1 {
		t.Fatalf("onDown not called exactly once: %d", down)
	}
	if h.Healthy() {
		t.Fatal("still healthy")
	}
	// 恢复探测成功
	r.failFn = func(name string, args []string) bool { return false }
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && up == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if up != 1 {
		t.Fatalf("onUp not called: %d", up)
	}
	h.Stop()
}
