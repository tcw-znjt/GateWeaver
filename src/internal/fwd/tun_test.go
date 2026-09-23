package fwd

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// tunGuard 探测用 fake：路由输出可切换、拨号可切换
type guardRun struct {
	mu    sync.Mutex
	route string // ip route get 输出
	fail  bool
}

func (g *guardRun) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail || name != "ip" {
		return nil, errors.New("boom")
	}
	return []byte(g.route), nil
}
func (g *guardRun) set(route string, fail bool) {
	g.mu.Lock()
	g.route, g.fail = route, fail
	g.mu.Unlock()
}

type pipeConn struct{ net.Conn }

type guardDial struct {
	mu   sync.Mutex
	fail bool
}

func (d *guardDial) DialTimeout(n, a string, t time.Duration) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return nil, errors.New("refused")
	}
	c1, c2 := net.Pipe()
	_ = c2
	return c1, nil
}
func (d *guardDial) set(fail bool) {
	d.mu.Lock()
	d.fail = fail
	d.mu.Unlock()
}

const tunRoute = "223.5.5.5 dev tun0 table 2022 src 192.168.1.10 uid 0 \n    cache \n"
const physRoute = "223.5.5.5 via 192.168.1.1 dev eth0 src 192.168.1.10 uid 0 \n    cache \n"

func TestTunGuardDegradeRecover(t *testing.T) {
	gr := &guardRun{}
	gr.set(tunRoute, false)
	gd := &guardDial{}
	var down, up int
	mu := sync.Mutex{}
	g := NewTunGuard(gr, gd, "tun", "127.0.0.1:19090",
		func() { mu.Lock(); down++; mu.Unlock() },
		func() { mu.Lock(); up++; mu.Unlock() }, nil)
	g.interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)

	time.Sleep(150 * time.Millisecond)
	if !g.Healthy() || down != 0 {
		t.Fatalf("should be healthy: healthy=%v down=%d", g.Healthy(), down)
	}

	// 双故障 → 判障
	gr.set(physRoute, false)
	gd.set(true)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		d := down
		mu.Unlock()
		if d == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if g.Healthy() {
		t.Fatal("should be unhealthy after threshold")
	}

	// 恢复 → onUp
	gr.set(tunRoute, false)
	gd.set(false)
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		u := up
		mu.Unlock()
		if u == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !g.Healthy() {
		t.Fatal("should recover")
	}
	// 判障/恢复各只回调一次
	mu.Lock()
	defer mu.Unlock()
	if down != 1 || up != 1 {
		t.Fatalf("callbacks not edge-triggered: down=%d up=%d", down, up)
	}
	g.Stop()
}

func TestTunGuardFlapBelowThresholdIgnored(t *testing.T) {
	gr := &guardRun{route: tunRoute}
	gd := &guardDial{}
	var down int
	g := NewTunGuard(gr, gd, "tun", "127.0.0.1:19090", func() { down++ }, nil, nil)
	g.interval = 30 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.Start(ctx)
	// 单次故障后立刻恢复（< failDown=3 次）
	time.Sleep(50 * time.Millisecond)
	gr.set(physRoute, false)
	time.Sleep(40 * time.Millisecond)
	gr.set(tunRoute, false)
	time.Sleep(300 * time.Millisecond)
	if down != 0 {
		t.Fatalf("flap must not trigger withdraw: down=%d", down)
	}
	if !g.Healthy() {
		t.Fatal("should stay healthy")
	}
	g.Stop()
}
