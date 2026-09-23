package fwd

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

type fakeDialer struct {
	mu   sync.Mutex
	fail bool
}

func (f *fakeDialer) DialTimeout(n, a string, t time.Duration) (net.Conn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return nil, errors.New("refused")
	}
	return nil, nil // 返回 nil Conn 但 err==nil；Close 在 health 里对 nil 安全吗？——见下
}

// nil conn 会 panic，用 pipe 返回真实 conn 两端。
func (f *fakeDialer) dialOK(a string) (net.Conn, error) {
	c1, c2 := net.Pipe()
	_ = c2
	return c1, nil
}

type okDialer struct{ f *fakeDialer }

func (o okDialer) DialTimeout(n, a string, t time.Duration) (net.Conn, error) {
	o.f.mu.Lock()
	fail := o.f.fail
	o.f.mu.Unlock()
	if fail {
		return nil, errors.New("refused")
	}
	return o.f.dialOK(a)
}

func TestClashHealthDegradeRecover(t *testing.T) {
	fd := &fakeDialer{}
	var down, up int
	h := NewClashHealth(okDialer{fd}, []string{"127.0.0.1:7893"}, 10*time.Millisecond, 3,
		func() { down++ }, func() { up++ })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.Start(ctx)
	if !h.Healthy() {
		t.Fatal("should start healthy")
	}
	fd.mu.Lock()
	fd.fail = true
	fd.mu.Unlock()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && down == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if down != 1 {
		t.Fatalf("onDown not called once: %d", down)
	}
	if h.Healthy() {
		t.Fatal("should be unhealthy")
	}
	fd.mu.Lock()
	fd.fail = false
	fd.mu.Unlock()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && up == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if up != 1 {
		t.Fatalf("onUp not called: %d", up)
	}
	h.Stop()
}

func TestClashHealthDisabledAlwaysHealthy(t *testing.T) {
	fd := &fakeDialer{}
	fd.fail = true
	h := NewClashHealth(okDialer{fd}, nil, 10*time.Millisecond, 2, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.Start(ctx)
	time.Sleep(100 * time.Millisecond)
	if !h.Healthy() {
		t.Fatal("empty probe set must stay healthy")
	}
	h.Stop()
}
