// Clash 服务可达性探测（clash-traffic-steering spec：故障逐设备降级直连）。
package fwd

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Dialer 抽象 TCP 拨测（单测注入 fake）。
type Dialer interface {
	DialTimeout(network, address string, timeout time.Duration) (net.Conn, error)
}

type NetDialer struct{}

func (NetDialer) DialTimeout(n, a string, t time.Duration) (net.Conn, error) {
	return net.DialTimeout(n, a, t)
}

// ClashHealth 周期拨测 Clash 的 TCP/DNS 端口；连续 Threshold 次失败判障。
type ClashHealth struct {
	d         Dialer
	addrs     []string // "ip:port" 列表（tcp 与 dns 各一）
	interval  time.Duration
	threshold int
	onDown    func()
	onUp      func()

	mu      sync.Mutex
	failed  int
	healthy bool // 未启用探测时保持 true
	cancel  context.CancelFunc
}

func NewClashHealth(d Dialer, addrs []string, interval time.Duration, threshold int, onDown, onUp func()) *ClashHealth {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if threshold <= 0 {
		threshold = 3
	}
	return &ClashHealth{d: d, addrs: addrs, interval: interval, threshold: threshold,
		onDown: onDown, onUp: onUp, healthy: true}
}

func (h *ClashHealth) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	h.mu.Lock()
	h.cancel = cancel
	h.mu.Unlock()
	go h.loop(ctx)
}

func (h *ClashHealth) Stop() {
	h.mu.Lock()
	c := h.cancel
	h.mu.Unlock()
	if c != nil {
		c()
	}
}

// SetTargets 更新探测地址集合（Clash 配置热变更后调用）。
func (h *ClashHealth) SetTargets(addrs []string) {
	h.mu.Lock()
	h.addrs = addrs
	h.mu.Unlock()
}

// SetEnabled 关闭时重置为 healthy（不参与降级判断）。
func (h *ClashHealth) SetEnabled(on bool) {
	h.mu.Lock()
	if !on {
		h.healthy, h.failed = true, 0
	}
	h.mu.Unlock()
}

// Healthy 返回当前判定。
func (h *ClashHealth) Healthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.healthy
}

func (h *ClashHealth) loop(ctx context.Context) {
	t := time.NewTicker(h.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.check(ctx)
		}
	}
}

func (h *ClashHealth) check(ctx context.Context) {
	h.mu.Lock()
	addrs := append([]string(nil), h.addrs...)
	h.mu.Unlock()
	ok := h.probeOnce(ctx, addrs)
	h.mu.Lock()
	if ok {
		h.failed = 0
		if !h.healthy {
			h.healthy = true
			h.mu.Unlock()
			if h.onUp != nil {
				h.onUp()
			}
			return
		}
	} else {
		h.failed++
		if h.healthy && h.failed >= h.threshold {
			h.healthy = false
			h.mu.Unlock()
			if h.onDown != nil {
				h.onDown()
			}
			return
		}
	}
	h.mu.Unlock()
}

// probeOnce 任一必需端口拨断即视为失败（全部可达才算健康）。
func (h *ClashHealth) probeOnce(ctx context.Context, addrs []string) bool {
	if len(addrs) == 0 {
		return true
	}
	for _, a := range addrs {
		cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		c, err := h.dial(cctx, a)
		cancel()
		if err != nil {
			return false
		}
		_ = c.Close()
	}
	return true
}

func (h *ClashHealth) dial(ctx context.Context, addr string) (net.Conn, error) {
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := h.d.DialTimeout("tcp", addr, 2*time.Second)
		ch <- res{c, err}
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("clash probe %s: %w", addr, ctx.Err())
	case r := <-ch:
		return r.c, r.err
	}
}
