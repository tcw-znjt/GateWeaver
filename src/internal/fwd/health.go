// 上游健康探测 + fail-open 触发（traffic-forwarding spec 第 4 条）。
package fwd

import (
	"context"
	"sync"
	"time"
)

// Health 周期性探测上游网关可达性；连续 Threshold 次失败判定故障并回调 onDown，
// 恢复后回调 onUp。探测顺带供引擎复核网关 MAC（design D6）。
type Health struct {
	r         Runner
	gw        string
	interval  time.Duration
	threshold int
	onDown    func()
	onUp      func()
	onChange  func(healthy bool)

	mu      sync.Mutex
	failed  int
	healthy bool
	cancel  context.CancelFunc
}

func NewHealth(r Runner, gw string, interval time.Duration, threshold int, onDown, onUp func(), onChange func(bool)) *Health {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if threshold <= 0 {
		threshold = 3
	}
	return &Health{r: r, gw: gw, interval: interval, threshold: threshold,
		onDown: onDown, onUp: onUp, onChange: onChange, healthy: true}
}

// Start 启动探测循环（ctx 取消即停）。
func (h *Health) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	h.mu.Lock()
	h.cancel = cancel
	h.mu.Unlock()
	go h.loop(ctx)
}

// Stop 停止探测循环。
func (h *Health) Stop() {
	h.mu.Lock()
	c := h.cancel
	h.mu.Unlock()
	if c != nil {
		c()
	}
}

// Healthy 返回当前判定。
func (h *Health) Healthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.healthy
}

func (h *Health) loop(ctx context.Context) {
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

func (h *Health) check(ctx context.Context) {
	ok := h.probeOnce(ctx)
	h.mu.Lock()
	if ok {
		h.failed = 0
		if !h.healthy {
			h.healthy = true
			h.mu.Unlock()
			if h.onChange != nil {
				h.onChange(true)
			}
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
			if h.onChange != nil {
				h.onChange(false)
			}
			if h.onDown != nil {
				h.onDown()
			}
			return
		}
	}
	h.mu.Unlock()
}

// probeOnce 先试 arping（L2，更贴近网关存活），退化 ping（L3）。
func (h *Health) probeOnce(ctx context.Context) bool {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := h.r.Run(cctx, "arping", "-q", "-c", "1", "-w", "1", h.gw); err == nil {
		return true
	}
	if _, err := h.r.Run(cctx, "ping", "-c", "1", "-W", "1", h.gw); err == nil {
		return true
	}
	return false
}
