// TUN 全局接管引导守护（tun-transit-guard spec）。
package fwd

import (
	"context"
	"net"
	"strings"
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

// TunGuard 每 interval 联合探测：① `ip route get <probeIP>` 出口为 TunIface；
// ② controller TCP 可达。连续 failDown 次失败判障（onDown 一次），
// 连续 okUp 次成功判恢复（onUp 一次）。Disabled 时恒健康。
type TunGuard struct {
	r        Runner
	d        Dialer
	tunIface string
	ctrlAddr string
	probeIP  string
	interval time.Duration

	failDown, okUp int
	onDown, onUp   func()
	notifyChange   func(ok bool)

	mu       sync.Mutex
	disabled bool
	failed   int
	okStreak int
	healthy  bool
	routeOK  bool
	ctrlOK   bool
	cancel   context.CancelFunc
}

func NewTunGuard(r Runner, d Dialer, tunIface, ctrlAddr string, onDown, onUp func(), onChange func(bool)) *TunGuard {
	return &TunGuard{
		r: r, d: d, tunIface: tunIface, ctrlAddr: ctrlAddr, probeIP: "223.5.5.5",
		interval: 5 * time.Second, failDown: 3, okUp: 2,
		onDown: onDown, onUp: onUp, notifyChange: onChange,
		healthy: true,
	}
}

// Configure 热更探测参数（接口名/controller 地址/开关）。
func (g *TunGuard) Configure(tunIface, ctrlAddr string, enabled bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if tunIface != "" {
		g.tunIface = tunIface
	}
	if ctrlAddr != "" {
		g.ctrlAddr = ctrlAddr
	}
	wasDisabled := g.disabled
	g.disabled = !enabled
	if !enabled && !wasDisabled {
		g.healthy, g.failed, g.okStreak = true, 0, 0
	}
}

// Healthy 返回联合判定。
func (g *TunGuard) Healthy() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.healthy
}

// Signals 返回最近一次两路探测的分项结果（管理台展示）。
func (g *TunGuard) Signals() (routeOK, ctrlOK bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.routeOK, g.ctrlOK
}

// Start 启动探测循环。
func (g *TunGuard) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	g.mu.Lock()
	g.cancel = cancel
	g.mu.Unlock()
	go g.loop(ctx)
}

// Stop 停止探测。
func (g *TunGuard) Stop() {
	g.mu.Lock()
	c := g.cancel
	g.mu.Unlock()
	if c != nil {
		c()
	}
}

func (g *TunGuard) loop(ctx context.Context) {
	t := time.NewTicker(g.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			g.check(ctx)
		}
	}
}

func (g *TunGuard) check(ctx context.Context) {
	g.mu.Lock()
	if g.disabled {
		g.mu.Unlock()
		return
	}
	tun, ctrl := g.tunIface, g.ctrlAddr
	g.mu.Unlock()

	routeOK := g.probeRoute(ctx, tun)
	ctrlOK := g.probeCtrl(ctx, ctrl)

	g.mu.Lock()
	g.routeOK, g.ctrlOK = routeOK, ctrlOK
	ok := routeOK && ctrlOK
	if ok {
		g.failed = 0
		g.okStreak++
		if !g.healthy && g.okStreak >= g.okUp {
			g.healthy = true
			g.okStreak = 0
			g.mu.Unlock()
			if g.notifyChange != nil {
				g.notifyChange(true)
			}
			if g.onUp != nil {
				g.onUp()
			}
			return
		}
	} else {
		g.okStreak = 0
		g.failed++
		if g.healthy && g.failed >= g.failDown {
			g.healthy = false
			g.failed = 0
			g.mu.Unlock()
			if g.notifyChange != nil {
				g.notifyChange(false)
			}
			if g.onDown != nil {
				g.onDown()
			}
			return
		}
	}
	g.mu.Unlock()
}

// probeRoute 主路由表默认路由是否指向 TUN 接口（对公网地址做路由决策，与真实连通性无关）。
func (g *TunGuard) probeRoute(ctx context.Context, tun string) bool {
	cctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	out, err := g.r.Run(cctx, "ip", "route", "get", g.probeIP)
	if err != nil {
		return false
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) && strings.HasPrefix(fields[i+1], tun) {
			return true
		}
	}
	return false
}

func (g *TunGuard) probeCtrl(ctx context.Context, addr string) bool {
	if addr == "" {
		return true // 未配置视为跳过该信号
	}
	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := g.d.DialTimeout("tcp", addr, 2*time.Second)
		ch <- res{c, err}
	}()
	select {
	case <-ctx.Done():
		return false
	case r := <-ch:
		if r.err != nil {
			return false
		}
		_ = r.c.Close()
		return true
	}
}

