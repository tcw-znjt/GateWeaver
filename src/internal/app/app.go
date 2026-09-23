// Package app 编排配置 → 引擎/转发的应用服务层，供 REST API 与 main 调用。
package app

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gateweaver/internal/arpframe"
	"gateweaver/internal/auditlog"
	"gateweaver/internal/config"
	"gateweaver/internal/discover"
	"gateweaver/internal/engine"
	"gateweaver/internal/fwd"
	"gateweaver/internal/neti"
	"gateweaver/internal/probe"
)

// App 是运行中的 GateWeaver 服务。
type App struct {
	Store    *config.Store
	Engine   *engine.Engine
	Sysctl   *fwd.SysctlMgr
	Rules    *fwd.RuleMgr
	Probe    *probe.Resolver
	Scanner  *discover.Scanner
	Log      *auditlog.Logger
	Runner   fwd.Runner

	health *fwd.Health

	mu            sync.Mutex
	gwIP          netip.Addr // 生效的上游（配置或探测）
	upstreamOK    bool
	forwardEnsured bool
	cancel        context.CancelFunc
}

// New 组装服务。factory 为二层收发器工厂（Linux 用 neti.NewRaw，单测用 fake）。
func New(store *config.Store, log *auditlog.Logger, factory neti.TransceiverFactory, runner fwd.Runner) *App {
	pr := probe.New(runner)
	eng := engine.New(factory, func(iface string, gw netip.Addr) (arpframe.MAC, error) {
		return pr.Resolve(iface, gw)
	}, log)
	sys := fwd.NewSysctlMgr(runner, store.Path()+".sysctl.orig")
	rules := fwd.NewRuleMgr(runner)
	return &App{
		Store: store, Engine: eng, Sysctl: sys, Rules: rules,
		Probe: pr, Scanner: discover.NewScanner(runner), Log: log, Runner: runner,
		upstreamOK: true,
	}
}

// Start 启动后台协程（健康探测）。ctx 取消即停（不做恢复，由 Shutdown 负责）。
func (a *App) Start(ctx context.Context) error {
	cfg := a.Store.Snapshot()
	gw, err := a.resolveGateway(ctx, cfg)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.gwIP = gw
	a.mu.Unlock()

	if err := a.Apply(cfg); err != nil {
		return err
	}

	hctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancel = cancel
	a.mu.Unlock()

	iv := 5 * time.Second
	a.health = fwd.NewHealth(a.Runner, gw.String(), iv, 3,
		a.onUpstreamDown, a.onUpstreamUp, a.onUpstreamChange)
	a.health.Start(hctx)
	return nil
}

// Apply 将一份配置投影到引擎与转发层（幂等，可热调用）。
func (a *App) Apply(cfg *config.Config) error {
	gw, err := a.resolveGateway(context.Background(), cfg)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.gwIP = gw
	a.mu.Unlock()
	var fixedMAC arpframe.MAC
	if cfg.GatewayMACFixed != "" {
		m, err := arpframe.ParseMAC(cfg.GatewayMACFixed)
		if err != nil {
			return fmt.Errorf("bad gateway_mac_fixed: %w", err)
		}
		fixedMAC = m
	}
	if err := a.Engine.Configure(engine.Params{
		GatewayIP:    gw,
		Interval:     time.Duration(cfg.InjectIntervalSec) * time.Second,
		RatePerSec:   cfg.InjectRatePerSec,
		Licensed:     cfg.LicensedAck,
		GlobalOn:     cfg.GlobalEnabled && a.UpstreamOK(),
		GwMACFixed:   fixedMAC,
	}); err != nil {
		return err
	}
	if err := a.Engine.ApplyTargets(cfg.Targets); err != nil {
		return err
	}
	return a.syncForwarding(cfg)
}

// syncForwarding 依据"是否有实际生效的目标"维护内核与规则。
func (a *App) syncForwarding(cfg *config.Config) error {
	ctx := context.Background()
	active := a.activeTargetIPs(cfg)
	if len(active) == 0 {
		// 无目标：清空规则；内核改动保留至停机（可能被 Docker 等共享，避免抖动）
		return a.Rules.Sync(ctx, nil, false)
	}
	if !a.forwardEnsured {
		if err := a.Sysctl.Set(ctx, "net.ipv4.ip_forward", "1"); err != nil {
			return err
		}
		for ifc := range ifacesOf(cfg.Targets, true) {
			if err := a.Sysctl.Set(ctx, "net.ipv4.conf."+ifc+".rp_filter", "2"); err != nil {
				return err
			}
		}
		a.mu.Lock()
		a.forwardEnsured = true
		a.mu.Unlock()
	}
	masq := cfg.ForwardMode == config.ModeMasq
	return a.Rules.Sync(ctx, active, masq)
}

func (a *App) activeTargetIPs(cfg *config.Config) []string {
	if !cfg.GlobalEnabled || !cfg.LicensedAck || !a.UpstreamOK() {
		return nil
	}
	var out []string
	for _, t := range cfg.Targets {
		if t.Enabled {
			out = append(out, t.IP)
		}
	}
	return out
}

func ifacesOf(targets []config.Target, enabledOnly bool) map[string]bool {
	m := map[string]bool{}
	for _, t := range targets {
		if !enabledOnly || t.Enabled {
			m[t.Iface] = true
		}
	}
	return m
}

// --- 上游健康回调（fail-open，traffic-forwarding spec） ---

func (a *App) onUpstreamChange(ok bool) {}

func (a *App) onUpstreamDown() {
	a.mu.Lock()
	a.upstreamOK = false
	a.mu.Unlock()
	a.Log.Log("upstream", "system", "", "上游网关不可达：fail-open 撤销全部接管")
	a.Engine.RestoreAll("upstream down")
	if err := a.Rules.Sync(context.Background(), nil, false); err != nil {
		a.Log.Logf("error", "system", "", "清空转发规则失败: %v", err)
	}
}

func (a *App) onUpstreamUp() {
	a.mu.Lock()
	a.upstreamOK = true
	a.mu.Unlock()
	a.Log.Log("upstream", "system", "", "上游网关恢复：按配置重新接管")
	cfg := a.Store.Snapshot()
	if err := a.Apply(cfg); err != nil {
		a.Log.Logf("error", "system", "", "恢复后重接管失败: %v", err)
	}
}

// UpstreamOK 返回上游健康状态。
func (a *App) UpstreamOK() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.upstreamOK
}

// --- 生命周期 ---

// RecoverAll 一键恢复：全局关闭 + 撤销 + 清规则（配置保留）。
func (a *App) RecoverAll(actor string) error {
	cfgNow := a.Store.Snapshot()
	if err := a.Store.Update(a.gwIP, func(c *config.Config) error {
		c.GlobalEnabled = false
		return nil
	}); err != nil {
		return err
	}
	a.Log.Logf("audit", actor, "", "一键恢复（原全局开关=%v）", cfgNow.GlobalEnabled)
	return a.Apply(a.Store.Snapshot())
}

// Shutdown 停机：恢复全部接管、还原内核参数、拆规则、停引擎。
func (a *App) Shutdown(ctx context.Context) error {
	a.mu.Lock()
	cancel := a.cancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	a.Engine.RestoreAll("shutdown")
	a.Engine.Stop()
	// 等恢复通告双发完成
	time.Sleep(1200 * time.Millisecond)
	var errs []string
	if err := a.Rules.Cleanup(ctx); err != nil {
		errs = append(errs, err.Error())
	}
	if a.forwardEnsured {
		// 引用检测：有其他 ip_forward 使用者时保守不还原（design 风险条目）
		if others, _ := a.ipForwardUsers(ctx); others {
			a.Log.Log("error", "system", "", "检测到其他转发使用者，保留 ip_forward=1")
		} else {
			if err := a.Sysctl.Restore(ctx); err != nil {
				errs = append(errs, err.Error())
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

// ipForwardUsers 启发式：监听 53 的容器 dnsmasq 或 docker0 存在视为可能有其他使用者。
func (a *App) ipForwardUsers(ctx context.Context) (bool, error) {
	out, err := a.Runner.Run(ctx, "sh", "-c", "ss -lun sport = :53 | grep -c dnsmasq || true; ip link show docker0 >/dev/null 2>&1 && echo docker || true")
	if err != nil {
		return false, err
	}
	s := string(out)
	return strings.Contains(s, "docker") || strings.Contains(s, "1\n"), nil
}

// resolveGateway 取配置指定或探测默认路由。
func (a *App) resolveGateway(ctx context.Context, cfg *config.Config) (netip.Addr, error) {
	if cfg.GatewayIP != "" {
		return netip.ParseAddr(cfg.GatewayIP)
	}
	gw, _, err := a.Probe.DefaultRoute()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("app: 无默认路由且未指定网关: %w", err)
	}
	return gw, nil
}

// Gateway 返回当前生效上游。
func (a *App) Gateway() netip.Addr {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gwIP
}

// Interfaces 返回本机接口与地址/MAC（管理台选择目标接口、展示接管侧 MAC）。
func (a *App) Interfaces() (map[string]probe.IfaceInfo, error) {
	return a.Probe.Addrs()
}
