// Package fwd 管理接管期的内核转发状态：ip_forward/rp_filter、仅针对目标集合的
// 过滤/伪装规则、上游健康探测。所有系统调用经 Runner 抽象以便单测（tasks 3.x）。
package fwd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Runner 执行外部命令并返回输出（fake 用于单测）。
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// DefaultRunner 返回真实执行器。
func DefaultRunner() Runner { return execRunner{} }

// --- Sysctl 管理 ---

// SysctlMgr 记录"改动前原值"并只还原自己改过的键。原值快照持久化到文件，
// 以便守护进程重启/崩溃后仍能正确还原（fnos-app-package spec：卸载彻底清理）。
type SysctlMgr struct {
	r       Runner
	mu      sync.Mutex
	changed map[string]string // key → 原值（仅我们改过的）
	file    string            // 持久化快照路径
}

func NewSysctlMgr(r Runner, snapshotPath string) *SysctlMgr {
	m := &SysctlMgr{r: r, changed: map[string]string{}, file: snapshotPath}
	m.load()
	return m
}

func sysctlPath(key string) string {
	return "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
}

// Set 设置 key=value；保存首次改动前的原值。
func (m *SysctlMgr) Set(ctx context.Context, key, value string) error {
	p := sysctlPath(key)
	m.mu.Lock()
	if _, done := m.changed[key]; !done {
		out, err := m.r.Run(ctx, "cat", p)
		if err != nil {
			m.mu.Unlock()
			return fmt.Errorf("fwd: read %s: %w", key, err)
		}
		m.changed[key] = strings.TrimSpace(string(out))
	}
	m.persist()
	m.mu.Unlock()
	if _, err := m.r.Run(ctx, "sh", "-c", fmt.Sprintf("echo %s > %s", value, p)); err != nil {
		return fmt.Errorf("fwd: set %s=%s: %w", key, value, err)
	}
	return nil
}

// Restore 还原所有由本管理器改过的键（引用检测由调用方决定是否调用）。
func (m *SysctlMgr) Restore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []string
	for key, orig := range m.changed {
		if _, err := m.r.Run(ctx, "sh", "-c", fmt.Sprintf("echo %s > %s", orig, sysctlPath(key))); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", key, err))
		}
	}
	m.changed = map[string]string{}
	m.persist()
	if len(errs) > 0 {
		return fmt.Errorf("fwd: restore errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Changed 返回当前被我们改动的键集合快照。
func (m *SysctlMgr) Changed() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.changed))
	for k, v := range m.changed {
		out[k] = v
	}
	return out
}

func (m *SysctlMgr) load() {
	if m.file == "" {
		return
	}
	b, err := os.ReadFile(m.file)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok && k != "" {
			m.changed[k] = v
		}
	}
}

func (m *SysctlMgr) persist() {
	if m.file == "" {
		return
	}
	_ = os.MkdirAll(filepath.Dir(m.file), 0o750)
	var sb strings.Builder
	for k, v := range m.changed {
		sb.WriteString(k + "=" + v + "\n")
	}
	_ = os.WriteFile(m.file, []byte(sb.String()), 0o600)
}

// --- 包过滤规则（iptables，Debian nft 后端兼容同名命令） ---

const (
	fwdChain = "GW_FORWARD"
	natChain = "GW_POSTROUTING"
	comment  = "gateweaver"
)

// RuleMgr 维护两条自定义链：FORWARD→GW_FORWARD（按目标放行）、
// POSTROUTING→GW_POSTROUTING（masquerade 模式下按目标改写源）。
// 目标集合外零影响（traffic-forwarding spec）。
type RuleMgr struct {
	r       Runner
	mu      sync.Mutex
	present map[string]bool // 当前已下发的目标 IP
	hooked  bool
}

func NewRuleMgr(r Runner) *RuleMgr {
	return &RuleMgr{r: r, present: map[string]bool{}}
}

func (m *RuleMgr) run(ctx context.Context, args ...string) error {
	out, err := m.r.Run(ctx, "iptables", args...)
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureChains 建链并挂载钩子（幂等：-C 已存在则跳过）。
func (m *RuleMgr) EnsureChains(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hooked {
		return nil
	}
	// 新建（已存在报错忽略）
	_, _ = m.r.Run(ctx, "iptables", "-t", "filter", "-N", fwdChain)
	_, _ = m.r.Run(ctx, "iptables", "-t", "nat", "-N", natChain)
	if err := m.linkIfAbsent(ctx, "filter", "FORWARD", fwdChain); err != nil {
		return err
	}
	if err := m.linkIfAbsent(ctx, "nat", "POSTROUTING", natChain); err != nil {
		return err
	}
	m.hooked = true
	return nil
}

func (m *RuleMgr) linkIfAbsent(ctx context.Context, table, parent, chain string) error {
	check := []string{"-t", table, "-C", parent, "-j", chain}
	if _, err := m.r.Run(ctx, "iptables", check...); err == nil {
		return nil
	}
	return m.run(ctx, "-t", table, "-A", parent, "-j", chain, "-m", "comment", "--comment", comment)
}

// Sync 将规则与目标集合 + 模式对齐：新增 -A、移除 -D。masq=false 时清空伪装规则。
func (m *RuleMgr) Sync(ctx context.Context, ips []string, masq bool) error {
	if err := m.EnsureChains(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	desired := map[string]bool{}
	for _, ip := range ips {
		desired[ip] = true
	}
	for ip := range desired {
		if !m.present[ip] {
			if err := m.run(ctx, "-t", "filter", "-A", fwdChain, "-s", ip+"/32", "-j", "ACCEPT",
				"-m", "comment", "--comment", comment); err != nil {
				return err
			}
		}
		if masq {
			if err := m.addIfAbsent(ctx, "nat", natChain, "-s", ip+"/32", "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
	}
	for ip := range m.present {
		if !desired[ip] {
			_ = m.run(ctx, "-t", "filter", "-D", fwdChain, "-s", ip+"/32", "-j", "ACCEPT",
				"-m", "comment", "--comment", comment)
			_ = m.run(ctx, "-t", "nat", "-D", natChain, "-s", ip+"/32", "-j", "MASQUERADE")
			delete(m.present, ip)
		}
	}
	if !masq {
		// 模式回退：清掉全部伪装规则（链保留）
		for ip := range desired {
			_ = m.run(ctx, "-t", "nat", "-D", natChain, "-s", ip+"/32", "-j", "MASQUERADE")
		}
	}
	for ip := range desired {
		m.present[ip] = true
	}
	return nil
}

func (m *RuleMgr) addIfAbsent(ctx context.Context, table, chain string, args ...string) error {
	full := append([]string{"-t", table, "-C", chain}, args...)
	if _, err := m.r.Run(ctx, "iptables", full...); err == nil {
		return nil
	}
	full = append([]string{"-t", table, "-A", chain}, args...)
	return m.run(ctx, full...)
}

// Cleanup 完全拆除：摘钩子、清规则、删链（uninstall/stop 兜底）。
func (m *RuleMgr) Cleanup(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var firstErr error
	try := func(args ...string) {
		if _, err := m.r.Run(ctx, "iptables", args...); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	try("-t", "filter", "-D", "FORWARD", "-j", fwdChain)
	try("-t", "nat", "-D", "POSTROUTING", "-j", natChain)
	try("-t", "filter", "-F", fwdChain)
	try("-t", "nat", "-F", natChain)
	try("-t", "filter", "-X", fwdChain)
	try("-t", "nat", "-X", natChain)
	m.present = map[string]bool{}
	m.hooked = false
	return firstErr
}
