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
	fwdChain     = "GW_FORWARD"
	natChain     = "GW_POSTROUTING"
	clashTCPChain = "GW_CLASH_TCP"
	clashDNSChain = "GW_CLASH_DNS"
	clashUDPChain = "GW_CLASH_UDP"
	comment      = "gateweaver"
	tproxyMark   = "0x1/0x1"
	tproxyTable  = "100"
)

// ClashParams Clash 引流参数（ClashAddr 空 = 本机 REDIRECT；否则 DNAT/TPROXY 到该 IPv4）。
type ClashParams struct {
	Addr    string // ""=本机
	TCPPort int
	DNSPort int
	UDPPort int // 0 = 不做 UDP TPROXY
}

// RuleMgr 维护：FORWARD→GW_FORWARD（直连放行）、POSTROUTING→GW_POSTROUTING（伪装）、
// PREROUTING→GW_CLASH_DNS/GW_CLASH_TCP（nat 改道），可选 PREROUTING→GW_CLASH_UDP（mangle TPROXY）。
// 目标集合按 direct/clash 两态动态迁移，私网目的绕行。
type RuleMgr struct {
	r       Runner
	mu      sync.Mutex
	direct  map[string]bool // GW_FORWARD 已下发目标
	masqSet map[string]bool // GW_POSTROUTING 已伪装目标
	clash   map[string]bool // 改道链已下发目标
	udpOn   bool            // TPROXY 规则+策略路由已建立
	hooked  bool
}

func NewRuleMgr(r Runner) *RuleMgr {
	return &RuleMgr{r: r, direct: map[string]bool{}, masqSet: map[string]bool{}, clash: map[string]bool{}}
}

func (m *RuleMgr) run(ctx context.Context, args ...string) error {
	out, err := m.r.Run(ctx, "iptables", args...)
	if err != nil {
		return fmt.Errorf("iptables %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// EnsureChains 建链并挂 PREROUTING 钩子（幂等）。
func (m *RuleMgr) EnsureChains(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hooked {
		return nil
	}
	for _, c := range [][3]string{
		{"filter", fwdChain, ""}, {"nat", natChain, ""}, {"nat", clashTCPChain, ""}, {"nat", clashDNSChain, ""},
	} {
		_, _ = m.r.Run(ctx, "iptables", "-t", c[0], "-N", c[1])
	}
	if err := m.linkIfAbsent(ctx, "filter", "FORWARD", fwdChain); err != nil {
		return err
	}
	if err := m.linkIfAbsent(ctx, "nat", "POSTROUTING", natChain); err != nil {
		return err
	}
	// DNS 链先挂（53 优先于 TCP 全量与私网绕行）
	if err := m.linkIfAbsent(ctx, "nat", "PREROUTING", clashDNSChain); err != nil {
		return err
	}
	if err := m.linkIfAbsent(ctx, "nat", "PREROUTING", clashTCPChain); err != nil {
		return err
	}
	// TCP 链内的静态绕行：RFC1918 目的不改道（clash-traffic-steering spec）
	for _, net := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if err := m.addIfAbsent(ctx, "nat", clashTCPChain, "-d", net, "-j", "RETURN"); err != nil {
			return err
		}
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

func (m *RuleMgr) addIfAbsent(ctx context.Context, table, chain string, args ...string) error {
	full := append([]string{"-t", table, "-C", chain}, args...)
	if _, err := m.r.Run(ctx, "iptables", full...); err == nil {
		return nil
	}
	full = append([]string{"-t", table, "-A", chain}, args...)
	return m.run(ctx, full...)
}

func (m *RuleMgr) delQuiet(ctx context.Context, table, chain string, args ...string) {
	full := append([]string{"-t", table, "-D", chain}, args...)
	_, _ = m.r.Run(ctx, "iptables", full...)
}

// Sync 全量对齐：directIPs 走直连放行（masq 时对同集合伪装），clashIPs 走改道链。
// 两集合互斥；冲突时 direct 优先。p 仅对 clashIPs 生效。
func (m *RuleMgr) Sync(ctx context.Context, directIPs, clashIPs []string, masq bool, p ClashParams) error {
	if err := m.EnsureChains(ctx); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	direct := toSet(directIPs)
	clash := toSet(clashIPs)
	for ip := range clash {
		if direct[ip] {
			delete(clash, ip) // 互斥：direct 优先
		}
	}

	// --- direct 链增删 ---
	for ip := range direct {
		if !m.direct[ip] {
			if err := m.run(ctx, "-t", "filter", "-A", fwdChain, "-s", ip+"/32", "-j", "ACCEPT",
				"-m", "comment", "--comment", comment); err != nil {
				return err
			}
			m.direct[ip] = true
		}
	}
	// --- clash 链增删 ---
	tcpT := m.clashTCPArgs(p)
	dnsT := m.clashDNSArgs(p)
	for ip := range clash {
		if !m.clash[ip] {
			if err := m.addIfAbsent(ctx, "nat", clashTCPChain, append([]string{"-s", ip + "/32"}, tcpT...)...); err != nil {
				return err
			}
			for _, a := range dnsT {
				if err := m.addIfAbsent(ctx, "nat", clashDNSChain, append([]string{"-s", ip + "/32"}, a...)...); err != nil {
					return err
				}
			}
			m.clash[ip] = true
		}
	}
	// 移除项
	for ip := range m.direct {
		if !direct[ip] {
			m.delQuiet(ctx, "filter", fwdChain, "-s", ip+"/32", "-j", "ACCEPT", "-m", "comment", "--comment", comment)
			delete(m.direct, ip)
		}
	}
	for ip := range m.clash {
		if !clash[ip] {
			m.delQuiet(ctx, "nat", clashTCPChain, append([]string{"-s", ip + "/32"}, tcpT...)...)
			for _, a := range dnsT {
				m.delQuiet(ctx, "nat", clashDNSChain, append([]string{"-s", ip + "/32"}, a...)...)
			}
			delete(m.clash, ip)
		}
	}
	// --- 伪装（仅 direct） ---
	for ip := range direct {
		if masq {
			if err := m.addIfAbsent(ctx, "nat", natChain, "-s", ip+"/32", "-j", "MASQUERADE"); err != nil {
				return err
			}
		}
	}
	for ip := range m.masqSet {
		if !direct[ip] || !masq {
			m.delQuiet(ctx, "nat", natChain, "-s", ip+"/32", "-j", "MASQUERADE")
			delete(m.masqSet, ip)
		}
	}
	for ip := range direct {
		if masq {
			m.masqSet[ip] = true
		}
	}

	// --- 可选 UDP TPROXY ---
	if p.UDPPort > 0 && len(clash) > 0 {
		if err := m.enableUDP(ctx, p); err != nil {
			return err
		}
		for ip := range clash {
			if err := m.addIfAbsent(ctx, "mangle", clashUDPChain,
				"-s", ip+"/32", "-p", "udp", "-j", "TPROXY",
				"--on-ip", orLocal(p.Addr), "--on-port", fmt.Sprint(p.UDPPort), "--tproxy-mark", tproxyMark); err != nil {
				return err
			}
		}
	} else if m.udpOn {
		m.disableUDP(ctx)
	}
	return nil
}

func (m *RuleMgr) clashTCPArgs(p ClashParams) []string {
	if p.Addr == "" {
		return []string{"-p", "tcp", "-j", "REDIRECT", "--to-ports", fmt.Sprint(p.TCPPort)}
	}
	return []string{"-p", "tcp", "-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", p.Addr, p.TCPPort)}
}

func (m *RuleMgr) clashDNSArgs(p ClashParams) [][]string {
	d := fmt.Sprint(p.DNSPort)
	if p.Addr == "" {
		return [][]string{
			{"-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-port", d},
			{"-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-port", d},
		}
	}
	dst := fmt.Sprintf("%s:%d", p.Addr, p.DNSPort)
	return [][]string{
		{"-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", dst},
		{"-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", dst},
	}
}

func orLocal(addr string) string {
	if addr == "" {
		return "0.0.0.0"
	}
	return addr
}

// enableUDP 建立 mangle TPROXY 链与策略路由（幂等；置 udpOn 供拆除判断）。
func (m *RuleMgr) enableUDP(ctx context.Context, p ClashParams) error {
	if !m.udpOn {
		_, _ = m.r.Run(ctx, "iptables", "-t", "mangle", "-N", clashUDPChain)
		if err := m.linkIfAbsent(ctx, "mangle", "PREROUTING", clashUDPChain); err != nil {
			return err
		}
		if _, err := m.r.Run(ctx, "sh", "-c", "ip rule show | grep -q 'fwmark 0x1/0x1' || ip rule add fwmark 0x1/0x1 table "+tproxyTable); err != nil {
			return fmt.Errorf("ip rule fwmark: %w", err)
		}
		if _, err := m.r.Run(ctx, "sh", "-c", "ip route show table "+tproxyTable+" | grep -q 'local default' || ip route add local default dev lo table "+tproxyTable); err != nil {
			return fmt.Errorf("ip route local: %w", err)
		}
		m.udpOn = true
	}
	return nil
}

func (m *RuleMgr) disableUDP(ctx context.Context) {
	_, _ = m.r.Run(ctx, "iptables", "-t", "mangle", "-F", clashUDPChain)
	_, _ = m.r.Run(ctx, "iptables", "-t", "mangle", "-D", "PREROUTING", "-j", clashUDPChain)
	_, _ = m.r.Run(ctx, "iptables", "-t", "mangle", "-X", clashUDPChain)
	_, _ = m.r.Run(ctx, "sh", "-c", "ip rule show | grep -q 'fwmark 0x1/0x1' && while ip rule del fwmark 0x1/0x1 table "+tproxyTable+" 2>/dev/null; do :; done; true")
	_, _ = m.r.Run(ctx, "sh", "-c", "ip route show table "+tproxyTable+" | grep -q 'local default' && ip route del local default dev lo table "+tproxyTable+"; true")
	m.udpOn = false
}

// Cleanup 完全拆除（stop/uninstall 兜底）。
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
	try("-t", "nat", "-D", "PREROUTING", "-j", clashDNSChain)
	try("-t", "nat", "-D", "PREROUTING", "-j", clashTCPChain)
	for _, pair := range [][2]string{{"filter", fwdChain}, {"nat", natChain}, {"nat", clashDNSChain}, {"nat", clashTCPChain}} {
		try("-t", pair[0], "-F", pair[1])
		try("-t", pair[0], "-X", pair[1])
	}
	// UDP 侧尽力拆除（无论 udpOn）
	_, _ = m.r.Run(ctx, "iptables", "-t", "mangle", "-D", "PREROUTING", "-j", clashUDPChain)
	_, _ = m.r.Run(ctx, "iptables", "-t", "mangle", "-F", clashUDPChain)
	_, _ = m.r.Run(ctx, "iptables", "-t", "mangle", "-X", clashUDPChain)
	_, _ = m.r.Run(ctx, "sh", "-c", "while ip rule del fwmark 0x1/0x1 table "+tproxyTable+" 2>/dev/null; do :; done; true")
	_, _ = m.r.Run(ctx, "sh", "-c", "ip route del local default dev lo table "+tproxyTable+" 2>/dev/null; true")
	m.direct, m.masqSet, m.clash = map[string]bool{}, map[string]bool{}, map[string]bool{}
	m.udpOn, m.hooked = false, false
	return firstErr
}

func toSet(ips []string) map[string]bool {
	out := make(map[string]bool, len(ips))
	for _, ip := range ips {
		out[ip] = true
	}
	return out
}
