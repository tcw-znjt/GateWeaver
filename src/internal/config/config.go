// Package config 定义 GateWeaver 的持久化配置与原子存储（JSON + rename + fsync）。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
)

// ForwardMode 上游送达模式
type ForwardMode string

const (
	ModeRoute ForwardMode = "route"      // 直连路由：保留源 IP
	ModeMasq  ForwardMode = "masquerade" // 地址伪装
)

// Target 一个接管目标。MAC 为主键（IP 可能因 DHCP 变化）。
type Target struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Iface    string `json:"iface"`
	Enabled  bool   `json:"enabled"`
	ViaClash bool   `json:"via_clash"` // true=流量改道 Clash；false=直连转发（原方案）
	Note     string `json:"note,omitempty"`
}

// Config 全局配置。
type Config struct {
	// 版本与授权
	Version       int  `json:"version"`
	LicensedAck   bool `json:"licensed_ack"` // 首次授权确认（safety spec）

	// 上游
	GatewayIP       string `json:"gateway_ip"`       // 空 = 自动探测（默认路由）
	GatewayMACFixed string `json:"gateway_mac_fixed"` // 空 = 自动学习
	FailOpenOnUpstreamDown bool `json:"fail_open"`    // 上游故障自动放开（默认 true）

	// 接管
	InjectIntervalSec int `json:"inject_interval_sec"` // 周期重申间隔
	InjectRatePerSec  int `json:"inject_rate_per_sec"` // 每目标限速（帧/秒）
	GlobalEnabled     bool `json:"global_enabled"`     // 全局开关

	// 转发
	ForwardMode ForwardMode `json:"forward_mode"` // route | masquerade

	// Clash 引流（Clash 为独立应用，本应用只改道流量）
	ClashEnabled    bool   `json:"clash_enabled"`
	ClashAddr       string `json:"clash_addr"`       // 空 = 本机 REDIRECT；否则 DNAT/TPROXY 到该 IP（如 Docker bridge 容器）
	ClashTCPPort    int    `json:"clash_tcp_port"`   // Clash redir-port
	ClashDNSPort    int    `json:"clash_dns_port"`   // Clash dns.listen 端口
	ClashUDPPort    int    `json:"clash_udp_port"`   // Clash tproxy-port，0 = 关闭 UDP 改道
	ClashFailDirect bool   `json:"clash_fail_direct"` // Clash 不可达时自动降级直连（默认开）

	// 管理台
	ListenAddrs []string `json:"listen_addrs"` // 默认 ["127.0.0.1:9666"]
	Port        int      `json:"port"`
	PasswordHash string  `json:"password_hash,omitempty"` // scrypt hex（salt$hash）
	PasswordSet  bool    `json:"password_set"`

	// 目标列表
	Targets []Target `json:"targets"`
}

// Default 返回安全默认值。
func Default() *Config {
	return &Config{
		Version:                1,
		FailOpenOnUpstreamDown: true,
		InjectIntervalSec:      20,
		InjectRatePerSec:       2,
		ForwardMode:            ModeRoute,
		ClashTCPPort:           7893,
		ClashDNSPort:           7874,
		ClashUDPPort:           0,
		ClashFailDirect:        true,
		Port:                   9666,
		ListenAddrs:            []string{"127.0.0.1", "auto"}, // auto = 全部非回环 IPv4（LAN）接口地址
	}
}

// Validate 做加载后与保存前的语义校验（对应 management-console spec 的非法输入拒绝）。
// reject 为已存在的目标 MAC 集合，用于网关排除校验。
func (c *Config) Validate(gwIP netip.Addr) error {
	if c.InjectIntervalSec < 1 || c.InjectIntervalSec > 3600 {
		return errors.New("inject_interval_sec out of range 1..3600")
	}
	if c.InjectRatePerSec < 1 || c.InjectRatePerSec > 10 {
		return errors.New("inject_rate_per_sec out of range 1..10")
	}
	switch c.ForwardMode {
	case ModeRoute, ModeMasq:
	default:
		return fmt.Errorf("unknown forward mode %q", c.ForwardMode)
	}
	if c.Port < 1 || c.Port > 65535 {
		return errors.New("bad port")
	}
	if c.ClashAddr != "" {
		if a, err := netip.ParseAddr(c.ClashAddr); err != nil || !a.Is4() {
			return fmt.Errorf("clash_addr %q must be an IPv4", c.ClashAddr)
		}
	}
	if c.ClashEnabled {
		if c.ClashTCPPort < 1 || c.ClashTCPPort > 65535 {
			return errors.New("clash_tcp_port out of range")
		}
		if c.ClashDNSPort < 1 || c.ClashDNSPort > 65535 {
			return errors.New("clash_dns_port out of range")
		}
		if c.ClashUDPPort < 0 || c.ClashUDPPort > 65535 {
			return errors.New("clash_udp_port out of range")
		}
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		if _, err := netip.ParseAddr(t.IP); err != nil {
			return fmt.Errorf("target %s: bad ip %q", t.MAC, t.IP)
		}
		if _, err := net.ParseMAC(t.MAC); err != nil {
			return fmt.Errorf("target %s: bad mac", t.MAC)
		}
		if gwIP.IsValid() && t.IP == gwIP.String() {
			return fmt.Errorf("target %s: gateway address cannot be a target", t.MAC)
		}
		if seen[t.MAC] {
			return fmt.Errorf("duplicate target mac %s", t.MAC)
		}
		seen[t.MAC] = true
	}
	return nil
}

// Store 是并发安全的配置存取器。
type Store struct {
	mu   sync.Mutex
	path string
	data *Config
}

// Load 读取配置文件；文件不存在时返回默认配置（尚未落盘）。
func Load(path string) (*Store, error) {
	s := &Store{path: path, data: Default()}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config %s corrupted: %w", path, err)
	}
	if c.ListenAddrs == nil {
		c.ListenAddrs = Default().ListenAddrs
	}
	if c.Version == 0 {
		c.Version = 1
	}
	s.data = &c
	return s, nil
}

// Path 返回配置文件路径。
func (s *Store) Path() string { return s.path }

// Snapshot 返回深拷贝（调用方自由使用）。
func (s *Store) Snapshot() *Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.data
	cp.Targets = append([]Target(nil), s.data.Targets...)
	cp.ListenAddrs = append([]string(nil), s.data.ListenAddrs...)
	return &cp
}

// Update 以 cb 修改配置并原子落盘；失败则不变更内存。
func (s *Store) Update(gwIP netip.Addr, cb func(*Config) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.data
	cp.Targets = append([]Target(nil), s.data.Targets...)
	cp.ListenAddrs = append([]string(nil), s.data.ListenAddrs...)
	if err := cb(&cp); err != nil {
		return err
	}
	if err := cp.Validate(gwIP); err != nil {
		return err
	}
	if err := s.writeLocked(&cp); err != nil {
		return err
	}
	s.data = &cp
	return nil
}

// writeLocked 原子写：tmp → fsync → rename → fsync(dir)。
func (s *Store) writeLocked(c *Config) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(s.path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
