// Package discover 局域网设备发现与上游网关探测：解析 `ip neigh` / `ip route`，
// 可选有界主动探测。所有命令经 Runner 注入，逻辑纯函数可单测。
package discover

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"gateweaver/internal/fwd"
)

// Entry 一条邻居记录。
type Entry struct {
	IP    string `json:"ip"`
	MAC   string `json:"mac"`
	Iface string `json:"iface"`
	State string `json:"state"` // REACHABLE/STALE/...
}

// ParseNeigh 解析 `ip neigh show` 输出。
func ParseNeigh(out string) []Entry {
	var list []Entry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		ip, err := netip.ParseAddr(fields[0])
		if err != nil || !ip.Is4() {
			continue
		}
		e := Entry{IP: fields[0]}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if i+1 < len(fields) {
					e.Iface = fields[i+1]
				}
			case "lladdr":
				if i+1 < len(fields) {
					e.MAC = fields[i+1]
				}
			case "FAILED", "INCOMPLETE", "STALE", "REACHABLE", "DELAY", "PROBE":
				e.State = fields[i]
			}
		}
		if e.MAC != "" && e.Iface != "" {
			list = append(list, e)
		}
	}
	return list
}

// ParseDefaultRoute 从 `ip route show default` 输出取 (gwIP, dev)。
func ParseDefaultRoute(out string) (gw string, dev string, err error) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "default" {
			continue
		}
		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "via":
				if i+1 < len(fields) {
					gw = fields[i+1]
				}
			case "dev":
				if i+1 < len(fields) {
					dev = fields[i+1]
				}
			}
		}
		if gw != "" {
			return gw, dev, nil
		}
	}
	return "", "", fmt.Errorf("discover: no default route")
}

// Scanner 使用外部命令的发现器。
type Scanner struct {
	r fwd.Runner
}

func NewScanner(r fwd.Runner) *Scanner { return &Scanner{r: r} }

// Neighbors 返回内核邻居表条目。
func (s *Scanner) Neighbors(ctx context.Context) ([]Entry, error) {
	out, err := s.r.Run(ctx, "ip", "neigh", "show")
	if err != nil {
		return nil, err
	}
	return ParseNeigh(string(out)), nil
}

// DefaultGateway 返回 (gwIP, dev)。
func (s *Scanner) DefaultGateway(ctx context.Context) (string, string, error) {
	out, err := s.r.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		return "", "", err
	}
	return ParseDefaultRoute(string(out))
}

// ProbeSubnet 对 IPv4 CIDR 做有界 ping 扫描（并发 ≤16，单 host 超时 300ms），
// 返回响应 IP 集合。用于补全 ARP 表未覆盖的活跃主机。
func (s *Scanner) ProbeSubnet(ctx context.Context, cidr string) ([]string, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil || !prefix.Addr().Is4() {
		return nil, fmt.Errorf("discover: bad cidr %q", cidr)
	}
	if prefix.Bits() < 22 {
		return nil, fmt.Errorf("discover: cidr %s too large (min /22)", cidr)
	}
	n := 1 << (32 - prefix.Bits())
	var addrs []string
	base := prefix.Masked().Addr()
	u := binary.BigEndian.Uint32(base.AsSlice())
	for i := 1; i < n-1; i++ {
		v := u + uint32(i)
		a := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		if prefix.Contains(a) {
			addrs = append(addrs, a.String())
		}
	}
	var (
		mu    sync.Mutex
		live  []string
		sem   = make(chan struct{}, 16)
		wg    sync.WaitGroup
	)
	for _, ip := range addrs {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			cctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
			defer cancel()
			if _, err := s.r.Run(cctx, "ping", "-c", "1", "-W", "1", ip); err == nil {
				mu.Lock()
				live = append(live, ip)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	return live, nil
}
