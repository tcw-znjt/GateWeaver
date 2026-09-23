// Package probe 解析上游网关真实 MAC：触发内核邻居解析后读取 `ip neigh`。
// 通过 Runner 注入命令，Windows 单测可验证解析逻辑；Linux 上即真实行为。
package probe

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"gateweaver/internal/arpframe"
	"gateweaver/internal/discover"
	"gateweaver/internal/fwd"
)

// Resolver 网关 MAC 解析器。
type Resolver struct {
	r fwd.Runner
}

func New(r fwd.Runner) *Resolver { return &Resolver{r: r} }

// Resolve 触发（ping）并读取网关 MAC。iface 保留给未来按接口过滤。
func (res *Resolver) Resolve(iface string, gw netip.Addr) (arpframe.MAC, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// 触发内核 ARP 解析（失败也继续：可能只回 RA/不可 ping 但二层可达）
	_, _ = res.r.Run(ctx, "ping", "-c", "1", "-W", "1", gw.String())
	out, err := res.r.Run(ctx, "ip", "neigh", "show", gw.String())
	if err != nil {
		return arpframe.MAC{}, err
	}
	entries := discover.ParseNeigh(string(out))
	for _, e := range entries {
		if e.IP == gw.String() && e.MAC != "" && e.State != "FAILED" && e.State != "INCOMPLETE" {
			return arpframe.ParseMAC(e.MAC)
		}
	}
	return arpframe.MAC{}, fmt.Errorf("probe: gateway %s not in neighbour table", gw)
}

// DefaultRoute 返回 (gwIP, dev)。
func (res *Resolver) DefaultRoute() (netip.Addr, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := res.r.Run(ctx, "ip", "route", "show", "default")
	if err != nil {
		return netip.Addr{}, "", err
	}
	gw, dev, err := discover.ParseDefaultRoute(string(out))
	if err != nil {
		return netip.Addr{}, "", err
	}
	a, err := netip.ParseAddr(gw)
	return a, dev, err
}

// IfaceInfo 接口的二层/三层信息（MAC 即目标设备被接管后学到的"网关 MAC"）。
type IfaceInfo struct {
	MAC   string         `json:"mac"`
	Addrs []netip.Prefix `json:"addrs"`
}

// Addrs 返回接口名 → {MAC, IPv4 前缀列表}（管理台展示本机接管接口 MAC 与选择监听地址）。
func (res *Resolver) Addrs() (map[string]IfaceInfo, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	outAddr, err := res.r.Run(ctx, "ip", "-o", "addr", "show")
	if err != nil {
		return nil, err
	}
	byIface, _ := parseAddrShow(string(outAddr))
	out := make(map[string]IfaceInfo, len(byIface))
	for iface, ps := range byIface {
		out[iface] = IfaceInfo{Addrs: ps}
	}
	// link 信息尽力而为：失败不致命（仅缺 MAC）
	if outLink, err := res.r.Run(ctx, "ip", "-o", "link", "show"); err == nil {
		for iface, mac := range parseLinkShow(string(outLink)) {
			info := out[iface]
			info.MAC = mac
			out[iface] = info
		}
	}
	return out, nil
}

// parseLinkShow 解析 `ip -o link show` 行：
// "2: eth0: <BROADCAST,...> mtu 1500 ... link/ether aa:bb:cc:dd:ee:ff brd ..."
func parseLinkShow(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		iface := strings.TrimSuffix(fields[1], ":")
		for i, f := range fields {
			if f == "link/ether" && i+1 < len(fields) {
				res[iface] = fields[i+1]
				break
			}
		}
	}
	return res
}

// parseAddrShow 解析 `ip -o addr show` 行：
// "2: eth0    inet 192.168.1.10/24 brd ... scope global eth0"
func parseAddrShow(out string) (map[string][]netip.Prefix, error) {
	res := map[string][]netip.Prefix{}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "inet" {
			continue
		}
		iface := fields[1]
		p, err := netip.ParsePrefix(fields[3])
		if err != nil {
			continue
		}
		res[iface] = append(res[iface], p)
	}
	return res, nil
}
