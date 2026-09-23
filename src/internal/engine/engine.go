// Package engine 实现 ARP 网关接管引擎：白名单目标注入、维持、被动应答、恢复与状态观测。
// 行为契约见 specs/arp-gateway-takeover。所有二层收发经由 neti.Transceiver，可注入 fake 做单测。
package engine

import (
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"gateweaver/internal/arpframe"
	"gateweaver/internal/auditlog"
	"gateweaver/internal/config"
	"gateweaver/internal/neti"
)

// 目标状态机（management-console spec 的状态总览使用）
const (
	StateDisabled  = "disabled"   // 未启用（禁用/全局关/未授权）
	StateInjecting = "injecting"  // 注入中，尚未观测到网关方向流量
	StateActive    = "active"     // 已生效：观测到目标→fnOS 的转发流量
	StateNoTraffic = "no_traffic" // 持续注入但长时间未见流量（疑似静态 ARP/防护）
)

// TargetStatus 单目标运行态快照。
type TargetStatus struct {
	MAC        string    `json:"mac"`
	IP         string    `json:"ip"`
	Iface      string    `json:"iface"`
	State      string    `json:"state"`
	LastInject time.Time `json:"last_inject,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
	SeenPkts   int64     `json:"seen_pkts"`
	SeenBytes  int64     `json:"seen_bytes"`
}

// GatewayProbe 解析上游网关真实 MAC（Linux 实现探测内核邻居表；单测注入 fake）。
type GatewayProbe func(iface string, gw netip.Addr) (arpframe.MAC, error)

// Params 引擎运行参数（来自主配置的投影）。
type Params struct {
	GatewayIP  netip.Addr
	Interval   time.Duration
	RatePerSec int
	Licensed   bool
	GlobalOn   bool
	GwMACFixed arpframe.MAC // 非零则不探测，直接使用
}

type targetRT struct {
	mac       arpframe.MAC
	ip        netip.Addr
	iface     string
	enabled   bool
	running   bool
	done      chan struct{}
	state     string
	lastInject time.Time
	lastSeen   time.Time
	seenPkts  int64
	seenBytes int64
	history   []time.Time // 限速滑动窗口
}

type ifaceRT struct {
	tr  neti.Transceiver
	mac arpframe.MAC
}

// Engine 接管引擎。全局单实例由 main 的进程锁保证。
type Engine struct {
	mu      sync.Mutex
	factory neti.TransceiverFactory
	probe   GatewayProbe
	log     *auditlog.Logger
	params  Params
	targets map[string]*targetRT // key: 规范化小写 MAC
	ifaces  map[string]*ifaceRT
	gwMAC   arpframe.MAC
	gwMACOK bool
	stopped bool
	now     func() time.Time
}

// New 创建引擎。factory 在目标首次启用时按接口懒创建收发器。
func New(factory neti.TransceiverFactory, probe GatewayProbe, log *auditlog.Logger) *Engine {
	return &Engine{
		factory: factory,
		probe:   probe,
		log:     log,
		targets: map[string]*targetRT{},
		ifaces:  map[string]*ifaceRT{},
		now:     time.Now,
	}
}

// Configure 应用运行参数。网关变更时失效缓存的真实 MAC。
func (e *Engine) Configure(p Params) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !p.GatewayIP.Is4() {
		return fmt.Errorf("engine: gateway %s must be a valid IPv4", p.GatewayIP)
	}
	if e.params.GatewayIP != p.GatewayIP {
		e.gwMAC, e.gwMACOK = arpframe.MAC{}, false
	}
	e.params = p
	if !p.GwMACFixed.IsZero() {
		e.gwMAC, e.gwMACOK = p.GwMACFixed, true
	}
	return nil
}

// ApplyTargets 同步目标集合（增/删/改/启停）。被移除或禁用的目标会被恢复。
func (e *Engine) ApplyTargets(targets []config.Target) error {
	e.mu.Lock()
	incoming := map[string]*targetRT{}
	for _, t := range targets {
		mac, err := arpframe.ParseMAC(t.MAC)
		if err != nil {
			e.mu.Unlock()
			return fmt.Errorf("engine: target %q bad mac: %w", t.MAC, err)
		}
		ip, err := netip.ParseAddr(t.IP)
		if err != nil {
			e.mu.Unlock()
			return fmt.Errorf("engine: target %q bad ip: %w", t.MAC, err)
		}
		if ip == e.params.GatewayIP {
			e.mu.Unlock()
			return fmt.Errorf("engine: refusing gateway %s as target", ip)
		}
		key := mac.String()
		rt, ok := e.targets[key]
		if !ok {
			rt = &targetRT{mac: mac, ip: ip, iface: t.Iface, state: StateDisabled}
			e.targets[key] = rt
		}
		rt.ip, rt.iface, rt.enabled = ip, t.Iface, t.Enabled
		incoming[key] = rt
	}
	// 移除的目标：先恢复通告，再停循环
	for key, rt := range e.targets {
		if _, ok := incoming[key]; !ok {
			if rt.running {
				e.restoreTargetLocked(rt)
			}
			e.stopTargetLocked(rt)
			delete(e.targets, key)
		}
	}
	// 启停处理
	var startErr error
	for key, rt := range incoming {
		if rt.enabled {
			if err := e.startTargetLocked(rt); err != nil {
				startErr = fmt.Errorf("engine: start target %s: %w", key, err)
				break
			}
		} else {
			if rt.running {
				e.restoreTargetLocked(rt)
				e.stopTargetLocked(rt)
			}
			rt.state = StateDisabled
		}
	}
	e.mu.Unlock()
	return startErr
}

// RestoreAll 撤销所有目标接管但保留配置（一键恢复/全局关闭/上游故障 fail-open）。
func (e *Engine) RestoreAll(reason string) {
	e.mu.Lock()
	for _, rt := range e.targets {
		if rt.running {
			e.restoreTargetLocked(rt)
			e.stopTargetLocked(rt)
		}
		rt.state = StateDisabled
	}
	e.eventLocked("restore", "system", "", "全部恢复: %s", reason)
	e.mu.Unlock()
}

// Stop 停止引擎：恢复全部接管并释放资源。
func (e *Engine) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped {
		return
	}
	e.stopped = true
	for _, rt := range e.targets {
		e.stopTargetLocked(rt)
	}
	for name, ift := range e.ifaces {
		_ = ift.tr.Close() // 解除 Next 阻塞 → 读循环退出
		delete(e.ifaces, name)
	}
}

// Status 返回全部目标状态快照（按 MAC 排序，稳定输出）。
func (e *Engine) Status() []TargetStatus {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]TargetStatus, 0, len(e.targets))
	for _, rt := range e.targets {
		st := rt.state
		if !rt.enabled || !e.canInjectLocked() {
			st = StateDisabled
		} else if st == StateActive && e.now().Sub(rt.lastSeen) > e.silenceWindowLocked() {
			st = StateNoTraffic
		}
		out = append(out, TargetStatus{
			MAC: rt.mac.String(), IP: rt.ip.String(), Iface: rt.iface, State: st,
			LastInject: rt.lastInject, LastSeen: rt.lastSeen,
			SeenPkts: rt.seenPkts, SeenBytes: rt.seenBytes,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].MAC < out[j].MAC })
	return out
}

// GatewayMAC 返回当前缓存的网关 MAC 与是否已知。
func (e *Engine) GatewayMAC() (arpframe.MAC, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.gwMAC, e.gwMACOK
}

// ResolveGatewayMAC 探测/复核网关真实 MAC（供健康探测与启动路径调用）。
func (e *Engine) ResolveGatewayMAC() {
	e.mu.Lock()
	gw := e.params.GatewayIP
	var ifaceName string
	for name := range e.ifaces {
		ifaceName = name
		break
	}
	probe, ok := e.probe, e.gwMACOK
	e.mu.Unlock()
	if ok || probe == nil || ifaceName == "" {
		return
	}
	mac, err := probe(ifaceName, gw)
	if err != nil {
		e.mu.Lock()
		e.eventLocked("error", "system", "", "网关 %s MAC 探测失败: %v", gw, err)
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	if !e.gwMACOK || e.gwMAC != mac {
		e.gwMAC, e.gwMACOK = mac, true
		e.eventLocked("takeover", "system", "", "网关真实 MAC: %s", mac)
	}
	e.mu.Unlock()
}

// --- 内部（调用方持锁） ---

func (e *Engine) canInjectLocked() bool {
	return e.params.Licensed && e.params.GlobalOn && !e.stopped
}

func (e *Engine) silenceWindowLocked() time.Duration {
	w := 5 * e.params.Interval
	if w < 60*time.Second {
		w = 60 * time.Second
	}
	return w
}

func (e *Engine) eventLocked(kind, actor, target, format string, args ...any) {
	// Log 自身有锁；此处不回调引擎锁
	if e.log != nil {
		e.log.Log(kind, actor, target, fmt.Sprintf(format, args...))
	}
}

func (e *Engine) ensureIfaceLocked(name string) (*ifaceRT, error) {
	if ift, ok := e.ifaces[name]; ok {
		return ift, nil
	}
	tr, err := e.factory(name)
	if err != nil {
		return nil, err
	}
	ift := &ifaceRT{tr: tr, mac: tr.HardwareAddr()}
	e.ifaces[name] = ift
	go e.readLoop(ift)
	e.eventLocked("takeover", "system", "", "attach 接口 %s (本机 MAC %s)", name, ift.mac)
	return ift, nil
}

func (e *Engine) startTargetLocked(rt *targetRT) error {
	ift, err := e.ensureIfaceLocked(rt.iface)
	if err != nil {
		return err
	}
	_ = ift
	if !rt.running {
		rt.running = true
		rt.done = make(chan struct{})
		rt.state = StateInjecting
		go e.injectLoop(rt, rt.done)
	}
	if !e.gwMACOK {
		go e.ResolveGatewayMAC()
	}
	return nil
}

func (e *Engine) stopTargetLocked(rt *targetRT) {
	if rt.running {
		close(rt.done)
		rt.running = false
		rt.done = nil
	}
	rt.state = StateDisabled
}

// injectLoop 单目标周期重申循环（启动即发一次）。
func (e *Engine) injectLoop(rt *targetRT, done chan struct{}) {
	for {
		e.injectOnce(rt)
		e.mu.Lock()
		interval := e.params.Interval
		e.mu.Unlock()
		if interval <= 0 {
			interval = 20 * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-done:
			timer.Stop()
			return
		case <-timer.C:
			timer.Stop()
		}
	}
}

// injectOnce 向单个目标单播一条伪造 reply（网关 IP → 本机 MAC）。
// 返回是否实际发出（受全局开关/授权/限速约束）。
func (e *Engine) injectOnce(rt *targetRT) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopped || !rt.enabled || !e.canInjectLocked() {
		return false
	}
	ift, ok := e.ifaces[rt.iface]
	if !ok {
		return false
	}
	if !e.allowRateLocked(rt) {
		return false
	}
	frame, err := arpframe.Encode(arpframe.Packet{
		SrcMAC: ift.mac, DstMAC: rt.mac, Op: arpframe.ARPReply,
		Sender: e.params.GatewayIP, SenderMAC: ift.mac,
		Target: rt.ip, TgtMAC: rt.mac,
	})
	if err != nil {
		e.eventLocked("error", "system", rt.mac.String(), "encode inject: %v", err)
		return false
	}
	if err := ift.tr.Send(frame); err != nil {
		e.eventLocked("error", "system", rt.mac.String(), "send inject: %v", err)
		return false
	}
	rt.lastInject = e.now()
	return true
}

// allowRateLocked 滑动窗口限速：任意 1s 内每目标注入帧 ≤ RatePerSec（spec：速率受控）。
func (e *Engine) allowRateLocked(rt *targetRT) bool {
	limit := e.params.RatePerSec
	if limit <= 0 {
		limit = 2
	}
	now := e.now()
	cut := rt.history[:0]
	for _, t := range rt.history {
		if now.Sub(t) < time.Second {
			cut = append(cut, t)
		}
	}
	rt.history = append(cut, now)
	return len(rt.history) <= limit
}

// restoreTargetLocked 恢复通告：网关 IP → 真实网关 MAC，单播立即 + 1s 双发。
// 网关 MAC 未知时记录错误（目标随 ARP 老化自回正，fail-open 语义）。
func (e *Engine) restoreTargetLocked(rt *targetRT) {
	ift, ok := e.ifaces[rt.iface]
	if !ok {
		return
	}
	if !e.gwMACOK {
		e.eventLocked("error", "system", rt.mac.String(), "恢复通告缺网关 MAC，等待目标 ARP 老化自回正")
		return
	}
	frame, err := arpframe.Encode(arpframe.Packet{
		SrcMAC: ift.mac, DstMAC: rt.mac, Op: arpframe.ARPReply,
		Sender: e.params.GatewayIP, SenderMAC: e.gwMAC,
		Target: rt.ip, TgtMAC: rt.mac,
	})
	if err != nil {
		e.eventLocked("error", "system", rt.mac.String(), "encode restore: %v", err)
		return
	}
	_ = ift.tr.Send(frame)
	e.eventLocked("restore", "system", rt.mac.String(), "恢复通告已发送")
	go func(iface string, dst string) {
		time.Sleep(time.Second)
		e.mu.Lock()
		defer e.mu.Unlock()
		ift2, ok := e.ifaces[iface]
		rt2, known := e.targets[dst]
		if ok && known && !rt2.running {
			_ = ift2.tr.Send(frame)
		}
	}(rt.iface, rt.mac.String())
}

// readLoop 单接口读循环：被动应答 + 流量观测（接管生效判定，spec 2.6）。
func (e *Engine) readLoop(ift *ifaceRT) {
	for {
		frame, err := ift.tr.Next()
		if err != nil {
			e.mu.Lock()
			_, alive := e.ifaces[ift.tr.Iface()]
			stopped := e.stopped
			e.mu.Unlock()
			if stopped || !alive {
				return
			}
			time.Sleep(50 * time.Millisecond)
			continue
		}
		e.handleFrame(ift, frame)
	}
}

func (e *Engine) handleFrame(ift *ifaceRT, frame []byte) {
	switch arpframe.Ethertype(frame) {
	case arpframe.EtherTypeARP:
		p, err := arpframe.Decode(frame)
		if err != nil {
			return
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		rt, known := e.targets[p.SenderMAC.String()]
		// 1) 被动应答：仅白名单启用目标查询网关；自伤/自环排除（p.SenderMAC == 网关 MAC 不答）
		if known && rt.running && rt.enabled && p.IsWhoHas(e.params.GatewayIP) &&
			e.canInjectLocked() && p.SenderMAC != e.gwMAC {
			if e.allowRateLocked(rt) {
				reply, err := arpframe.Encode(arpframe.Packet{
					SrcMAC: ift.mac, DstMAC: p.SenderMAC, Op: arpframe.ARPReply,
					Sender: e.params.GatewayIP, SenderMAC: ift.mac,
					Target: p.Sender, TgtMAC: p.SenderMAC,
				})
				if err == nil {
					_ = ift.tr.Send(reply)
					rt.lastInject = e.now()
				}
			}
			return
		}
		// 2) 网关自身 reply 顺带学习真实映射（仅当未知时）
		if p.Op == arpframe.ARPReply && p.Sender == e.params.GatewayIP && !e.gwMACOK {
			e.gwMAC, e.gwMACOK = p.SenderMAC, true
		}
	case arpframe.EtherTypeIPv4:
		src, ok1 := arpframe.SrcMACOf(frame)
		dst, ok2 := arpframe.DstMACOf(frame)
		if !ok1 || !ok2 || dst != ift.mac {
			return
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		if rt, known := e.targets[src.String()]; known && rt.enabled {
			rt.seenPkts++
			rt.seenBytes += int64(len(frame))
			rt.lastSeen = e.now()
			rt.state = StateActive
		}
	}
}
