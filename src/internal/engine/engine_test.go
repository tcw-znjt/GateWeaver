package engine

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"gateweaver/internal/arpframe"
	"gateweaver/internal/config"
	"gateweaver/internal/neti"
)

// --- fake transport ---

type fakeNet struct {
	mu    sync.Mutex
	name  string
	mac   arpframe.MAC
	sent  [][]byte
	in    chan []byte
	closed bool
}

func (f *fakeNet) Iface() string              { return f.name }
func (f *fakeNet) HardwareAddr() arpframe.MAC { return f.mac }
func (f *fakeNet) Send(b []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	cp := append([]byte(nil), b...)
	f.sent = append(f.sent, cp)
	return nil
}
func (f *fakeNet) Next() ([]byte, error) {
	b, ok := <-f.in
	if !ok {
		return nil, errors.New("closed")
	}
	return b, nil
}
func (f *fakeNet) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		f.closed = true
		close(f.in)
	}
	return nil
}
func (f *fakeNet) sentFrames() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([][]byte(nil), f.sent...)
}
func (f *fakeNet) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = nil
}

func newFakeEngine(t *testing.T, fn *fakeNet) *Engine {
	t.Helper()
	factory := func(iface string) (neti.Transceiver, error) {
		if iface == fn.name {
			return fn, nil
		}
		return nil, fmt.Errorf("unknown iface %s", iface)
	}
	probe := func(iface string, gw netip.Addr) (arpframe.MAC, error) { return gwMAC, nil }
	e := New(factory, probe, nil)
	return e
}

var (
	gwIP     = netip.MustParseAddr("192.168.1.1")
	gwMAC, _ = arpframe.ParseMAC("de:ad:be:ef:00:01")
	myMAC, _ = arpframe.ParseMAC("aa:aa:aa:aa:aa:01")
	tgtMAC, _ = arpframe.ParseMAC("bb:bb:bb:bb:bb:02")
	tgtIP    = netip.MustParseAddr("192.168.1.50")
	othMAC, _ = arpframe.ParseMAC("cc:cc:cc:cc:cc:03")
	othIP    = netip.MustParseAddr("192.168.1.51")
)

func mustTargetParams() Params {
	return Params{
		GatewayIP: gwIP, Interval: 50 * time.Millisecond, RatePerSec: 5,
		Licensed: true, GlobalOn: true, GwMACFixed: gwMAC,
	}
}

func target(mac arpframe.MAC, ip netip.Addr, enabled bool) config.Target {
	return config.Target{MAC: mac.String(), IP: ip.String(), Iface: "eth0", Enabled: enabled}
}

func whoHas(srcMAC arpframe.MAC, srcIP, want netip.Addr) []byte {
	f, err := arpframe.Encode(arpframe.Packet{
		SrcMAC: srcMAC, DstMAC: arpframe.MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Op: arpframe.ARPRequest, Sender: srcIP, SenderMAC: srcMAC, Target: want,
	})
	if err != nil {
		panic(err)
	}
	return f
}

func ipv4From(srcMAC, dstMAC arpframe.MAC) []byte {
	f := make([]byte, 60)
	copy(f[0:6], dstMAC[:])
	copy(f[6:12], srcMAC[:])
	f[12], f[13] = 0x08, 0x00
	return f
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", msg)
}

func decodeSent(t *testing.T, fn *fakeNet) []arpframe.Packet {
	t.Helper()
	var out []arpframe.Packet
	for _, f := range fn.sentFrames() {
		if arpframe.Ethertype(f) != arpframe.EtherTypeARP {
			continue
		}
		p, err := arpframe.Decode(f)
		if err != nil {
			t.Fatalf("sent malformed frame: %v", err)
		}
		out = append(out, p)
	}
	return out
}

// --- tests ---

// 2.3 白名单外零发包 + 周期重申
func TestPeriodicInjectOnlyTargets(t *testing.T) {
	fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 16)}
	e := newFakeEngine(t, fn)
	if err := e.Configure(mustTargetParams()); err != nil {
		t.Fatal(err)
	}
	if err := e.ApplyTargets([]config.Target{target(tgtMAC, tgtIP, true), target(othMAC, othIP, false)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, time.Second, func() bool { return len(decodeSent(t, fn)) >= 2 }, "periodic inject")
	e.Stop()
	for _, p := range decodeSent(t, fn) {
		if p.DstMAC != tgtMAC {
			t.Fatalf("frame sent to non-target %s", p.DstMAC)
		}
		if p.Op != arpframe.ARPReply || p.Sender != gwIP || p.SenderMAC != myMAC {
			t.Fatalf("frame not a forged gateway reply: %+v", p)
		}
	}
}

// 授权/全局开关门控：未确认或未开启时零注入
func TestNoInjectWithoutLicenseOrGlobal(t *testing.T) {
	for _, p := range []Params{
		func() Params { q := mustTargetParams(); q.Licensed = false; return q }(),
		func() Params { q := mustTargetParams(); q.GlobalOn = false; return q }(),
	} {
		fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 16)}
		e := newFakeEngine(t, fn)
		if err := e.Configure(p); err != nil {
			t.Fatal(err)
		}
		if err := e.ApplyTargets([]config.Target{target(tgtMAC, tgtIP, true)}); err != nil {
			t.Fatal(err)
		}
		// 触发被动应答路径也应被拦截
		fn.in <- whoHas(tgtMAC, tgtIP, gwIP)
		time.Sleep(200 * time.Millisecond)
		if n := len(decodeSent(t, fn)); n != 0 {
			t.Fatalf("licensed=%v global=%v: %d frames sent, want 0", p.Licensed, p.GlobalOn, n)
		}
		e.Stop()
	}
}

// 2.4 被动应答：目标毫秒级应答；非目标与网关自身查询不答
func TestPassiveResponder(t *testing.T) {
	fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 16)}
	e := newFakeEngine(t, fn)
	params := mustTargetParams()
	params.Interval = time.Hour // 关掉周期注入，单独测被动路径
	e.Configure(params)
	e.ApplyTargets([]config.Target{target(tgtMAC, tgtIP, true), target(othMAC, othIP, true)})
	time.Sleep(150 * time.Millisecond) // 等待启动期初始注入完成，再清空
	fn.reset()

	start := time.Now()
	fn.in <- whoHas(tgtMAC, tgtIP, gwIP)
	waitFor(t, 500*time.Millisecond, func() bool { return len(decodeSent(t, fn)) == 1 }, "target who-has reply")
	if d := time.Since(start); d > 200*time.Millisecond {
		t.Fatalf("reply latency %v too high", d)
	}
	p := decodeSent(t, fn)[0]
	if p.Op != arpframe.ARPReply || p.SenderMAC != myMAC || p.DstMAC != tgtMAC || p.Sender != gwIP {
		t.Fatalf("bad passive reply: %+v", p)
	}

	// 非目标与网关自身查询：不应答
	fn.reset()
	fn.in <- whoHas(othMAC, othIP, netip.MustParseAddr("192.168.1.9")) // 查的不是网关
	fn.in <- whoHas(gwMAC, gwIP, gwIP)                                   // 网关自身流量
	time.Sleep(200 * time.Millisecond)
	if n := len(decodeSent(t, fn)); n != 0 {
		t.Fatalf("responder leaked %d frames", n)
	}
	e.Stop()
}

// 速率受控：1s 窗口内每目标 ≤ RatePerSec
func TestRateLimit(t *testing.T) {
	fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 64)}
	e := newFakeEngine(t, fn)
	params := mustTargetParams()
	params.Interval = time.Hour
	params.RatePerSec = 3
	e.Configure(params)
	e.ApplyTargets([]config.Target{target(tgtMAC, tgtIP, true)})
	time.Sleep(150 * time.Millisecond) // 等待启动期初始注入完成
	fn.reset()
	for i := 0; i < 20; i++ {
		fn.in <- whoHas(tgtMAC, tgtIP, gwIP)
	}
	time.Sleep(300 * time.Millisecond)
	if n := len(decodeSent(t, fn)); n > 3 {
		t.Fatalf("rate limit broken: %d frames in window, cap 3", n)
	}
	e.Stop()
}

// 2.5 移除/禁用/全部恢复 → 恢复通告（sha = 真实网关 MAC）
func TestRestoreAnnouncesRealGateway(t *testing.T) {
	fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 16)}
	e := newFakeEngine(t, fn)
	e.Configure(mustTargetParams())
	e.ApplyTargets([]config.Target{target(tgtMAC, tgtIP, true)})
	waitFor(t, time.Second, func() bool { return len(decodeSent(t, fn)) >= 1 }, "inject started")
	fn.reset()

	e.ApplyTargets([]config.Target{}) // 移除
	var restore *arpframe.Packet
	waitFor(t, time.Second, func() bool {
		for i := range decodeSent(t, fn) {
			p := decodeSent(t, fn)[i]
			if p.SenderMAC == gwMAC {
				restore = &p
				return true
			}
		}
		return false
	}, "restore frame")
	if restore.Op != arpframe.ARPReply || restore.Sender != gwIP || restore.DstMAC != tgtMAC {
		t.Fatalf("bad restore frame: %+v", *restore)
	}
	// 恢复后继续注入应停止
	fn.reset()
	time.Sleep(200 * time.Millisecond)
	if n := len(decodeSent(t, fn)); n != 0 {
		t.Fatalf("injection continued after removal: %d frames", n)
	}
	e.Stop()
}

// 2.6 生效判定：观测目标 IPv4 流量到达本机 → active；计数增长
func TestActiveStateViaObservation(t *testing.T) {
	fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 16)}
	e := newFakeEngine(t, fn)
	params := mustTargetParams()
	params.Interval = time.Hour
	e.Configure(params)
	e.ApplyTargets([]config.Target{target(tgtMAC, tgtIP, true)})

	if st := e.Status()[0].State; st != StateInjecting {
		t.Fatalf("initial state %s", st)
	}
	fn.in <- ipv4From(tgtMAC, myMAC)
	fn.in <- ipv4From(tgtMAC, myMAC)
	waitFor(t, time.Second, func() bool {
		st := e.Status()[0]
		return st.State == StateActive && st.SeenPkts == 2
	}, "state active with counters")

	// 非目标流量不计
	fn.in <- ipv4From(othMAC, myMAC)
	if st := e.Status()[0]; st.SeenPkts != 2 {
		t.Fatalf("non-target traffic counted: %d", st.SeenPkts)
	}
	e.Stop()
}

// 网关地址不可作为目标（spec：拒绝非法目标）
func TestGatewayCannotBeTarget(t *testing.T) {
	fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 16)}
	e := newFakeEngine(t, fn)
	e.Configure(mustTargetParams())
	if err := e.ApplyTargets([]config.Target{target(gwMAC, gwIP, true)}); err == nil {
		t.Fatal("expected refusal for gateway target")
	}
	e.Stop()
}

// RestoreAll：恢复全部且保留目标（禁用态）
func TestRestoreAllKeepsConfig(t *testing.T) {
	fn := &fakeNet{name: "eth0", mac: myMAC, in: make(chan []byte, 16)}
	e := newFakeEngine(t, fn)
	e.Configure(mustTargetParams())
	e.ApplyTargets([]config.Target{target(tgtMAC, tgtIP, true)})
	waitFor(t, time.Second, func() bool { return len(decodeSent(t, fn)) >= 1 }, "inject")
	fn.reset()
	e.RestoreAll("test")
	waitFor(t, time.Second, func() bool { return len(decodeSent(t, fn)) >= 1 }, "restore")
	if len(e.Status()) != 1 || e.Status()[0].State != StateDisabled {
		t.Fatalf("targets lost or not disabled after RestoreAll")
	}
	e.Stop()
}
