package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"gateweaver/internal/app"
	"gateweaver/internal/arpframe"
	"gateweaver/internal/auditlog"
	"gateweaver/internal/config"
	"gateweaver/internal/neti"
)

// --- fakes ---

type quietNet struct {
	closed chan struct{}
	once   sync.Once
}

func newQuietNet() *quietNet { return &quietNet{closed: make(chan struct{})} }

func (q *quietNet) Iface() string              { return "eth0" }
func (q *quietNet) HardwareAddr() arpframe.MAC { return arpframe.MAC{2, 2, 2, 2, 2, 2} }
func (q *quietNet) Send(b []byte) error        { return nil }
func (q *quietNet) Next() ([]byte, error) {
	<-q.closed
	return nil, errors.New("closed")
}
func (q *quietNet) Close() error {
	q.once.Do(func() { close(q.closed) })
	return nil
}

type apiRunner struct {
	mu    sync.Mutex
	calls []string
}

func (r *apiRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	line := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, line)
	switch {
	case name == "ip" && strings.Contains(line, "route show default"):
		return []byte("default via 192.168.1.1 dev eth0 proto dhcp\n"), nil
	case name == "ip" && strings.Contains(line, "neigh show"):
		return []byte("192.168.1.1 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE\n192.168.1.77 dev eth0 lladdr 77:77:77:77:77:77 REACHABLE\n"), nil
	case name == "ip" && strings.Contains(line, "addr show"):
		return []byte("1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.168.1.10/24 brd + scope global eth0\n"), nil
	case name == "ip" && strings.Contains(line, "link show"):
		return []byte("1: lo: <LOOPBACK> mtu 65536 state UNKNOWN link/loopback 00:00:00:00:00:00\n2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP link/ether aa:aa:aa:aa:aa:01 brd ff:ff:ff:ff:ff:ff\n"), nil
	case name == "ping" || name == "arping":
		return nil, nil
	default: // iptables / cat / sh -c 等一律成功
		return nil, nil
	}
}

// --- test harness ---

type harness struct {
	srv   *httptest.Server
	token string
	t     *testing.T
}

func newHarness(t *testing.T) (*harness, *config.Store, *app.App) {
	t.Helper()
	dir := t.TempDir()
	store, err := config.Load(dir + "/config.json")
	if err != nil {
		t.Fatal(err)
	}
	alog, err := auditlog.New(dir+"/logs", 5<<20, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { alog.Close() })
	factory := func(iface string) (neti.Transceiver, error) {
		if iface == "eth0" {
			return newQuietNet(), nil
		}
		return nil, fmt.Errorf("no such iface %s", iface)
	}
	a := app.New(store, alog, factory, &apiRunner{})
	if err := a.Start(context.Background()); err != nil {
		t.Fatalf("app start: %v", err)
	}
	t.Cleanup(func() { _ = a.Shutdown(context.Background()) })
	s := NewServer(a, store, alog)
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &harness{srv: ts, t: t}, store, a
}

func (h *harness) call(method, path, token string, body any) (*http.Response, map[string]any) {
	h.t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, h.srv.URL+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func (h *harness) login(t *testing.T, pw string) string {
	t.Helper()
	resp, _ := h.call("POST", "/api/login", "", map[string]string{"password": pw})
	if resp.StatusCode != 200 {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	_, out := h.call("POST", "/api/login", "", map[string]string{"password": pw})
	return out["token"].(string)
}

// 5.1 鉴权与引导流程
func TestAuthFlow(t *testing.T) {
	h, _, _ := newHarness(t)
	// 未鉴权 → 401（management-console spec）
	if resp, _ := h.call("GET", "/api/overview", "", nil); resp.StatusCode != 401 {
		t.Fatalf("want 401, got %d", resp.StatusCode)
	}
	// initial 报告 needs_setup
	_, init := h.call("GET", "/api/initial", "", nil)
	if init["needs_setup"] != true {
		t.Fatalf("needs_setup should be true: %v", init)
	}
	// 设置口令 → 登录
	resp, _ := h.call("POST", "/api/setup", "", map[string]string{"password": "testpass123"})
	if resp.StatusCode != 200 {
		t.Fatalf("setup: %d", resp.StatusCode)
	}
	// 短口令被拒
	h2, _, _ := newHarness(t)
	if resp, _ := h2.call("POST", "/api/setup", "", map[string]string{"password": "short"}); resp.StatusCode != 400 {
		t.Fatal("short password must be rejected")
	}
	// 口令错 → 401
	if resp, _ := h.call("POST", "/api/login", "", map[string]string{"password": "wrong-password"}); resp.StatusCode != 401 {
		t.Fatal("wrong password must 401")
	}
	tok := h.login(t, "testpass123")
	if resp, _ := h.call("GET", "/api/overview", tok, nil); resp.StatusCode != 200 {
		t.Fatalf("authorized overview: %d", resp.StatusCode)
	}
	// setup 只能一次
	if resp, _ := h.call("POST", "/api/setup", "", map[string]string{"password": "another-pass1"}); resp.StatusCode != 403 {
		t.Fatal("second setup must 403")
	}
}

// 5.3 目标 CRUD + 授权门控 + 校验
func TestTargetLifecycle(t *testing.T) {
	h, store, _ := newHarness(t)
	_, _ = h.call("POST", "/api/setup", "", map[string]string{"password": "testpass123"})
	tok := h.login(t, "testpass123")

	// 未确认授权 → 开全局被拒（safety spec）
	resp, _ := h.call("POST", "/api/global", tok, map[string]bool{"enabled": true})
	if resp.StatusCode != 403 {
		t.Fatalf("global before license ack must 403, got %d", resp.StatusCode)
	}
	// 网关 IP 作为目标被拒
	resp, _ = h.call("POST", "/api/targets", tok, config.Target{MAC: "11:22:33:44:55:66", IP: "192.168.1.1", Iface: "eth0"})
	if resp.StatusCode != 400 {
		t.Fatal("gateway target must be rejected")
	}
	// 非法接口
	resp, _ = h.call("POST", "/api/targets", tok, config.Target{MAC: "11:22:33:44:55:66", IP: "192.168.1.60", Iface: "wlan9"})
	if resp.StatusCode != 400 {
		t.Fatal("unknown iface target must be rejected at apply")
	}
	// 合法添加（未启用）
	resp, _ = h.call("POST", "/api/targets", tok, config.Target{MAC: "BB:bb:bb:bb:bb:b2", IP: "192.168.1.60", Iface: "eth0"})
	if resp.StatusCode != 201 {
		t.Fatalf("add target: %d", resp.StatusCode)
	}
	// 重复 MAC 拒绝
	resp, _ = h.call("POST", "/api/targets", tok, config.Target{MAC: "bb:bb:bb:bb:bb:b2", IP: "192.168.1.61", Iface: "eth0"})
	if resp.StatusCode != 400 {
		t.Fatal("duplicate mac (case-insensitive) must be rejected")
	}
	// 授权确认 → 全局开 → 启用目标 → 状态变 injecting
	if resp, _ := h.call("POST", "/api/license/ack", tok, map[string]bool{}); resp.StatusCode != 200 {
		t.Fatal("license ack failed")
	}
	if resp, _ := h.call("PUT", "/api/targets/bb:bb:bb:bb:bb:b2", tok, map[string]bool{"enabled": true}); resp.StatusCode != 200 {
		t.Fatal("enable target failed")
	}
	if resp, _ := h.call("POST", "/api/global", tok, map[string]bool{"enabled": true}); resp.StatusCode != 200 {
		t.Fatal("global enable failed")
	}
	_, ov := h.call("GET", "/api/overview", tok, nil)
	if ov["global_enabled"] != true {
		t.Fatalf("global should be on: %v", ov)
	}
	ts, _ := json.Marshal(ov["targets"])
	if !strings.Contains(string(ts), "injecting") && !strings.Contains(string(ts), "active") {
		t.Fatalf("target should be injecting: %s", ts)
	}
	// 持久化：配置落盘且目标在
	cfg := store.Snapshot()
	if len(cfg.Targets) != 1 || !cfg.Targets[0].Enabled || !cfg.LicensedAck {
		t.Fatalf("persist mismatch: %+v", cfg)
	}
	// 删除 → 恢复 → 目标清空
	if resp, _ := h.call("DELETE", "/api/targets/bb:bb:bb:bb:bb:b2", tok, nil); resp.StatusCode != 200 {
		t.Fatal("delete failed")
	}
	_, tsOut := h.call("GET", "/api/targets", tok, nil)
	_ = tsOut
	if len(store.Snapshot().Targets) != 0 {
		t.Fatal("targets remain after delete")
	}
}

// 5.3 热生效 + 5.4 状态与恢复端点
func TestConfigHotApplyAndRecover(t *testing.T) {
	h, store, a := newHarness(t)
	_, _ = h.call("POST", "/api/setup", "", map[string]string{"password": "testpass123"})
	tok := h.login(t, "testpass123")
	// 非法值拒绝
	resp, _ := h.call("PUT", "/api/config", tok, map[string]any{"inject_interval_sec": 0})
	if resp.StatusCode != 400 {
		t.Fatal("invalid interval must 400")
	}
	// 合法更新
	if resp, _ := h.call("PUT", "/api/config", tok, map[string]any{"inject_interval_sec": 1, "forward_mode": "masquerade"}); resp.StatusCode != 200 {
		t.Fatal("config update failed")
	}
	c := store.Snapshot()
	if c.InjectIntervalSec != 1 || c.ForwardMode != config.ModeMasq {
		t.Fatalf("not persisted: %+v", c)
	}
	// 加目标并全局开 → 恢复端点
	_, _ = h.call("POST", "/api/license/ack", tok, map[string]any{})
	_, _ = h.call("POST", "/api/targets", tok, config.Target{MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.80", Iface: "eth0", Enabled: true})
	if resp, _ := h.call("POST", "/api/global", tok, map[string]bool{"enabled": true}); resp.StatusCode != 200 {
		t.Fatal("global on failed")
	}
	// 一键恢复（management-console spec）
	if resp, _ := h.call("POST", "/api/recover", tok, nil); resp.StatusCode != 200 {
		t.Fatal("recover failed")
	}
	c = store.Snapshot()
	if c.GlobalEnabled {
		t.Fatal("global must be off after recover")
	}
	if len(c.Targets) != 1 || !c.Targets[0].Enabled {
		t.Fatalf("config must be preserved after recover: %+v", c.Targets)
	}
	_ = a
}

// 5.2 发现端点
func TestDiscoverEndpoint(t *testing.T) {
	h, _, _ := newHarness(t)
	_, _ = h.call("POST", "/api/setup", "", map[string]string{"password": "testpass123"})
	tok := h.login(t, "testpass123")
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/discover", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("discover: %d", resp.StatusCode)
	}
	var list []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("want 2 neighbours, got %d", len(list))
	}
	// 未鉴权 → 401
	raw, err := http.Get(h.srv.URL + "/api/discover")
	if err != nil {
		t.Fatal(err)
	}
	raw.Body.Close()
	if raw.StatusCode != 401 {
		t.Fatalf("unauthenticated discover must 401, got %d", raw.StatusCode)
	}
}

// 事件端点 + 审计内容检查（safety spec）
func TestEventsAudit(t *testing.T) {
	h, _, _ := newHarness(t)
	_, _ = h.call("POST", "/api/setup", "", map[string]string{"password": "testpass123"})
	tok := h.login(t, "testpass123")
	_, _ = h.call("POST", "/api/license/ack", tok, map[string]any{})
	_, _ = h.call("POST", "/api/targets", tok, config.Target{MAC: "cc:cc:cc:cc:cc:cc", IP: "192.168.1.90", Iface: "eth0"})
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/events", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var evs []map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&evs); err != nil {
		t.Fatal(err)
	}
	var foundAdd, foundAck bool
	for _, e := range evs {
		msg, _ := e["message"].(string)
		if strings.Contains(msg, "添加目标") {
			foundAdd = true
		}
		if strings.Contains(msg, "授权使用边界已确认") {
			foundAck = true
		}
	}
	if !foundAdd || !foundAck {
		t.Fatalf("audit entries missing: %+v", evs)
	}
}

// /api/interfaces 暴露本机接口 MAC（接管侧"网关 MAC"可观测）
func TestInterfacesEndpoint(t *testing.T) {
	h, _, _ := newHarness(t)
	_, _ = h.call("POST", "/api/setup", "", map[string]string{"password": "testpass123"})
	tok := h.login(t, "testpass123")
	req, _ := http.NewRequest("GET", h.srv.URL+"/api/interfaces", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var ifs map[string]struct {
		MAC   string   `json:"mac"`
		Addrs []string `json:"addrs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ifs); err != nil {
		t.Fatal(err)
	}
	eth, ok := ifs["eth0"]
	if !ok {
		t.Fatalf("eth0 missing: %+v", ifs)
	}
	if eth.MAC != "aa:aa:aa:aa:aa:01" {
		t.Fatalf("eth0 mac = %q", eth.MAC)
	}
	if len(eth.Addrs) != 1 || eth.Addrs[0] != "192.168.1.10/24" {
		t.Fatalf("eth0 addrs = %v", eth.Addrs)
	}
}
