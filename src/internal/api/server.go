// Package api 提供 GateWeaver 管理台的 REST 接口与内嵌前端。
// 访问边界：仅监听配置指定的 LAN 地址；除 /api/ping、初始引导外全部需要 Bearer 会话。
package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"

	"gateweaver/internal/app"
	"gateweaver/internal/auditlog"
	"gateweaver/internal/config"
	"gateweaver/internal/discover"
)

// Server 管理台服务。
type Server struct {
	app   *app.App
	store *config.Store
	log   *auditlog.Logger

	mu       sync.Mutex
	sessions map[string]session // token → session
}

type session struct {
	user    string
	expires time.Time
}

// NewServer 构造。
func NewServer(a *app.App, store *config.Store, log *auditlog.Logger) *Server {
	return &Server{app: a, store: store, log: log, sessions: map[string]session{}}
}

// Handler 返回带路由的 mux（供 httptest 与 Listen 共用）。
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/ping", s.hPing)
	mux.HandleFunc("GET /api/initial", s.hInitial)
	mux.HandleFunc("POST /api/setup", s.hSetup)
	mux.HandleFunc("POST /api/login", s.hLogin)

	auth := func(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			actor, err := s.auth(r)
			if err != nil {
				writeErr(w, http.StatusUnauthorized, err)
				return
			}
			h(w, r, actor)
		})
	}
	mux.HandleFunc("POST /api/logout", auth(s.hLogout))
	mux.HandleFunc("GET /api/overview", auth(s.hOverview))
	mux.HandleFunc("GET /api/config", auth(s.hGetConfig))
	mux.HandleFunc("PUT /api/config", auth(s.hPutConfig))
	mux.HandleFunc("POST /api/license/ack", auth(s.hLicenseAck))
	mux.HandleFunc("GET /api/targets", auth(s.hGetTargets))
	mux.HandleFunc("POST /api/targets", auth(s.hAddTarget))
	mux.HandleFunc("PUT /api/targets/{mac}", auth(s.hUpdateTarget))
	mux.HandleFunc("DELETE /api/targets/{mac}", auth(s.hDeleteTarget))
	mux.HandleFunc("POST /api/global", auth(s.hGlobal))
	mux.HandleFunc("POST /api/recover", auth(s.hRecover))
	mux.HandleFunc("GET /api/discover", auth(s.hDiscover))
	mux.HandleFunc("GET /api/interfaces", auth(s.hInterfaces))
	mux.HandleFunc("GET /api/events", auth(s.hEvents))
	mux.Handle("/", s.staticHandler())
	return mux
}

// Listen 在配置指定的地址上启动 HTTP 服务（阻塞；ctx 取消退出）。
// "auto" 展开为本机全部非回环 IPv4 地址（LAN 侧），满足"仅监听 LAN"的边界。
func (s *Server) Listen(ctx context.Context) error {
	cfg := s.store.Snapshot()
	var addrs []string
	for _, a := range cfg.ListenAddrs {
		if a == "auto" {
			ifs, err := s.app.Interfaces()
			if err == nil {
				for _, info := range ifs {
					for _, p := range info.Addrs {
						if p.Addr().Is4() && !p.Addr().IsLoopback() {
							addrs = append(addrs, p.Addr().String())
						}
					}
				}
			}
			continue
		}
		addrs = append(addrs, a)
	}
	if cfg.Port > 0 {
		for i, a := range addrs {
			if _, _, err := net.SplitHostPort(a); err != nil {
				addrs[i] = net.JoinHostPort(a, fmt.Sprint(cfg.Port))
			}
		}
	}
	if len(addrs) == 0 {
		addrs = []string{"127.0.0.1:9666"}
	}
	var listeners []net.Listener
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			for _, l := range listeners {
				l.Close()
			}
			return fmt.Errorf("api: listen %s: %w", a, err)
		}
		listeners = append(listeners, ln)
	}
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	errCh := make(chan error, 1)
	for i, ln := range listeners {
		if i == 0 {
			go func(l net.Listener) { errCh <- srv.Serve(l) }(ln)
		} else {
			go func(l net.Listener) { _ = srv.Serve(l) }(ln)
		}
	}
	return <-errCh
}

// --- 鉴权 ---

// HashPassword scrypt(32768,8,1) → "saltB64$hashB64"。
func HashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h, err := scrypt.Key([]byte(pw), salt, 32768, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt) + "$" + base64.StdEncoding.EncodeToString(h), nil
}

// CheckPassword 常量时间比较。
func CheckPassword(hashed, pw string) bool {
	sp := strings.SplitN(hashed, "$", 2)
	if len(sp) != 2 {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(sp[0])
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(sp[1])
	if err != nil {
		return false
	}
	got, err := scrypt.Key([]byte(pw), salt, 32768, 8, 1, 32)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(want, got) == 1
}

func (s *Server) auth(r *http.Request) (string, error) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if tok == "" {
		return "", errors.New("unauthorized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[tok]
	if !ok || time.Now().After(sess.expires) {
		delete(s.sessions, tok)
		return "", errors.New("session expired")
	}
	sess.expires = time.Now().Add(12 * time.Hour) // 滑动过期
	s.sessions[tok] = sess
	return "api:" + tok[:8], nil
}

func (s *Server) newSession() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	s.mu.Lock()
	s.sessions[tok] = session{user: "admin", expires: time.Now().Add(12 * time.Hour)}
	s.mu.Unlock()
	return tok, nil
}

// --- handlers ---

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, err error) {
	writeJSON(w, code, map[string]string{"error": err.Error()})
}

func decodeBody(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) hPing(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"ok": true, "version": Version, "time": time.Now()})
}

// Version 构建版本（ldflags 注入）。
var Version = "dev"

func (s *Server) hInitial(w http.ResponseWriter, r *http.Request) {
	cfg := s.store.Snapshot()
	writeJSON(w, 200, map[string]any{
		"needs_setup":   !cfg.PasswordSet,
		"needs_license": !cfg.LicensedAck,
		"version":       Version,
	})
}

func (s *Server) hSetup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil || len(body.Password) < 8 {
		writeErr(w, 400, errors.New("password must be >= 8 chars"))
		return
	}
	if s.store.Snapshot().PasswordSet {
		writeErr(w, 403, errors.New("password already set"))
		return
	}
	h, err := HashPassword(body.Password)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if err := s.store.Update(s.app.Gateway(), func(c *config.Config) error {
		c.PasswordHash, c.PasswordSet = h, true
		return nil
	}); err != nil {
		writeErr(w, 500, err)
		return
	}
	s.log.Log("audit", "bootstrap", "", "管理口令已设置")
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, 400, err)
		return
	}
	cfg := s.store.Snapshot()
	if !cfg.PasswordSet || !CheckPassword(cfg.PasswordHash, body.Password) {
		time.Sleep(500 * time.Millisecond) // 减缓爆破
		writeErr(w, 401, errors.New("口令错误"))
		return
	}
	tok, err := s.newSession()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]string{"token": tok})
}

func (s *Server) hLogout(w http.ResponseWriter, r *http.Request, actor string) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	s.mu.Lock()
	delete(s.sessions, tok)
	s.mu.Unlock()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// Overview 总览
type overview struct {
	GlobalEnabled bool                   `json:"global_enabled"`
	LicensedAck   bool                   `json:"licensed_ack"`
	ForwardMode   string                 `json:"forward_mode"`
	Gateway       gatewayView            `json:"gateway"`
	UpstreamOK    bool                   `json:"upstream_ok"`
	Targets       []any                  `json:"targets"`
	Counts        map[string]int         `json:"counts"`
}

type gatewayView struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Known  bool   `json:"known"`
	Source string `json:"source"` // config|probe
}

func (s *Server) hOverview(w http.ResponseWriter, r *http.Request, actor string) {
	cfg := s.store.Snapshot()
	gwm, gwok := s.app.Engine.GatewayMAC()
	src := "probe"
	if cfg.GatewayIP != "" {
		src = "config"
	}
	targets := make([]any, 0, len(cfg.Targets))
	st := s.app.Engine.Status()
	stByMac := map[string]any{}
	for _, ts := range st {
		stByMac[ts.MAC] = ts
	}
	counts := map[string]int{}
	for _, t := range cfg.Targets {
		if t.Enabled {
			counts["enabled"]++
		} else {
			counts["disabled"]++
		}
		targets = append(targets, map[string]any{"target": t, "status": stByMac[strings.ToLower(t.MAC)]})
	}
	writeJSON(w, 200, overview{
		GlobalEnabled: cfg.GlobalEnabled, LicensedAck: cfg.LicensedAck,
		ForwardMode: string(cfg.ForwardMode),
		Gateway:     gatewayView{IP: s.app.Gateway().String(), MAC: gwm.String(), Known: gwok, Source: src},
		UpstreamOK:  s.app.UpstreamOK(),
		Targets:     targets, Counts: counts,
	})
}

func (s *Server) hGetConfig(w http.ResponseWriter, r *http.Request, actor string) {
	writeJSON(w, 200, s.store.Snapshot())
}

// PutConfig 更新全局参数（不含 targets——目标走专用端点）。
func (s *Server) hPutConfig(w http.ResponseWriter, r *http.Request, actor string) {
	var body struct {
		GatewayIP            *string              `json:"gateway_ip"`
		GatewayMACFixed      *string              `json:"gateway_mac_fixed"`
		FailOpen             *bool                `json:"fail_open"`
		InjectIntervalSec    *int                 `json:"inject_interval_sec"`
		InjectRatePerSec     *int                 `json:"inject_rate_per_sec"`
		ForwardMode          *string              `json:"forward_mode"`
		Port                 *int                 `json:"port"`
		ListenAddrs          *[]string            `json:"listen_addrs"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, 400, err)
		return
	}
	err := s.store.Update(s.app.Gateway(), func(c *config.Config) error {
		if body.GatewayIP != nil {
			if *body.GatewayIP != "" {
				if _, e := netip.ParseAddr(*body.GatewayIP); e != nil {
					return fmt.Errorf("bad gateway_ip: %w", e)
				}
			}
			c.GatewayIP = *body.GatewayIP
		}
		if body.GatewayMACFixed != nil {
			c.GatewayMACFixed = *body.GatewayMACFixed
		}
		if body.FailOpen != nil {
			c.FailOpenOnUpstreamDown = *body.FailOpen
		}
		if body.InjectIntervalSec != nil {
			c.InjectIntervalSec = *body.InjectIntervalSec
		}
		if body.InjectRatePerSec != nil {
			c.InjectRatePerSec = *body.InjectRatePerSec
		}
		if body.ForwardMode != nil {
			c.ForwardMode = config.ForwardMode(*body.ForwardMode)
		}
		if body.Port != nil {
			c.Port = *body.Port
		}
		if body.ListenAddrs != nil {
			c.ListenAddrs = *body.ListenAddrs
		}
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	s.log.Log("audit", actor, "", "全局配置更新")
	if err := s.app.Apply(s.store.Snapshot()); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, s.store.Snapshot())
}

func (s *Server) hLicenseAck(w http.ResponseWriter, r *http.Request, actor string) {
	err := s.store.Update(s.app.Gateway(), func(c *config.Config) error {
		c.LicensedAck = true
		return nil
	})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	s.log.Log("audit", actor, "", "授权使用边界已确认")
	_ = s.app.Apply(s.store.Snapshot())
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hGetTargets(w http.ResponseWriter, r *http.Request, actor string) {
	writeJSON(w, 200, s.store.Snapshot().Targets)
}

func (s *Server) hAddTarget(w http.ResponseWriter, r *http.Request, actor string) {
	var t config.Target
	if err := decodeBody(r, &t); err != nil {
		writeErr(w, 400, err)
		return
	}
	// 跨网段/未知接口拒绝（arp-gateway-takeover spec：目标须与接管接口同二层）
	ifs, err := s.app.Interfaces()
	if err == nil {
		if _, ok := ifs[t.Iface]; !ok {
			writeErr(w, 400, fmt.Errorf("接口 %q 不存在或不可用于接管", t.Iface))
			return
		}
	}
	err = s.store.Update(s.app.Gateway(), func(c *config.Config) error {
		for _, ex := range c.Targets {
			if strings.EqualFold(ex.MAC, t.MAC) {
				return errors.New("目标已存在")
			}
		}
		c.Targets = append(c.Targets, t)
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	s.log.Logf("audit", actor, t.MAC, "添加目标 %s(%s) enabled=%v", t.IP, t.Iface, t.Enabled)
	if err := s.app.Apply(s.store.Snapshot()); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 201, t)
}

func (s *Server) hUpdateTarget(w http.ResponseWriter, r *http.Request, actor string) {
	mac := r.PathValue("mac")
	var body struct {
		Enabled *bool   `json:"enabled"`
		IP      *string `json:"ip"`
		Iface   *string `json:"iface"`
		Note    *string `json:"note"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, 400, err)
		return
	}
	err := s.store.Update(s.app.Gateway(), func(c *config.Config) error {
		for i := range c.Targets {
			if strings.EqualFold(c.Targets[i].MAC, mac) {
				if body.Enabled != nil {
					c.Targets[i].Enabled = *body.Enabled
				}
				if body.IP != nil {
					c.Targets[i].IP = *body.IP
				}
				if body.Iface != nil {
					c.Targets[i].Iface = *body.Iface
				}
				if body.Note != nil {
					c.Targets[i].Note = *body.Note
				}
				return nil
			}
		}
		return errors.New("目标不存在")
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	s.log.Log("audit", actor, mac, "更新目标")
	if err := s.app.Apply(s.store.Snapshot()); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hDeleteTarget(w http.ResponseWriter, r *http.Request, actor string) {
	mac := r.PathValue("mac")
	err := s.store.Update(s.app.Gateway(), func(c *config.Config) error {
		out := c.Targets[:0]
		found := false
		for _, t := range c.Targets {
			if strings.EqualFold(t.MAC, mac) {
				found = true
				continue
			}
			out = append(out, t)
		}
		if !found {
			return errors.New("目标不存在")
		}
		c.Targets = out
		return nil
	})
	if err != nil {
		writeErr(w, 400, err)
		return
	}
	s.log.Log("audit", actor, mac, "删除目标")
	if err := s.app.Apply(s.store.Snapshot()); err != nil {
		writeErr(w, 400, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hGlobal(w http.ResponseWriter, r *http.Request, actor string) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeBody(r, &body); err != nil {
		writeErr(w, 400, err)
		return
	}
	if body.Enabled && !s.store.Snapshot().LicensedAck {
		writeErr(w, 403, errors.New("须先确认授权使用边界"))
		return
	}
	err := s.store.Update(s.app.Gateway(), func(c *config.Config) error {
		c.GlobalEnabled = body.Enabled
		return nil
	})
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	s.log.Logf("audit", actor, "", "全局开关 → %v", body.Enabled)
	if err := s.app.Apply(s.store.Snapshot()); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hRecover(w http.ResponseWriter, r *http.Request, actor string) {
	if err := s.app.RecoverAll(actor); err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) hDiscover(w http.ResponseWriter, r *http.Request, actor string) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	entries, err := s.app.Scanner.Neighbors(ctx)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	if cidr := r.URL.Query().Get("probe"); cidr != "" {
		live, err := s.app.Scanner.ProbeSubnet(ctx, cidr)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		known := map[string]bool{}
		for _, e := range entries {
			known[e.IP] = true
		}
		for _, ip := range live {
			if !known[ip] {
				entries = append(entries, discover.Entry{IP: ip, State: "PROBED"})
			}
		}
	}
	writeJSON(w, 200, entries)
}

func (s *Server) hInterfaces(w http.ResponseWriter, r *http.Request, actor string) {
	ifs, err := s.app.Interfaces()
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, ifs)
}

func (s *Server) hEvents(w http.ResponseWriter, r *http.Request, actor string) {
	limit := 200
	fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	if limit <= 0 || limit > 2000 {
		limit = 200
	}
	ev, err := s.log.Recent(limit)
	if err != nil {
		writeErr(w, 500, err)
		return
	}
	writeJSON(w, 200, ev)
}
