// Command gateweaver 是 fnOS 上的常驻守护进程：ARP 接管引擎 + 转发管理 + 管理台。
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"gateweaver/internal/api"
	"gateweaver/internal/app"
	"gateweaver/internal/auditlog"
	"gateweaver/internal/config"
	"gateweaver/internal/fwd"
	"gateweaver/internal/neti"
)

var logf = log.New(os.Stderr, "[gateweaver] ", log.LstdFlags|log.Lmsgprefix)

func main() {
	dataDir := flag.String("data", envOr("GW_DATA", "/var/apps/gateweaver/data"), "数据目录（配置/日志/锁）")
	noLock := flag.Bool("no-lock", false, "跳过单实例锁（仅调试）")
	flag.Parse()

	if err := run(*dataDir, *noLock); err != nil {
		logf.Fatal(err)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func run(dataDir string, noLock bool) error {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	// 单实例互斥（safety spec）
	unlock := func() {}
	if !noLock {
		u, err := acquireLock(filepath.Join(dataDir, "gateweaver.lock"))
		if err != nil {
			return err
		}
		unlock = u
	}
	defer unlock()

	store, err := config.Load(filepath.Join(dataDir, "config.json"))
	if err != nil {
		return err
	}
	alog, err := auditlog.New(filepath.Join(dataDir, "logs"), 5<<20, 4)
	if err != nil {
		return err
	}
	defer alog.Close()

	runner := fwd.DefaultRunner()
	a := app.New(store, alog, neti.NewRaw, runner)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	started := false
	if err := a.Start(ctx); err != nil {
		// 前置检查失败（如无默认路由）：管理台仍然拉起，接管保持关闭
		alog.Logf("error", "system", "", "启动失败（接管未启用）: %v", err)
		log.Printf("接管启动失败，仅运行管理台: %v", err)
	} else {
		started = true
	}

	srv := api.NewServer(a, store, alog)
	apiErr := make(chan error, 1)
	go func() { apiErr <- srv.Listen(ctx) }()
	alog.Logf("takeover", "system", "", "守护进程启动 pid=%d", os.Getpid())

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	select {
	case err := <-apiErr:
		if err != nil && started {
			// API 挂了不应带走引擎：记录并继续等待信号（由 stop 脚本兜底恢复）
			alog.Logf("error", "system", "", "管理台异常退出: %v", err)
			<-sig
		}
	case s := <-sig:
		alog.Logf("restore", "system", "", "收到信号 %v，开始安全停机", s)
	}

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutCancel()
	if err := a.Shutdown(shutCtx); err != nil {
		log.Printf("停机清理存在错误: %v", err)
	}
	alog.Logf("restore", "system", "", "已停机并完成恢复")
	cancel()
	return nil
}

// acquireLock 单实例互斥锁（lock_unix.go 用 flock；lock_other.go 用 PID 文件）。
func acquireLock(path string) (func(), error) {
	return platformLock(path)
}
