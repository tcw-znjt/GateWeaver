//go:build !unix

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// platformLock 非 Unix（Windows 开发机）回退：PID 文件 + 存活检查，仅供本地调试。
func platformLock(path string) (func(), error) {
	if b, err := os.ReadFile(path); err == nil {
		if pid, e := strconv.Atoi(string(b)); e == nil && pidAlive(pid) {
			return nil, fmt.Errorf("已有实例在运行 (pid %d)", pid)
		}
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o750)
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		return nil, err
	}
	return func() { _ = os.Remove(path) }, nil
}

func pidAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Windows: FindProcess 总成功，需 Signal(0) 判活；自 pid 即视为存活
	return p.Signal(syscall.Signal(0)) == nil || pid == os.Getpid()
}

var _ = time.Now
