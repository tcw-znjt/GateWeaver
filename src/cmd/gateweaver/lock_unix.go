//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

// platformLock 使用 flock(2) 实现内核级单实例互斥（safety spec：防双引擎）。
func platformLock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("已有 GateWeaver 实例在运行（%s 被锁定）: %w", path, err)
	}
	_, _ = f.WriteString(fmt.Sprint(os.Getpid()))
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
