// Package auditlog 提供追加式 JSONL 事件/审计日志（容量滚动，safety-and-recovery spec）。
package auditlog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Event 是一条结构化日志。
type Event struct {
	Time    time.Time `json:"time"`
	Kind    string    `json:"kind"`    // takeover|restore|upstream|config|error|audit
	Actor   string    `json:"actor"`   // "api:<sessionid>" / "system"
	Target  string    `json:"target,omitempty"`
	Message string    `json:"message"`
}

// Logger 是并发安全的滚动 JSONL 日志。
type Logger struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	keep     int // 保留的轮转文件数
	cur      *os.File
	curSize  int64
	w        *bufio.Writer
}

// New 在 dir 下创建 logger（当前文件 events.jsonl）。maxBytes 为单文件上限，keep 为轮转保留数。
func New(dir string, maxBytes int64, keep int) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	l := &Logger{dir: dir, maxBytes: maxBytes, keep: keep}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) path() string { return filepath.Join(l.dir, "events.jsonl") }

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path(), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.cur, l.curSize = f, st.Size()
	l.w = bufio.NewWriter(f)
	return nil
}

// Log 追加一条事件（time 自动填充）。
func (l *Logger) Log(kind, actor, target, msg string) {
	l.LogEvent(Event{Time: time.Now(), Kind: kind, Actor: actor, Target: target, Message: msg})
}

// Logf 格式化追加。
func (l *Logger) Logf(kind, actor, target, format string, args ...any) {
	l.Log(kind, actor, target, fmt.Sprintf(format, args...))
}

// LogEvent 追加原始事件。
func (l *Logger) LogEvent(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	line := append(b, '\n')
	n, _ := l.w.Write(line)
	_ = l.w.Flush()
	l.curSize += int64(n)
	if l.curSize > l.maxBytes {
		l.rotate()
	}
}

// rotate 关闭当前文件 → 重命名带序号 → 修剪超额文件 → 重开。
func (l *Logger) rotate() {
	_ = l.w.Flush()
	_ = l.cur.Close()
	// 现有 N.1 → N.2 …（倒序腾位）
	for i := l.keep - 1; i >= 1; i-- {
		src := filepath.Join(l.dir, fmt.Sprintf("events.jsonl.%d", i))
		dst := filepath.Join(l.dir, fmt.Sprintf("events.jsonl.%d", i+1))
		if i == l.keep-1 {
			_ = os.Remove(dst)
		}
		_ = os.Rename(src, dst)
	}
	_ = os.Rename(l.path(), filepath.Join(l.dir, "events.jsonl.1"))
	l.curSize = 0
	_ = l.open()
}

// Recent 返回最多 limit 条最新事件（跨轮转文件，旧→新排序）。
func (l *Logger) Recent(limit int) ([]Event, error) {
	l.mu.Lock()
	names := []string{}
	for i := l.keep; i >= 1; i-- {
		p := filepath.Join(l.dir, fmt.Sprintf("events.jsonl.%d", i))
		if _, err := os.Stat(p); err == nil {
			names = append(names, p)
		}
	}
	names = append(names, l.path())
	// 从最旧开始读取
	out := make([]Event, 0, limit)
	for _, p := range names {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 256*1024)
		for sc.Scan() {
			var e Event
			if err := json.Unmarshal(sc.Bytes(), &e); err == nil {
				out = append(out, e)
			}
		}
		f.Close()
	}
	l.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.Before(out[j].Time) })
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

// Close 落盘并关闭。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.w != nil {
		_ = l.w.Flush()
	}
	if l.cur != nil {
		return l.cur.Close()
	}
	return nil
}

// ParseKind 供测试/查询辅助：判断 kind 字符串合法性（小写字母+下划线）。
func ValidKind(s string) bool {
	if s == "" || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !(r == '_' || (r >= 'a' && r <= 'z')) {
			return false
		}
	}
	return true
}
