package auditlog

import (
	"fmt"
	"testing"
)

func TestAppendReadRecent(t *testing.T) {
	l, err := New(t.TempDir(), 5<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		l.Log("audit", "api:test", "aa:bb", fmt.Sprintf("event %d", i))
	}
	l.Close()
	l2, err := New(l.dir, 5<<20, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Close()
	ev, err := l2.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ev) != 5 {
		t.Fatalf("want 5, got %d", len(ev))
	}
	for i := 1; i < len(ev); i++ {
		if ev[i-1].Time.After(ev[i].Time) {
			t.Fatal("not ordered old→new")
		}
	}
}

func TestRotationKeepsBounds(t *testing.T) {
	l, err := New(t.TempDir(), 400, 2)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		l.Log("takeover", "system", "", fmt.Sprintf("msg-%d-padding-to-grow-lines-quickly", i))
	}
	l.Close()
	ev, _ := l.Recent(1000)
	if len(ev) == 0 || len(ev) >= 200 {
		t.Fatalf("rotation broken: kept %d of 200", len(ev))
	}
	// 最新事件必须在
	var last bool
	for _, e := range ev {
		if e.Message == "msg-199-padding-to-grow-lines-quickly" {
			last = true
		}
	}
	if !last {
		t.Fatal("newest event lost")
	}
}
