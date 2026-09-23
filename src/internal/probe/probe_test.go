package probe

import "testing"

func TestParseLinkShow(t *testing.T) {
	out := `1: lo: <LOOPBACK,UP> mtu 65536 state UNKNOWN group default qlen 1000 link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 state UP link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff
3: wlan0: <BROADCAST> mtu 1500 state DOWN link/ether 11:22:33:44:55:66`
	m := parseLinkShow(out)
	if m["eth0"] != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("eth0: %+v", m)
	}
	if m["wlan0"] != "11:22:33:44:55:66" {
		t.Fatalf("wlan0: %+v", m)
	}
	if _, has := m["lo"]; has {
		t.Fatalf("loopback interface must be skipped: %+v", m)
	}
}

func TestParseAddrShow(t *testing.T) {
	m, err := parseAddrShow("2: eth0    inet 10.0.0.5/24 brd + scope global eth0\n")
	if err != nil || len(m["eth0"]) != 1 {
		t.Fatalf("parse: %v %+v", err, m)
	}
}
