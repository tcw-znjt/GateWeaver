package discover

import "testing"

func TestParseNeigh(t *testing.T) {
	out := `192.168.1.1 dev eth0 lladdr de:ad:be:ef:00:01 REACHABLE
192.168.1.50 dev eth0 lladdr bb:bb:bb:bb:bb:02 STALE
10.0.0.9 dev eth1 FAILED
fe80::1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
badline`
	list := ParseNeigh(out)
	if len(list) != 2 {
		t.Fatalf("got %d entries: %+v", len(list), list)
	}
	if list[0].IP != "192.168.1.1" || list[0].MAC != "de:ad:be:ef:00:01" || list[0].State != "REACHABLE" {
		t.Fatalf("entry0: %+v", list[0])
	}
	if list[1].Iface != "eth0" {
		t.Fatalf("entry1: %+v", list[1])
	}
}

func TestParseDefaultRoute(t *testing.T) {
	gw, dev, err := ParseDefaultRoute("default via 192.168.1.1 dev eth0 proto dhcp metric 100\n")
	if err != nil || gw != "192.168.1.1" || dev != "eth0" {
		t.Fatalf("got %s %s %v", gw, dev, err)
	}
	if _, _, err := ParseDefaultRoute("10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.2\n"); err == nil {
		t.Fatal("expected error without default route")
	}
}
