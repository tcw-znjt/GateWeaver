package arpframe

import (
	"net/netip"
	"testing"
)

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %s: %v", s, err)
	}
	return a
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	src, _ := ParseMAC("aa:bb:cc:dd:ee:01")
	dst, _ := ParseMAC("11:22:33:44:55:66")
	p := Packet{
		SrcMAC:  src,
		DstMAC:  dst,
		Op:      ARPReply,
		Sender:  mustAddr(t, "192.168.1.1"),
		SenderMAC: src,
		Target:  mustAddr(t, "192.168.1.50"),
		TgtMAC:  dst,
	}
	frame, err := Encode(p)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(frame) != EtherARPFrameLen {
		t.Fatalf("frame len = %d, want %d", len(frame), EtherARPFrameLen)
	}
	got, err := Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.SrcMAC != p.SrcMAC || got.DstMAC != p.DstMAC {
		t.Errorf("mac mismatch: %+v", got)
	}
	if got.Op != ARPReply || got.Sender != p.Sender || got.Target != p.Target ||
		got.SenderMAC != p.SenderMAC || got.TgtMAC != p.TgtMAC {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, p)
	}
}

func TestDecodeRejectsMalformed(t *testing.T) {
	okFrame, err := Encode(Packet{
		Op: ARPRequest, Sender: mustAddr(t, "10.0.0.1"), Target: mustAddr(t, "10.0.0.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		frame  []byte
		wantEr error
	}{
		{"too short", okFrame[:20], ErrShortFrame},
		{"not arp ethertype", func() []byte {
			f := append([]byte(nil), okFrame...)
			f[12], f[13] = 0x08, 0x00
			return f
		}(), ErrNotARP},
		{"bad hlen", func() []byte {
			f := append([]byte(nil), okFrame...)
			f[14+4] = 8
			return f
		}(), ErrBadHardware},
		{"bad op", func() []byte {
			f := append([]byte(nil), okFrame...)
			f[14+7] = 9
			return f
		}(), ErrBadHardware},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.frame)
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEncodeRejectsBroadcastSourceAndNonIPv4(t *testing.T) {
	bc := MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if _, err := Encode(Packet{SrcMAC: bc, Op: ARPReply,
		Sender: mustAddr(t, "1.1.1.1"), Target: mustAddr(t, "1.1.1.2")}); err != ErrBroadcastSrc {
		t.Fatalf("want ErrBroadcastSrc, got %v", err)
	}
	if _, err := Encode(Packet{Op: ARPReply,
		Sender: mustAddr(t, "fe80::1"), Target: mustAddr(t, "1.1.1.2")}); err != ErrInvalidSender {
		t.Fatalf("want ErrInvalidSender, got %v", err)
	}
}

func TestIsWhoHas(t *testing.T) {
	gw := mustAddr(t, "192.168.1.1")
	p := Packet{Op: ARPRequest, Sender: mustAddr(t, "192.168.1.50"), Target: gw}
	if !p.IsWhoHas(gw) {
		t.Fatal("should match who-has gateway")
	}
	if p.IsWhoHas(mustAddr(t, "192.168.1.9")) {
		t.Fatal("should not match other ip")
	}
	p.Op = ARPReply
	if p.IsWhoHas(gw) {
		t.Fatal("reply must not match")
	}
}

func TestParseMAC(t *testing.T) {
	if _, err := ParseMAC("aa:bb:cc:dd:ee"); err == nil {
		t.Fatal("short mac should fail")
	}
	m, err := ParseMAC("AA:bb:CC:dd:EE:0f")
	if err != nil {
		t.Fatal(err)
	}
	if m.String() != "aa:bb:cc:dd:ee:0f" {
		t.Fatalf("String() = %s", m.String())
	}
}
