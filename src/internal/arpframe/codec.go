// Package arpframe 实现以太网 II + ARP 帧的编解码（接管引擎的纯逻辑层，跨平台可测试）。
package arpframe

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Ethernet / ARP 常量
const (
	EtherTypeARP  uint16 = 0x0806
	EtherTypeIPv4 uint16 = 0x0800

	ARPRequest uint16 = 1
	ARPReply   uint16 = 2

	// ARP 帧固定头部（以太网头之后）：htype,proto,halen,plen,op = 28 字节 + 4*hw + 4*ip = 42 字节
	ARPFrameLen = 42

	// 以太网帧（含 ARP 载荷、不含 FCS）最小长度
	EtherARPFrameLen = 14 + ARPFrameLen
)

var (
	ErrShortFrame    = errors.New("arpframe: frame too short")
	ErrNotARP        = errors.New("arpframe: not an ARP frame")
	ErrBadHardware   = errors.New("arpframe: unsupported hardware/protocol type")
	ErrBroadcastSrc  = errors.New("arpframe: broadcast source mac")
	ErrInvalidSender = errors.New("arpframe: invalid sender address")
)

// MAC 为 6 字节 MAC 地址
type MAC [6]byte

func (m MAC) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5])
}

// IsZero 报告 MAC 是否全零。
func (m MAC) IsZero() bool { return m == MAC{} }

// ParseMAC 解析 "aa:bb:cc:dd:ee:ff" 形式。
func ParseMAC(s string) (MAC, error) {
	var m MAC
	b, err := parseHw(s)
	if err != nil {
		return m, err
	}
	copy(m[:], b)
	return m, nil
}

func parseHw(s string) ([]byte, error) {
	if len(s) != 17 {
		return nil, fmt.Errorf("arpframe: bad mac %q", s)
	}
	out := make([]byte, 0, 6)
	for i := 0; i < 6; i++ {
		hi, ok1 := hexVal(s[i*3])
		lo, ok2 := hexVal(s[i*3+1])
		if !ok1 || !ok2 {
			return nil, fmt.Errorf("arpframe: bad mac %q", s)
		}
		if i < 5 && s[i*3+2] != ':' {
			return nil, fmt.Errorf("arpframe: bad mac %q", s)
		}
		out = append(out, hi<<4|lo)
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// Packet 是一次收发所用的 ARP 报文（含目的/源 MAC）。
type Packet struct {
	SrcMAC  MAC     // 以太网源（我方 MAC）
	DstMAC  MAC     // 以太网目的（单播目标 MAC 或广播）
	Op      uint16  // ARPRequest / ARPReply
	Sender  netip.Addr // SPA 发送者协议地址
	SenderMAC MAC      // SHA 发送者硬件地址
	Target  netip.Addr // TPA 目标协议地址
	TgtMAC  MAC        // THA 目标硬件地址（request 时可为全零）
}

// Encode 序列化为以太网帧字节流。校验语义约束：
// 源 MAC 不得为广播；ARP 头部 htype=1/proto=ARP/hlen=6/plen=4。
func Encode(p Packet) ([]byte, error) {
	if !p.Sender.Is4() || !p.Target.Is4() {
		return nil, ErrInvalidSender
	}
	broadcast := MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if p.SrcMAC == broadcast {
		return nil, ErrBroadcastSrc
	}
	frame := make([]byte, EtherARPFrameLen)
	// 以太网头
	copy(frame[0:6], p.DstMAC[:])
	copy(frame[6:12], p.SrcMAC[:])
	binary.BigEndian.PutUint16(frame[12:14], EtherTypeARP)
	// ARP 头
	a := frame[14:]
	binary.BigEndian.PutUint16(a[0:2], 1)             // htype = Ethernet
	binary.BigEndian.PutUint16(a[2:4], EtherTypeARP)  // proto
	a[4] = 6
	a[5] = 4
	binary.BigEndian.PutUint16(a[6:8], p.Op)
	copy(a[8:14], p.SenderMAC[:])
	copy(a[14:18], p.Sender.AsSlice())
	copy(a[18:24], p.TgtMAC[:])
	copy(a[24:28], p.Target.AsSlice())
	return frame, nil
}

// Decode 从以太网帧解析 ARP。返回的 Packet 中 SrcMAC/DstMAC 取自以太网头，
// SenderMAC/TgtMAC 取自 ARP 头。对畸形帧返回错误（长度、类型、头部字段）。
func Decode(frame []byte) (Packet, error) {
	var p Packet
	if len(frame) < EtherARPFrameLen {
		return p, ErrShortFrame
	}
	copy(p.DstMAC[:], frame[0:6])
	copy(p.SrcMAC[:], frame[6:12])
	if et := binary.BigEndian.Uint16(frame[12:14]); et != EtherTypeARP {
		return p, fmt.Errorf("%w: ethertype 0x%04x", ErrNotARP, et)
	}
	a := frame[14 : 14+ARPFrameLen]
	if binary.BigEndian.Uint16(a[0:2]) != 1 || binary.BigEndian.Uint16(a[2:4]) != EtherTypeARP {
		return p, ErrBadHardware
	}
	if a[4] != 6 || a[5] != 4 {
		return p, ErrBadHardware
	}
	p.Op = binary.BigEndian.Uint16(a[6:8])
	if p.Op != ARPRequest && p.Op != ARPReply {
		return p, fmt.Errorf("%w: op %d", ErrBadHardware, p.Op)
	}
	copy(p.SenderMAC[:], a[8:14])
	copy(p.TgtMAC[:], a[18:24])
	sa, ok := addrFrom(a[14:18])
	if !ok {
		return p, ErrInvalidSender
	}
	ta, ok := addrFrom(a[24:28])
	if !ok {
		return p, ErrInvalidSender
	}
	p.Sender, p.Target = sa, ta
	return p, nil
}

// IsWhoHas 判定该帧是否为"who-has <want> tell <sender>"的 ARP 请求，
// 且请求发起方为 senders 集合之一（供被动应答循环过滤白名单）。
func (p Packet) IsWhoHas(want netip.Addr) bool {
	return p.Op == ARPRequest && p.Target == want
}

// Ethertype 返回帧的以太网类型（长度不足返回 0）。
func Ethertype(frame []byte) uint16 {
	if len(frame) < 14 {
		return 0
	}
	return binary.BigEndian.Uint16(frame[12:14])
}

// SrcMACOf 读取以太网源 MAC。
func SrcMACOf(frame []byte) (MAC, bool) {
	if len(frame) < 12 {
		return MAC{}, false
	}
	var m MAC
	copy(m[:], frame[6:12])
	return m, true
}

// DstMACOf 读取以太网目的 MAC。
func DstMACOf(frame []byte) (MAC, bool) {
	if len(frame) < 12 {
		return MAC{}, false
	}
	var m MAC
	copy(m[:], frame[0:6])
	return m, true
}

func addrFrom(b []byte) (netip.Addr, bool) {
	var a4 [4]byte
	copy(a4[:], b)
	return netip.AddrFrom4(a4), true
}
