//go:build linux

package neti

import (
	"errors"
	"fmt"
	"net"
	"syscall"

	"gateweaver/internal/arpframe"
)

type rawConn struct {
	iface string
	mac   arpframe.MAC
	fd    int
	ifidx int
}

// NewRaw 在指定接口上创建 AF_PACKET SOCK_RAW 收发器（ETH_P_ARP + ETH_P_IP 观测）。
// 需要 root / CAP_NET_RAW。
func NewRaw(iface string) (Transceiver, error) {
	inf, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("neti: interface %s: %w", iface, err)
	}
	var mac arpframe.MAC
	b, err := arpframe.ParseMAC(inf.HardwareAddr.String())
	if err != nil {
		return nil, fmt.Errorf("neti: bad hw addr on %s: %w", iface, err)
	}
	mac = b

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("neti: socket: %w", err)
	}
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:   inf.Index,
	}
	if err := syscall.Bind(fd, &sll); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("neti: bind: %w", err)
	}
	return &rawConn{iface: iface, mac: mac, fd: fd, ifidx: inf.Index}, nil
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func (c *rawConn) Iface() string                  { return c.iface }
func (c *rawConn) HardwareAddr() arpframe.MAC     { return c.mac }
func (c *rawConn) Close() error                   { return syscall.Close(c.fd) }

func (c *rawConn) Send(frame []byte) error {
	dst, _ := arpframe.DstMACOf(frame)
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ARP),
		Ifindex:   c.ifidx,
		Halen:    6,
	}
	copy(sll.Addr[:], dst[:])
	return syscall.Sendto(c.fd, frame, 0, &sll)
}

func (c *rawConn) Next() ([]byte, error) {
	buf := make([]byte, 2048)
	n, _, err := syscall.Recvfrom(c.fd, buf, 0)
	if err != nil {
		return nil, err
	}
	if n < 14 {
		return nil, errors.New("neti: short read")
	}
	return buf[:n], nil
}
