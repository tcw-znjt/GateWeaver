//go:build !linux

package neti

import "errors"

// NewRaw 在非 Linux 平台不可用（AF_PACKET 为 Linux 特性）。
// 单测通过 fake Transceiver 注入，不需要真实套接字。
func NewRaw(iface string) (Transceiver, error) {
	return nil, errors.New("neti: raw sockets require linux")
}
