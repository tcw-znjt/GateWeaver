// Package neti 抽象二层帧收发原语：Linux 下用 AF_PACKET，其它平台仅用于单测编译。
package neti

import "gateweaver/internal/arpframe"

// Transceiver 是单个网络接口上的原始帧收发器。
type Transceiver interface {
	// Iface 绑定的接口名
	Iface() string
	// HardwareAddr 本机接口 MAC
	HardwareAddr() arpframe.MAC
	// Send 发送一个已编码以太网帧
	Send(frame []byte) error
	// Next 阻塞读取下一帧；Close 后返回错误。
	Next() ([]byte, error)
	// Close 释放底层 socket
	Close() error
}

// TransceiverFactory 按接口名创建收发器（引擎在 attach 接口时调用，单测注入 fake）。
type TransceiverFactory func(iface string) (Transceiver, error)
