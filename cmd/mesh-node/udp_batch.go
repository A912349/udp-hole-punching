// Package main uses these shared datagram types to batch UDP I/O where the platform supports it.

package main

import "net"

type receivedDatagram struct {
	data    []byte
	address *net.UDPAddr
}

type udpBatchReader interface {
	read() ([]receivedDatagram, error)
}
