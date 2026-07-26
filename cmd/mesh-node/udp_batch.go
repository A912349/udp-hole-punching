package main

import "net"

type receivedDatagram struct {
	data    []byte
	address *net.UDPAddr
}

type udpBatchReader interface {
	read() ([]receivedDatagram, error)
}
