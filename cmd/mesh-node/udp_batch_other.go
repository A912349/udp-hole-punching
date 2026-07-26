//go:build !linux && !android

package main

import (
	"net"

	"home-udp-mesh/internal/protocol"
)

type singleUDPBatchReader struct {
	conn     *net.UDPConn
	buffer   []byte
	datagram [1]receivedDatagram
}

func newUDPBatchReader(conn *net.UDPConn) udpBatchReader {
	return &singleUDPBatchReader{
		conn:   conn,
		buffer: make([]byte, protocol.MaxDatagramSize),
	}
}

func (r *singleUDPBatchReader) read() ([]receivedDatagram, error) {
	length, address, err := r.conn.ReadFromUDP(r.buffer)
	if err != nil {
		return nil, err
	}
	r.datagram[0] = receivedDatagram{data: r.buffer[:length], address: address}
	return r.datagram[:], nil
}
