//go:build linux || android

package main

import (
	"net"

	"golang.org/x/net/ipv4"

	"home-udp-mesh/internal/protocol"
)

// A small batch amortizes recvmmsg overhead without keeping a large burst in
// userspace while the node is handling earlier packets.
const udpReceiveBatchSize = 16

type linuxUDPBatchReader struct {
	conn      *ipv4.PacketConn
	messages  []ipv4.Message
	datagrams []receivedDatagram
}

func newUDPBatchReader(conn *net.UDPConn) udpBatchReader {
	r := &linuxUDPBatchReader{
		conn:      ipv4.NewPacketConn(conn),
		messages:  make([]ipv4.Message, udpReceiveBatchSize),
		datagrams: make([]receivedDatagram, udpReceiveBatchSize),
	}
	for i := range r.messages {
		r.messages[i].Buffers = [][]byte{make([]byte, protocol.MaxDatagramSize)}
	}
	return r
}

func (r *linuxUDPBatchReader) read() ([]receivedDatagram, error) {
	n, err := r.conn.ReadBatch(r.messages, 0)
	if err != nil {
		return nil, err
	}
	for i := 0; i < n; i++ {
		address, ok := r.messages[i].Addr.(*net.UDPAddr)
		if !ok {
			continue
		}
		r.datagrams[i] = receivedDatagram{
			data:    r.messages[i].Buffers[0][:r.messages[i].N],
			address: address,
		}
	}
	return r.datagrams[:n], nil
}
