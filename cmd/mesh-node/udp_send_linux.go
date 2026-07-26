//go:build linux || android

package main

import (
	"net"

	"golang.org/x/net/ipv4"
)

type linuxUDPBatchWriter struct {
	conn     *ipv4.PacketConn
	messages []ipv4.Message
}

func newUDPBatchWriter(conn *net.UDPConn) udpBatchWriter {
	return &linuxUDPBatchWriter{
		conn:     ipv4.NewPacketConn(conn),
		messages: make([]ipv4.Message, udpSendBatchSize),
	}
}

func (w *linuxUDPBatchWriter) write(batch []outboundDatagram) (int, error) {
	for i := range batch {
		w.messages[i].Buffers = [][]byte{batch[i].data}
		w.messages[i].Addr = batch[i].address
	}
	return w.conn.WriteBatch(w.messages[:len(batch)], 0)
}
