//go:build !linux && !android

package main

import "net"

type singleUDPBatchWriter struct {
	conn *net.UDPConn
}

func newUDPBatchWriter(conn *net.UDPConn) udpBatchWriter {
	return &singleUDPBatchWriter{conn: conn}
}

func (w *singleUDPBatchWriter) write(batch []outboundDatagram) (int, error) {
	for i := range batch {
		if _, err := w.conn.WriteToUDP(batch[i].data, batch[i].address); err != nil {
			return i, err
		}
	}
	return len(batch), nil
}
