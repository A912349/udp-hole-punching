package main

import (
	"context"
	"net"
)

type udpBatchWriter interface {
	write([]outboundDatagram) (int, error)
}

func (n *node) startUDPSender(ctx context.Context) {
	n.udpSendQueue = make(chan outboundDatagram, udpSendQueueSize)
	n.udpSendPool.New = func() any { return make([]byte, maxFastFrame) }
	go func() {
		writers := make(map[*net.UDPConn]udpBatchWriter)
		batch := make([]outboundDatagram, 0, udpSendBatchSize)
		for {
			select {
			case <-ctx.Done():
				return
			case first, ok := <-n.udpSendQueue:
				if !ok {
					return
				}
				batch = append(batch[:0], first)
			}
			for len(batch) < cap(batch) {
				select {
				case frame, ok := <-n.udpSendQueue:
					if !ok {
						return
					}
					batch = append(batch, frame)
				default:
					goto send
				}
			}
		send:
			for start := 0; start < len(batch); {
				conn := batch[start].conn
				end := start + 1
				for end < len(batch) && batch[end].conn == conn {
					end++
				}
				writer := writers[conn]
				if writer == nil {
					writer = newUDPBatchWriter(conn)
					writers[conn] = writer
				}
				sent, err := writer.write(batch[start:end])
				for i := start; i < start+sent; i++ {
					n.stats.sentPackets.Add(1)
					n.stats.sentBytes.Add(uint64(len(batch[i].data)))
				}
				if err != nil {
					n.debugf("UDP batch send failed after %d/%d packets: %v", sent, end-start, err)
				}
				start = end
			}
			for i := range batch {
				n.udpSendPool.Put(batch[i].data[:maxFastFrame])
			}
		}
	}()
}
