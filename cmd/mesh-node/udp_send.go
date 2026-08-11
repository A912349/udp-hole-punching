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
		grouped := make(map[*net.UDPConn][]outboundDatagram)
		connOrder := make([]*net.UDPConn, 0, udpSendBatchSize)
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
			connOrder = connOrder[:0]
			for i := range batch {
				conn := batch[i].conn
				if _, exists := grouped[conn]; !exists {
					connOrder = append(connOrder, conn)
				}
				grouped[conn] = append(grouped[conn], batch[i])
			}
			for _, conn := range connOrder {
				frames := grouped[conn]
				writer := writers[conn]
				if writer == nil {
					writer = newUDPBatchWriter(conn)
					writers[conn] = writer
				}
				sent, err := writer.write(frames)
				for i := 0; i < sent; i++ {
					n.stats.sentPackets.Add(1)
					n.stats.sentBytes.Add(uint64(len(frames[i].data)))
				}
				if err != nil {
					n.debugf("UDP batch send failed after %d/%d packets: %v", sent, len(frames), err)
				}
				delete(grouped, conn)
			}
			for i := range batch {
				n.udpSendPool.Put(batch[i].data[:maxFastFrame])
			}
		}
	}()
}
