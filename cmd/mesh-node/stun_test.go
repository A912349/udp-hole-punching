package main

import (
	"encoding/binary"
	"testing"
)

func TestSTUNMappedEndpoint(t *testing.T) {
	transaction := [12]byte{1, 2, 3, 4}
	response := make([]byte, 32)
	binary.BigEndian.PutUint16(response, 0x0101)
	binary.BigEndian.PutUint16(response[2:], 12)
	binary.BigEndian.PutUint32(response[4:], 0x2112A442)
	copy(response[8:], transaction[:])
	binary.BigEndian.PutUint16(response[20:], 0x0020)
	binary.BigEndian.PutUint16(response[22:], 8)
	response[25] = 1
	binary.BigEndian.PutUint16(response[26:], 12345^0x2112)
	binary.BigEndian.PutUint32(response[28:], 0x01020304^0x2112A442)

	endpoint, ok := stunMappedEndpoint(response, transaction)
	if !ok || endpoint != "1.2.3.4:12345" {
		t.Fatalf("stunMappedEndpoint() = %q, %v", endpoint, ok)
	}
	transaction[0]++
	if _, ok := stunMappedEndpoint(response, transaction); ok {
		t.Fatal("STUN response with another transaction was accepted")
	}
}
