package main

import "testing"

func TestValidSymmetricSessionID(t *testing.T) {
	if !validSymmetricSessionID("00112233445566778899aabbccddeeff") {
		t.Fatal("valid 128-bit session ID was rejected")
	}
	for _, invalid := range []string{"", "0011", "00112233445566778899aabbccddeefg", "00112233445566778899aabbccddeeff00"} {
		if validSymmetricSessionID(invalid) {
			t.Fatalf("invalid session ID %q was accepted", invalid)
		}
	}
}
