//go:build !linux

package main

import "net"

// bindUDPInterface is a no-op outside Linux: SO_BINDTODEVICE is a Linux
// socket option, and the mobile policy-routing problem it works around does
// not exist on desktop platforms.
func bindUDPInterface(conn *net.UDPConn, iface string) error {
	_ = conn
	_ = iface
	return nil
}

// defaultRouteInterface has no portable implementation; interface auto-pinning
// stays a Linux feature.
func defaultRouteInterface() string { return "" }
