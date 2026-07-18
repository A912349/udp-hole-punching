//go:build windows

package main

import (
	"net"
	"os/exec"
	"strings"
	"unicode"
)

// Windows keeps resolver configuration in the network stack rather than
// /etc/resolv.conf. ipconfig is available on supported Windows versions and
// gives us the same upstream selection behaviour as the Linux implementation.
func platformSystemResolver() string {
	out, err := exec.Command("ipconfig", "/all").Output()
	if err == nil {
		inDNSServers := false
		for _, line := range strings.Split(string(out), "\n") {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "dns servers") {
				inDNSServers = true
			} else if !inDNSServers || line == "" || !unicode.IsSpace(rune(line[0])) {
				inDNSServers = false
				continue
			}
			value := line
			if _, after, ok := strings.Cut(line, ":"); ok {
				value = after
			}
			for _, field := range strings.Fields(value) {
				if ip := net.ParseIP(field); ip != nil && ip.To4() != nil && !isMeshDNSAddress(ip) {
					return net.JoinHostPort(ip.String(), "53")
				}
			}
		}
	}
	return "1.1.1.1:53"
}
