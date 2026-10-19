//go:build linux

// platformSystemResolver reads the configured upstream DNS server on Linux.

package main

import "os"

func platformSystemResolver() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		if resolver := resolverFromResolvConf(string(b)); resolver != "" {
			return resolver
		}
	}
	return ""
}
