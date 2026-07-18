//go:build linux

package main

import "os"

func platformSystemResolver() string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err == nil {
		if resolver := resolverFromResolvConf(string(b)); resolver != "" {
			return resolver
		}
	}
	return "1.1.1.1:53"
}
