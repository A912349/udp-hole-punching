//go:build !linux && !windows

package main

import (
	"errors"
)

func openTUN(string) (tunDevice, error) {
	return nil, errors.New("TUN is supported on Linux and Windows")
}
func configureTUN(string, string, int) error {
	return errors.New("TUN is supported on Linux and Windows")
}
func readTUN(tunDevice, []byte) (int, error) {
	return 0, errors.New("TUN is supported only on Linux and Windows")
}
func configureTUNRoutes(string, map[string]bool, map[string]bool) error {
	return errors.New("TUN is supported only on Linux")
}
func configureSystemDNS(string, string, string) error { return nil }
func configureSiteNAT([]string, []string) error       { return nil }
func cleanupTUN(string, map[string]bool)              {}
func configurePlatformNetwork(int) error              { return nil }
func cleanupPlatformNetwork(int)                      {}
