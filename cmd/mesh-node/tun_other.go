//go:build !linux

package main

import (
	"errors"
	"os"
)

func openTUN(string) (*os.File, error)       { return nil, errors.New("TUN is supported only on Linux") }
func configureTUN(string, string, int) error { return errors.New("TUN is supported only on Linux") }
func readTUN(*os.File, []byte) (int, error)  { return 0, errors.New("TUN is supported only on Linux") }
func configureTUNRoutes(string, map[string]bool, map[string]bool) error {
	return errors.New("TUN is supported only on Linux")
}
func configureSystemDNS(string, string, string) error { return nil }
func configureSiteNAT([]string, []string) error       { return nil }
