//go:build !linux

package main

import (
	"errors"
	"os"
)

func openTUN(string) (*os.File, error)       { return nil, errors.New("TUN is supported only on Linux") }
func configureTUN(string, string, int) error { return errors.New("TUN is supported only on Linux") }
