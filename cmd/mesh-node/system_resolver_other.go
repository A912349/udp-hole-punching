//go:build !linux && !windows

package main

func platformSystemResolver() string { return "" }
