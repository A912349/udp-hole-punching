//go:build !linux && !windows

package main

func platformSystemResolver() string { return "1.1.1.1:53" }
