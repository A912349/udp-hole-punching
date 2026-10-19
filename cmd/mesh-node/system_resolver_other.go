//go:build !linux && !windows

// This platform has no supported system-resolver lookup.

package main

func platformSystemResolver() string { return "" }
