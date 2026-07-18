package main

import "io"

// tunDevice is deliberately small so the data plane can use the native Linux
// file descriptor and the Windows Wintun session through the same code.
type tunDevice interface {
	io.Reader
	io.Writer
	io.Closer
}
