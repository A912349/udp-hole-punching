//go:build linux && (mips || mipsle || mips64 || mips64le)

package main

// Linux on MIPS encodes ioctl direction and size bits differently
// (_IOC_DIRBITS = 3, _IOC_SIZEBITS = 13 in asm/ioctl.h), so the same
// _IOW('T', 202, int) request yields another value for TUNSETIFF.
const tunSetIFF = 0x200454ca
