//go:build linux && !mips && !mipsle && !mips64 && !mips64le

package main

// TUNSETIFF on architectures with the generic Linux ioctl encoding
// (x86, arm, arm64, riscv, ...): _IOW('T', 202, int).
const tunSetIFF = 0x400454ca
