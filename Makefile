# Home UDP Mesh build shortcuts, mirroring the CI recipe in
# .github/workflows/go.yml. Point GO at any Go >= 1.23 toolchain if the
# system one is older, e.g.:
#   make GO=/usr/local/go-1.24/bin/go all

GO ?= go
LDFLAGS := -s -w -buildid=
BIN := bin

.PHONY: all build test vet mips arm64 upx clean mesh-node-pprof-off mesh-node-pprof-on

all: build

build: | $(BIN)
	$(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BIN)/server ./cmd/server
	$(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BIN)/mesh-node ./cmd/mesh-node

test:
	$(GO) test ./cmd/server ./cmd/mesh-node ./internal/protocol

vet:
	$(GO) vet ./...

$(BIN):
	@mkdir -p $(BIN)

# OpenWrt flavor: mesh-node-pprof-off swaps cmd/mesh-node/pprof.go for the
# pprof-openwrt.go.inactive stub (see cmd/mesh-node/) before cross-compiling,
# so net/http/pprof is not linked into the router binary (~1.5 MB unstripped).
mesh-node-pprof-off:
	-mv cmd/mesh-node/pprof.go cmd/mesh-node/pprof.go.off
	-mv cmd/mesh-node/pprof-openwrt.go.inactive cmd/mesh-node/pprof-openwrt.go
mesh-node-pprof-on:
	-mv cmd/mesh-node/pprof.go.off cmd/mesh-node/pprof.go
	-mv cmd/mesh-node/pprof-openwrt.go cmd/mesh-node/pprof-openwrt.go.inactive

# OpenWrt routers (MediaTek MT7621 etc.): MIPS32r2 little-endian, no FPU.
mips: | $(BIN)
	-make mesh-node-pprof-off
	-CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BIN)/mesh-node-linux-mipsle ./cmd/mesh-node
	-make mesh-node-pprof-on

# Coordinator for 64-bit ARM single-board hosts. The coordinator is not
# available for mipsle: sqlite support is unavailable on that platform.
arm64: | $(BIN)
	-CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BIN)/server-linux-arm64 ./cmd/server
	-CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags="$(LDFLAGS)" -o $(BIN)/mesh-node-linux-arm64 ./cmd/mesh-node

upx:
	@if command -v upx >/dev/null; then for f in $(BIN)/*; do upx --best --lzma "$$f"; done; else echo "install upx to compress bin/"; fi

clean:
	$(RM) -r $(BIN)
