GO ?= /opt/go-1.27/bin/go
OUT := out
TOOLS := $(OUT)/ppdump $(OUT)/ppreport

.PHONY: tools lab-profile project-profile clean

tools: $(TOOLS)

$(OUT):
	mkdir -p $@

$(OUT)/ppdump: tools/ppdump.go | $(OUT)
	$(GO) build -o $@ $<

$(OUT)/ppreport: tools/ppreport.go | $(OUT)
	$(GO) build -o $@ $<

lab-profile: tools
	$(GO) test -c -o $(OUT)/labx.test ./scratch/labx
	$(OUT)/labx.test -test.bench=. -test.cpuprofile=$(OUT)/labx.pb.gz
	gunzip -c $(OUT)/labx.pb.gz > $(OUT)/labx.pb
	$(OUT)/ppreport $(OUT)/labx.pb

project-profile: tools
	mkdir -p $(OUT)/profile
	$(GO) test -run '^$$' -bench BenchmarkHotPathCrypto -benchtime=$${BENCHTIME:-10s} \
		-cpuprofile=$(OUT)/profile/h.pb.gz ./../cmd/mesh-node
	gunzip -c $(OUT)/profile/h.pb.gz > $(OUT)/profile/h.pb
	$(OUT)/ppreport $(OUT)/profile/h.pb

clean:
	rm -rf $(OUT)
