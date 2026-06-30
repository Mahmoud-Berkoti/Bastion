# Bastion build. Run inside a Linux environment with BTF enabled
# (see Vagrantfile). `make all` builds the BPF object and the Go binary.

CLANG   ?= clang
BPFTOOL ?= bpftool
GO      ?= go

ARCH := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

BPF_SRC := bpf/bastion.bpf.c
BPF_OBJ := bpf/bastion.bpf.o
VMLINUX := bpf/vmlinux.h

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Werror -Ibpf

.PHONY: all bpf go vmlinux test vet setup-veth teardown-veth run bench clean

all: bpf go

# Generate CO-RE type definitions from the running kernel's BTF.
vmlinux: $(VMLINUX)
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

bpf: $(BPF_OBJ)
$(BPF_OBJ): $(BPF_SRC) bpf/common.h $(VMLINUX)
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@

go:
	$(GO) build -o bin/bastion ./cmd/bastion

vet:
	$(GO) vet ./...

# BPF_PROG_TEST_RUN unit tests need root (BPF syscalls) but no NIC.
# Resolve the go binary now: sudo's secure_path usually lacks it.
test: bpf vet
	sudo -E $(shell which $(GO)) test ./test/... -count=1 -v

# veth pair in a netns for safe XDP testing (never your real NIC).
setup-veth:
	sudo ./scripts/setup_veth.sh up
teardown-veth:
	sudo ./scripts/setup_veth.sh down

run: all
	sudo ./bin/bastion -iface veth-host -config config/rules.yaml

bench: all
	sudo ./bench/compare_iptables.sh

clean:
	rm -f $(BPF_OBJ) bin/bastion
