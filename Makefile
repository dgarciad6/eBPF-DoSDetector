# Compiladores y flags
BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf

LIBBPF_CFLAGS = -Wall -g
LIBBPF_LDLIBS = -lbpf -lelf
CC = gcc

# Variables configurables
PROG ?= ejemplo
IFACE ?= eth0
MODE ?= tc
TYPE ?= IDS
SECTION ?= tc

# Rutas
BPF_SRC := $(PROG).c
BPF_OBJ := $(PROG).o
USER_BIN := main

# Objetivo por defecto
all: $(USER_BIN) $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): main.c
	$(CC) $(LIBBPF_CFLAGS) -o $@ $< $(LIBBPF_LDLIBS)

# ---- TC ----
attach-tc: $(BPF_OBJ)
	sudo tc qdisc add dev $(IFACE) clsact 2>/dev/null || true
	sudo tc filter add dev $(IFACE) ingress bpf da obj $(BPF_OBJ) sec tcx/ingress

detach-tc:
	sudo tc filter delete dev $(IFACE) ingress || true
	sudo tc qdisc del dev $(IFACE) clsact 2>/dev/null || true
	sudo rm -f /sys/fs/bpf/tc/globals/*

# ---- XDP ----
attach-xdp: $(BPF_OBJ)
	sudo ip link set dev $(IFACE) xdp obj $(BPF_OBJ) sec $(SECTION)

detach-xdp:
	sudo ip link set dev $(IFACE) xdp off
	sudo rm -f /sys/fs/bpf/$(PROG)

# Limpieza
clean:
	rm -f $(USER_BIN) */*/*.o */*/*.o

