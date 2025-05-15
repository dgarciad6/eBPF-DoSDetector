BPF_CLANG ?= clang
BPF_CFLAGS = -O2 -g -Wall -target bpf

LIBBPF_CFLAGS = -Wall -g
LIBBPF_LDLIBS = -lbpf -lelf
CC = gcc

INTERFAZ = eth0
PROG ?= icmp_counter
BPF_SRC = $(PROG).c
BPF_OBJ = $(PROG).o
USER_BIN = main

all: $(USER_BIN) $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(USER_BIN): main.c
	$(CC) $(LIBBPF_CFLAGS) -o $@ $< $(LIBBPF_LDLIBS)

attach:
	sudo tc qdisc add dev $(INTERFAZ) clsact 2>/dev/null || true
	sudo tc filter add dev $(INTERFAZ) ingress bpf da obj $(BPF_OBJ) sec tcx/ingress

detach:
	sudo tc filter delete dev $(INTERFAZ) ingress || true
	sudo tc qdisc del dev $(INTERFAZ) clsact 2>/dev/null || true
	sudo rm -f /sys/fs/bpf/tc/globals/$(PROG)
	rm -f *.o
clean:
	rm -f $(USER_BIN) *.o
