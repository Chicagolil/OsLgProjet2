CLANG := clang
CC := gcc

BPF_CFLAGS := -O2 -g -Wall -target bpf -D __TARGET_ARCH_x86
USER_CFLAGS := -O2 -g -Wall
LIBS := -lbpf -lelf -lz

VMLINUX := /sys/kernel/btf/vmlinux

all: prog

vmlinux.h:
		bpftool btf dump file $(VMLINUX) format c > vmlinux.h

prog.bpf.o: prog.bpf.c vmlinux.h
		$(CLANG) $(BPF_CFLAGS) -c prog.bpf.c -o prog.bpf.o

prog: prog.c prog.bpf.o
		$(CC) $(USER_CFLAGS) prog.c -o prog $(LIBS)

clean:
		rm -f prog prog.bpf.o vmlinux.h
