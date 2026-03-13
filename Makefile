
CLANG      := /usr/bin/clang
CC         ?= gcc
BPFTOOL    ?= bpftool

PROJECT    := edr
VMLINUX_H  := bpf/vmlinux.h

BPF_SRC    := bpf/edr_bpf.bpf.c
BPF_OBJ    := edr_bpf.bpf.o

DB         := edr.db
DB_JOURNAL := edr.db-journal

USER_SRC   := src/main.c	\
			  src/storage.c	\
			  src/filters.c	\
			  src/tracker.c	\
			  src/rules.c	\
			  src/insert_event.c	\
			  src/rules/file_access_rules.c	\
			  src/rules/exec_rules.c	\
			  src/rules/network_rules.c	\
			  src/rules/process_anomalies_rules.c

USER_BIN   := $(PROJECT)

INC_DIRS   := -Iinclude -Ibpf -I.
CFLAGS     := -O2 -Wall -Wextra -Iinclude
LDFLAGS    := -lbpf -lelf -lz -lsqlite3

BPF_DEFS   := -D__BPF__ -D__TARGET_ARCH_x86

.PHONY: all run clean fclean re

all: $(VMLINUX_H) $(BPF_OBJ) $(USER_BIN)

$(VMLINUX_H):
	@mkdir -p bpf
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX_H)

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX_H) include/edr_event.h
	$(CLANG) -O2 -g -target bpf $(BPF_DEFS) \
		$(INC_DIRS) \
		-c $(BPF_SRC) -o $(BPF_OBJ)

$(USER_BIN): $(USER_SRC) include/edr_event.h
	$(CC) $(CFLAGS) $(USER_SRC) -o $(USER_BIN) $(LDFLAGS)

run: all
	sudo ./$(USER_BIN)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
	rm -f $(DB) $(DB_JOURNAL)

fclean: clean
	rm -f $(VMLINUX_H)

re: fclean all