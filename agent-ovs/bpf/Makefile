# SPDX-License-Identifier: GPL-2.0

LLC ?= llc
CLANG ?= clang
CFLAGS += -Wall -Wno-unused-value -Wno-pointer-sign -D__KERNEL__ -D__TARGET_ARCH_x86 \
	-Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-Wno-unknown-warning-option \
	-fno-stack-protector -I./include

OBJ = bpf_ep.o

%.o: %.c
	@echo "${CLANG}" $@
	$(CLANG) $(CFLAGS) -g -O2 -emit-llvm -c $< -o -| \
	$(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@


all:	$(OBJ)

.PHONY: install
install: 
	install -d /usr/local/bin/bpf
	install -m 700 *.o /usr/local/bin/bpf
	install -m 755 check.sh /usr/local/bin/bpf
	install -m 755 init.sh /usr/local/bin/bpf

.PHONY: clean
clean:
	rm *.o

.PHONY: check
check:
	./check.sh bpf_ep.o ingress ep-ingress
	./check.sh bpf_ep.o ingress vxlan-ingress
