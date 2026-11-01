# Build the C mount core.
#
#   make                                  # device build, -O2
#   make CC=aarch64-linux-android-clang   # cross build
#   make test MM_MODULE_DIR='"/tmp/x/modules"' MM_ROOT_PREFIX='"/tmp/x/root"'
#   make lkm KDIR=<android-gki-kernel-tree>   # build kernel/magic_hide/magic_hide.ko

CC      ?= clang
CFLAGS  ?= -O2 -Wall -Wextra -std=c11 -pthread
LDFLAGS ?= -pthread

BIN := magic_mount
SRC := magic_mount.c
KDIR ?= /lib/modules/$(shell uname -r)/build
LKM_DIR := $(CURDIR)/kernel/magic_hide

all: $(BIN)

$(BIN): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@ $(LDFLAGS)

# Host-only build used by the sandbox tests (paths come from the command line).
test: $(SRC)
	$(CC) $(CFLAGS) -DMM_MODULE_DIR=$(MM_MODULE_DIR) \
		-DMM_ROOT_PREFIX=$(MM_ROOT_PREFIX) $(SRC) -o $(BIN)_test

# Needs a configured kernel tree matching the device (GKI 5.10/5.15/6.1/6.6).
lkm:
	$(MAKE) -C $(KDIR) M=$(LKM_DIR) modules

clean:
	rm -f $(BIN) $(BIN)_test
	-@test -d $(KDIR) && $(MAKE) -C $(KDIR) M=$(LKM_DIR) clean

.PHONY: all test lkm clean
