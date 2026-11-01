# Kernel Module
obj-m += firewall_main.o

# Kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

# Userspace compiler
CC := gcc
CFLAGS := -Wall -Wextra -O2

# Default target: build both
all: module firewallctl

# Build Kernel Module
module:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# Build userspace control tool
firewallctl: firewallctl.c
	$(CC) $(CFLAGS) -o $@ $<

# Clean generated files
clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -f firewallctl

.PHONY: all module clean