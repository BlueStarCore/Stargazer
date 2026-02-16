# Stargazer NGFW - Management Daemon + IPC Client build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
CFLAGS       := -Wall -Wextra -Werror -Os -static -I.
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/mgmtd

TARGETS := $(BUILD_DIR)/stargazer-mgmtd \
           $(BUILD_DIR)/stargazer-ipc-cli

all: $(TARGETS)

$(BUILD_DIR)/stargazer-mgmtd: stargazer-mgmtd.c stargazer_ipc.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-ipc-cli: stargazer-ipc-cli.c stargazer_ipc.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
