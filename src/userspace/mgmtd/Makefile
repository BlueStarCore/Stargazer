# Stargazer NGFW - Management Daemon + IPC Client build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
CFLAGS       := -Wall -Wextra -Werror -Os -static -I. -I$(COMMON_DIR)
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/mgmtd

TARGETS := $(BUILD_DIR)/stargazer-mgmtd \
           $(BUILD_DIR)/stargazer-ipc-cli

all: $(TARGETS)

$(BUILD_DIR)/stargazer-mgmtd: stargazer-mgmtd.c stargazer_ipc.h $(COMMON_DIR)/password_policy.c $(COMMON_DIR)/password_policy.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ stargazer-mgmtd.c $(COMMON_DIR)/password_policy.c $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-ipc-cli: stargazer-ipc-cli.c stargazer_ipc.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
