# Stargazer NGFW - Logind + C helpers build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
MGMTD_DIR    := ../mgmtd
CFLAGS       := -Wall -Wextra -Werror -Os -static -I$(COMMON_DIR) -I$(MGMTD_DIR)
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/logind

TARGETS := $(BUILD_DIR)/stargazer-logind \
           $(BUILD_DIR)/stargazer-hashpw \
           $(BUILD_DIR)/stargazer-readline

all: $(TARGETS)

$(BUILD_DIR)/stargazer-logind: stargazer-logind.c $(MGMTD_DIR)/stargazer_ipc.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ stargazer-logind.c $(LDFLAGS)

$(BUILD_DIR)/stargazer-hashpw: stargazer-hashpw.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-readline: stargazer-readline.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
