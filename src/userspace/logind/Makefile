# Stargazer NGFW - Logind + C helpers build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
CFLAGS       := -Wall -Wextra -Werror -Os -static -I$(COMMON_DIR)
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/logind

TARGETS := $(BUILD_DIR)/stargazer-logind \
           $(BUILD_DIR)/stargazer-hashpw \
           $(BUILD_DIR)/stargazer-readline

all: $(TARGETS)

$(BUILD_DIR)/stargazer-logind: stargazer-logind.c $(COMMON_DIR)/password_policy.c $(COMMON_DIR)/password_policy.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ stargazer-logind.c $(COMMON_DIR)/password_policy.c $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-hashpw: stargazer-hashpw.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-readline: stargazer-readline.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS)

.PHONY: all clean
