# Stargazer NGFW - C CLI binary build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
CFLAGS       := -Wall -Wextra -Werror -Os -static -I. -I../mgmtd
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/cli
VERSION      ?= dev

SRCS := stargazer-cli.c \
        cli_readline.c \
        cli_ipc.c \
        cli_configure.c \
        cli_registry.c \
        cli_dispatch.c \
        cli_diagnose.c

HEADERS := cli_readline.h cli_ipc.h cli_configure.h cli_registry.h cli_dispatch.h \
           cli_diagnose.h ../mgmtd/stargazer_ipc.h

TARGET := $(BUILD_DIR)/stargazer-cli

all: $(TARGET)

$(TARGET): $(SRCS) $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
