# Stargazer NGFW - C CLI binary build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
CFLAGS       := -Wall -Wextra -Werror -Os -static -I. -I../mgmtd -I$(COMMON_DIR)
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/cli
VERSION      ?= dev

SRCS := stargazer-cli.c \
        cli_readline.c \
        cli_ipc.c \
        cli_configure.c \
        cli_cmd_table.c \
        cli_dispatch.c \
        cli_diagnose.c \
        cli_diagnose_config.c \
        cli_diagnose_fw.c \
        cli_diagnose_upgrade.c \
        cli_diagnose_sys.c \
        cli_diagnose_sandbox.c \
        cli_diagnose_db.c \
        cli_diagnose_pentest.c \
        cli_show.c \
        cli_debug.c \
        cli_sandbox.c \
        $(COMMON_DIR)/sg_validate.c

HEADERS := cli_readline.h cli_ipc.h cli_configure.h cli_cmd_table.h \
           cli_dispatch.h cli_diagnose.h cli_diagnose_sys.h cli_show.h \
           cli_debug.h cli_sandbox.h \
           $(COMMON_DIR)/sg_validate.h ../mgmtd/stargazer_ipc.h

TARGET := $(BUILD_DIR)/stargazer-cli

all: $(TARGET)

$(TARGET): $(SRCS) $(HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -DVERSION=\"$(VERSION)\" -o $@ $(SRCS) $(LDFLAGS)

clean:
	rm -f $(TARGET)

.PHONY: all clean
