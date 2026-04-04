# SPDX-License-Identifier: MIT
# Makefile for stargazer-webd — embedded HTTP daemon
#
# Same pattern as cli/Makefile: cross-compile with musl, static linking.
# Mongoose is compiled with relaxed CFLAGS (third-party amalgamation).

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
MGMTD_DIR    := ../mgmtd
CFLAGS       := -Wall -Wextra -Werror -Os -static -I. -I$(MGMTD_DIR) -I$(COMMON_DIR) -pthread
LDFLAGS      := -static -lpthread
BUILD_DIR    ?= ../../../build/webd

# Mongoose: third-party amalgamation, relaxed warnings
# MG_TLS=MG_TLS_BUILTIN enables built-in TLS (no OpenSSL dependency)
MG_CFLAGS    := -Wall -Os -static -I. \
                -DMG_ENABLE_LINES=0 -DMG_ENABLE_SSI=0 \
                -DMG_ENABLE_DIRLIST=0 \
                -DMG_TLS=MG_TLS_BUILTIN

SRCS := stargazer-webd.c webd_api.c webd_ipc.c webd_pool.c \
        webd_session.c webd_sandbox.c $(COMMON_DIR)/sg_validate.c

HEADERS := webd_api.h webd_ipc.h webd_pool.h webd_session.h \
           webd_sandbox.h mongoose.h $(MGMTD_DIR)/stargazer_ipc.h

TARGET := $(BUILD_DIR)/stargazer-webd

all: $(TARGET)

$(BUILD_DIR)/mongoose.o: mongoose.c mongoose.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(MG_CFLAGS) -c -o $@ mongoose.c

$(TARGET): $(SRCS) $(HEADERS) $(BUILD_DIR)/mongoose.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(BUILD_DIR)/mongoose.o $(LDFLAGS)

clean:
	rm -f $(TARGET) $(BUILD_DIR)/mongoose.o

.PHONY: all clean
