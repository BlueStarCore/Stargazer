# Stargazer NGFW - Management Daemon + IPC Client build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
CFLAGS       := -Wall -Wextra -Werror -Os -static -I. -I$(COMMON_DIR)
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/mgmtd

# SQLite amalgamation: third-party, compile without -Werror
SQLITE_CFLAGS := -Wall -Os -static -I. \
                 -DSQLITE_THREADSAFE=0 \
                 -DSQLITE_OMIT_LOAD_EXTENSION \
                 -DSQLITE_OMIT_DEPRECATED

TARGETS := $(BUILD_DIR)/stargazer-mgmtd \
           $(BUILD_DIR)/stargazer-ipc-cli

all: $(TARGETS)

$(BUILD_DIR)/sqlite3.o: sqlite3.c sqlite3.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SQLITE_CFLAGS) -c -o $@ sqlite3.c

MGMTD_APPLY_SRCS := mgmtd_apply_route.c mgmtd_apply_iface.c \
                     mgmtd_apply_nat.c mgmtd_apply_dns.c mgmtd_apply_dhcp.c

$(BUILD_DIR)/stargazer-mgmtd: stargazer-mgmtd.c stargazer_ipc.h mgmtd_apply.h \
                               $(MGMTD_APPLY_SRCS) \
                               sg_db.c sg_db.h \
                               $(COMMON_DIR)/password_policy.c $(COMMON_DIR)/password_policy.h \
                               $(COMMON_DIR)/sg_validate.c $(COMMON_DIR)/sg_validate.h \
                               $(BUILD_DIR)/sqlite3.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ stargazer-mgmtd.c $(MGMTD_APPLY_SRCS) \
		sg_db.c $(COMMON_DIR)/password_policy.c \
		$(COMMON_DIR)/sg_validate.c $(BUILD_DIR)/sqlite3.o $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-ipc-cli: stargazer-ipc-cli.c stargazer_ipc.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) $(BUILD_DIR)/sqlite3.o

.PHONY: all clean
