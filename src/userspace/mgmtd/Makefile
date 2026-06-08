# Stargazer NGFW - Management Daemon + IPC Client build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
CFLAGS       := -Wall -Wextra -Werror -Os -static -I. -I$(COMMON_DIR)
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/mgmtd

# SQLite amalgamation: third-party, compile without -Werror
# -U_FORTIFY_SOURCE: musl lacks __memcpy_chk / __memset_chk
# -Dfcntl64=fcntl:   musl provides fcntl only (already 64-bit)
SQLITE_CFLAGS := -Wall -Os -static -I. \
                 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 \
                 -Dfcntl64=fcntl \
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
                     mgmtd_apply_nat.c mgmtd_apply_dns.c mgmtd_apply_dhcp.c \
                     mgmtd_apply_firewall.c mgmtd_apply_ntp.c \
                     mgmtd_apply_ssl.c mgmtd_sequence.c

MGMTD_SRCS := mgmtd_user.c mgmtd_firmware.c mgmtd_network.c mgmtd_diag.c \
              mgmtd_ipset.c mgmtd_fqdn.c

$(BUILD_DIR)/stargazer-mgmtd: stargazer-mgmtd.c stargazer_ipc.h mgmtd_apply.h \
                               mgmtd_internal.h mgmtd_sequence.h \
                               $(MGMTD_SRCS) $(MGMTD_APPLY_SRCS) \
                               sg_db.c sg_db.h \
                               $(COMMON_DIR)/password_policy.c $(COMMON_DIR)/password_policy.h \
                               $(COMMON_DIR)/sg_validate.c $(COMMON_DIR)/sg_validate.h \
                               $(BUILD_DIR)/sqlite3.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ stargazer-mgmtd.c $(MGMTD_SRCS) $(MGMTD_APPLY_SRCS) \
		sg_db.c $(COMMON_DIR)/password_policy.c \
		$(COMMON_DIR)/sg_validate.c $(BUILD_DIR)/sqlite3.o $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-ipc-cli: stargazer-ipc-cli.c stargazer_ipc.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) $(BUILD_DIR)/sqlite3.o

.PHONY: all clean
