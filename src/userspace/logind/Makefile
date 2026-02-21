# Stargazer NGFW - Logind + C helpers build
# Cross-compile for ARM64 with musl static linking

CC           := $(CROSS_COMPILE)gcc
COMMON_DIR   := ../common
MGMTD_DIR    := ../mgmtd
CFLAGS       := -Wall -Wextra -Werror -Os -static -I$(COMMON_DIR) -I$(MGMTD_DIR)
SQLITE_CFLAGS := -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION -Os -static
LDFLAGS      := -static
BUILD_DIR    ?= ../../../build/logind

TARGETS := $(BUILD_DIR)/stargazer-logind \
           $(BUILD_DIR)/stargazer-hashpw \
           $(BUILD_DIR)/stargazer-readline

all: $(TARGETS)

$(BUILD_DIR)/stargazer-logind: stargazer-logind.c $(MGMTD_DIR)/sg_db.c $(MGMTD_DIR)/sg_db.h \
                                $(COMMON_DIR)/password_policy.c $(COMMON_DIR)/password_policy.h \
                                $(BUILD_DIR)/sqlite3.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ stargazer-logind.c $(MGMTD_DIR)/sg_db.c \
		$(COMMON_DIR)/password_policy.c $(BUILD_DIR)/sqlite3.o $(LDFLAGS) -lcrypt

$(BUILD_DIR)/sqlite3.o: $(MGMTD_DIR)/sqlite3.c $(MGMTD_DIR)/sqlite3.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(SQLITE_CFLAGS) -c -o $@ $(MGMTD_DIR)/sqlite3.c

$(BUILD_DIR)/stargazer-hashpw: stargazer-hashpw.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) -lcrypt

$(BUILD_DIR)/stargazer-readline: stargazer-readline.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGETS) $(BUILD_DIR)/sqlite3.o

.PHONY: all clean
