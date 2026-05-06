# Stargazer NGFW - NetFlow v9 exporter daemon
# Cross-compile for ARM64 with musl static linking

CC        := $(CROSS_COMPILE)gcc
CFLAGS    := -Wall -Wextra -Werror -Os -static -I../../modules
BUILD_DIR ?= ../../../build/flowd

TARGET := $(BUILD_DIR)/sg-flowd

all: $(TARGET)

$(TARGET): sg-flowd.c ../../modules/sg_flow.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ sg-flowd.c

clean:
	rm -f $(TARGET)

.PHONY: all clean
