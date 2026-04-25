# sg-partinit — first-boot GPT partition creator

CROSS_COMPILE ?= aarch64-linux-musl-
CC      := $(CROSS_COMPILE)gcc
CFLAGS  := -Wall -Wextra -Werror -Os -static
BUILD_DIR ?= ../../build/tools

.PHONY: all clean

all: $(BUILD_DIR)/sg-partinit

$(BUILD_DIR)/sg-partinit: sg-partinit.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(BUILD_DIR)/sg-partinit
