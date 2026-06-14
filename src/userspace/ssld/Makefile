# Makefile HOST-TEST cho stargazer-ssld (transparent TLS-inspection proxy).
#
# SPLICE không cần TLS lib; BUMP cần OpenSSL. Bản cross-compile aarch64 cho
# BPI-R4 do root Makefile lo (cần OpenSSL/sysroot aarch64). File này build/test
# nhanh trên host (OpenSSL host có sẵn).
#
#   make test         # relay + ca/certcache + bump (+tls từ ../ipsd)
#   make ssld         # build daemon (cần root + iptables REDIRECT để chạy thật)
#   make clean
#
# Dùng chung peek-SNI + splice/bump decision + signature engine từ ../ipsd.

CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -I. -I../ipsd
SANIT  := -fsanitize=address,undefined
BUILD  := build

# module dùng chung từ ipsd
IPSD   := ../ipsd/tls_clienthello.c ../ipsd/tls_policy.c \
          ../ipsd/sig_rule.c ../ipsd/ac.c

SSLD_SRCS := main.c conn.c relay.c origdst.c ca.c certcache.c bump.c $(IPSD)

.PHONY: test relay-test ca-test bump-test ssld clean

test: relay-test ca-test bump-test
	@echo "== TẤT CẢ SSLD TEST PASS =="

relay-test: $(BUILD)/relay_test
	@echo "--- relay_test (splice byte pump) ---"
	./$(BUILD)/relay_test

ca-test: $(BUILD)/ca_certcache_test
	@echo "--- ca_certcache_test (forge cert + verify chain) ---"
	./$(BUILD)/ca_certcache_test

bump-test: $(BUILD)/bump_test
	@echo "--- bump_test (MITM end-to-end, TLS thật) ---"
	@# OpenSSL có one-time alloc → tắt leak detection (noise, không phải bug ssld)
	ASAN_OPTIONS=detect_leaks=0 ./$(BUILD)/bump_test

$(BUILD)/relay_test: relay.c relay.h relay_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ relay.c relay_test.c -lpthread

$(BUILD)/ca_certcache_test: ca.c certcache.c ca_certcache_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ ca.c certcache.c ca_certcache_test.c \
	    -lssl -lcrypto -lpthread

$(BUILD)/bump_test: ca.c certcache.c bump.c bump_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ ca.c certcache.c bump.c bump_test.c \
	    -lssl -lcrypto -lpthread

ssld: $(BUILD)/stargazer-ssld
	@echo "binary: $(BUILD)/stargazer-ssld"

$(BUILD)/stargazer-ssld: $(SSLD_SRCS) | $(BUILD)
	$(CC) -O2 -Wall -Wextra -std=c11 -I. -I../ipsd \
	    -o $@ $(SSLD_SRCS) -lssl -lcrypto -lpthread

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
