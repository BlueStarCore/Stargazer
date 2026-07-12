# HOST-TEST Makefile for stargazer-ssld (transparent TLS-inspection proxy).
#
# SPLICE needs no TLS lib; BUMP needs OpenSSL. The aarch64 cross-compile build
# for the BPI-R4 is handled by the root Makefile (needs an aarch64
# OpenSSL/sysroot). This file builds/tests quickly on the host (the host OpenSSL
# is available).
#
#   make test         # relay + ca/certcache + bump (+tls from ../ipsd)
#   make ssld         # build the daemon (needs root + iptables REDIRECT to run live)
#   make clean
#
# Shares peek-SNI + the splice/bump decision + the signature engine from ../ipsd.

CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11 -I. -I../ipsd
SANIT  := -fsanitize=address,undefined
BUILD  := build

# shared modules from ipsd
IPSD   := ../ipsd/tls_clienthello.c ../ipsd/tls_policy.c \
          ../ipsd/sig_rule.c ../ipsd/ac.c

SSLD_SRCS := main.c conn.c relay.c origdst.c ca.c certcache.c bump.c revmap.c $(IPSD)

.PHONY: test relay-test ca-test bump-test ssld clean

test: relay-test ca-test bump-test
	@echo "== ALL SSLD TESTS PASS =="

relay-test: $(BUILD)/relay_test
	@echo "--- relay_test (splice byte pump) ---"
	./$(BUILD)/relay_test

ca-test: $(BUILD)/ca_certcache_test
	@echo "--- ca_certcache_test (forge cert + verify chain) ---"
	./$(BUILD)/ca_certcache_test

bump-test: $(BUILD)/bump_test
	@echo "--- bump_test (MITM end-to-end, real TLS) ---"
	@# OpenSSL has one-time allocs -> disable leak detection (noise, not an ssld bug)
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
