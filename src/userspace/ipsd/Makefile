# HOST-TEST Makefile for stargazer-ipsd (runs on the dev machine with native gcc).
#
# This is NOT the production build — the musl-static cross-compile for BPI-R4 is
# handled by the root Makefile (see docs/ips-master-plan.md §4). This file is
# only for quick unit tests + harnesses on the host.
#
#   make test         # build + run ac_test and sig_test (with ASan/UBSan)
#   make ac-test      # only the Aho-Corasick test
#   make sig-test     # only the rule parser test
#   make sig-dump     # build harness; then: ./build/sig_dump <file.rules> [payload] [dport]
#   make et RULES=/tmp/et-scan.rules PAYLOAD="USER root" DPORT=21
#   make clean

CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
SANIT  := -fsanitize=address,undefined
BUILD  := build

# P4 — if the host has libpcre2-8 → also test the pcre path (HAVE_PCRE). If not →
# build without pcre (pcre rules CLAMPED to ALERT), tests still run.
HAVE_PCRE := $(shell pkg-config --exists libpcre2-8 2>/dev/null && echo 1)
ifeq ($(HAVE_PCRE),1)
  PCRE_FLAGS := -DHAVE_PCRE $(shell pkg-config --cflags --libs libpcre2-8)
endif

# Shared engine sources (does NOT include files containing main()).
CORE   := ac.c sig_rule.c
HDR    := ac.h sig_rule.h

.PHONY: test ac-test sig-test feat-test model-test fusion-test engine-test reload-test ctdump-test nfq-test tls-test tls-policy-test reass-test ipsd sig-dump et rules-fetch clean

test: ac-test sig-test feat-test model-test fusion-test engine-test reload-test ctdump-test nfq-test tls-test tls-policy-test reass-test
	@echo "== ALL TESTS PASS =="

ac-test: $(BUILD)/ac_test
	@echo "--- running ac_test ---"
	./$(BUILD)/ac_test

sig-test: $(BUILD)/sig_test
	@echo "--- running sig_test ---"
	./$(BUILD)/sig_test

feat-test: $(BUILD)/feature_test
	@echo "--- running feature_test ---"
	./$(BUILD)/feature_test

model-test: $(BUILD)/model_test
	@echo "--- running model_test ---"
	./$(BUILD)/model_test

fusion-test: $(BUILD)/fusion_test
	@echo "--- running fusion_test ---"
	./$(BUILD)/fusion_test

engine-test: $(BUILD)/engine_test
	@echo "--- running engine_test (hybrid pipeline) ---"
	./$(BUILD)/engine_test


nfq-test: $(BUILD)/nfq_test
	@echo "--- running nfq_test (parse, host) ---"
	./$(BUILD)/nfq_test

tls-test: $(BUILD)/tls_clienthello_test
	@echo "--- running tls_clienthello_test (parse SNI, host) ---"
	./$(BUILD)/tls_clienthello_test

tls-policy-test: $(BUILD)/tls_policy_test
	@echo "--- running tls_policy_test (splice/bump decision, host) ---"
	./$(BUILD)/tls_policy_test

reass-test: $(BUILD)/reass_test
	@echo "--- running reass_test (TCP stream reassembly + streaming AC, host) ---"
	./$(BUILD)/reass_test

ctdump-test: $(BUILD)/ctdump_test
	@echo "--- running ctdump_test (host, no kernel needed) ---"
	./$(BUILD)/ctdump_test

reload-test: $(BUILD)/reload_test $(BUILD)/reload_test_tsan
	@echo "--- running reload_test (ASan) ---"
	./$(BUILD)/reload_test
	@echo "--- running reload_test_tsan (TSan T4) ---"
	setarch "$$(uname -m)" -R ./$(BUILD)/reload_test_tsan

ipsd: $(BUILD)/stargazer-ipsd
	@echo "binary: $(BUILD)/stargazer-ipsd"

sig-dump: $(BUILD)/sig_dump
	@echo "usage: ./$(BUILD)/sig_dump <file.rules> [payload] [dport] [tcp|udp|icmp]"

# ET OPEN ruleset for load testing — kept in rules/ so it survives reboots.
# `make et` downloads it automatically if missing.
#   make et                                  # load + report
#   make et PAYLOAD="USER root" DPORT=21      # load + test match
ET_URL  := https://rules.emergingthreats.net/open/snort-2.9.20/rules/emerging-scan.rules
RULES   ?= rules/emerging-scan.rules
PAYLOAD ?=
DPORT   ?=

rules/emerging-scan.rules:
	@mkdir -p rules
	curl -fsSL --max-time 30 -o $@ $(ET_URL)

rules-fetch: rules/emerging-scan.rules
	@echo "ruleset ready: $<"

et: $(BUILD)/sig_dump $(RULES)
	./$(BUILD)/sig_dump "$(RULES)" $(if $(PAYLOAD),"$(PAYLOAD)") $(DPORT)

# --- build rules ---------------------------------------------------------
$(BUILD)/ac_test: ac.c ac.h ac_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ ac.c ac_test.c

$(BUILD)/sig_test: $(CORE) $(HDR) sig_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ $(CORE) proto_buf.c tls_clienthello.c sig_test.c $(PCRE_FLAGS)

$(BUILD)/feature_test: feature.c feature.h feature_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ feature.c feature_test.c -lm

# Machine-generated model (tl2cgen): built separately with -w (suppress
# generated-code warnings), no sanitizer for speed. Linked into test/daemon.
$(BUILD)/predict.o: model/predict.c model/predict.h | $(BUILD)
	$(CC) -O2 -w -c -o $@ model/predict.c

$(BUILD)/model_test: ips_model.c ips_model.h feature.h model/predict.h model_test.c $(BUILD)/predict.o | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ ips_model.c model_test.c $(BUILD)/predict.o -lm

$(BUILD)/fusion_test: fusion.c fusion.h sig_rule.h ac.h fusion_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ fusion.c fusion_test.c

$(BUILD)/engine_test: engine.c engine.h flow_rule.c flow_rule.h fusion.c \
                      sig_rule.c ac.c ips_model.c feature.h \
                      model/predict.h engine_test.c $(BUILD)/predict.o | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ engine.c flow_rule.c fusion.c sig_rule.c \
	    ac.c ips_model.c engine_test.c $(BUILD)/predict.o -lm

$(BUILD)/nfq_test: nfq.c nfq.h sig_rule.h nfq_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ nfq.c nfq_test.c

$(BUILD)/tls_clienthello_test: tls_clienthello.c tls_clienthello.h tls_clienthello_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ tls_clienthello.c tls_clienthello_test.c

$(BUILD)/tls_policy_test: tls_policy.c tls_policy.h tls_policy_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ tls_policy.c tls_policy_test.c

$(BUILD)/reass_test: ac.c ac.h reass.c reass.h reass_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ ac.c reass.c reass_test.c

# stargazer-ipsd binary (host build, no sanitizer for clean linking)
IPSD_SRCS := main.c nfq.c ctdump.c feature.c flow_rule.c \
             sig_rule.c sig_reload.c ac.c reass.c \
             proto_buf.c tls_clienthello.c ml_scan.c \
             engine.c fusion.c ips_model.c ml_eval.c insp_ipc.c

$(BUILD)/stargazer-ipsd: $(IPSD_SRCS) model/predict.c $(BUILD)/predict.o | $(BUILD)
	$(CC) -O2 -Wall -Wextra -std=c11 \
	    -o $@ $(IPSD_SRCS) $(BUILD)/predict.o -lpthread -lm

$(BUILD)/ctdump_test: ctdump.c ctdump.h feature.c feature.h flow_rule.c flow_rule.h \
                     sig_rule.h ctdump_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ ctdump.c feature.c flow_rule.c \
	    ctdump_test.c -lm

SIG_RELOAD_SRCS := sig_reload.c sig_reload.h sig_rule.c ac.c sig_reload_test.c

$(BUILD)/reload_test: $(SIG_RELOAD_SRCS) | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) \
	    -o $@ sig_reload.c sig_rule.c ac.c sig_reload_test.c -lpthread

$(BUILD)/reload_test_tsan: $(SIG_RELOAD_SRCS) | $(BUILD)
	$(CC) -O1 -Wall -Wextra -std=c11 -fsanitize=thread \
	    -o $@ sig_reload.c sig_rule.c ac.c sig_reload_test.c -lpthread

# harness without sanitizer for fast loading of large rulesets
$(BUILD)/sig_dump: $(CORE) $(HDR) sig_dump.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(CORE) sig_dump.c

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
