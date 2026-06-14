# Makefile HOST-TEST cho stargazer-ipsd (chạy trên máy dev bằng gcc native).
#
# Đây KHÔNG phải bản build sản phẩm — bản cross-compile musl-static cho BPI-R4
# do root Makefile lo (xem docs/ips-master-plan.md §4). File này chỉ để chạy
# nhanh unit test + harness trên host.
#
#   make test         # build + chạy ac_test và sig_test (kèm ASan/UBSan)
#   make ac-test      # chỉ test Aho-Corasick
#   make sig-test     # chỉ test parser rule
#   make sig-dump     # build harness; rồi: ./build/sig_dump <file.rules> [payload] [dport]
#   make et RULES=/tmp/et-scan.rules PAYLOAD="USER root" DPORT=21
#   make clean

CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
SANIT  := -fsanitize=address,undefined
BUILD  := build

# P4 — nếu host có libpcre2-8 → test luôn đường pcre (HAVE_PCRE). Không có →
# build không pcre (luật pcre KẸP ALERT), test vẫn chạy.
HAVE_PCRE := $(shell pkg-config --exists libpcre2-8 2>/dev/null && echo 1)
ifeq ($(HAVE_PCRE),1)
  PCRE_FLAGS := -DHAVE_PCRE $(shell pkg-config --cflags --libs libpcre2-8)
endif

# Nguồn engine dùng chung (KHÔNG gồm file chứa main()).
CORE   := ac.c sig_rule.c
HDR    := ac.h sig_rule.h

.PHONY: test ac-test sig-test feat-test model-test fusion-test engine-test reload-test ctdump-test nfq-test tls-test tls-policy-test reass-test ipsd sig-dump et rules-fetch clean

test: ac-test sig-test feat-test model-test fusion-test engine-test reload-test ctdump-test nfq-test tls-test tls-policy-test reass-test
	@echo "== TẤT CẢ TEST PASS =="

ac-test: $(BUILD)/ac_test
	@echo "--- chạy ac_test ---"
	./$(BUILD)/ac_test

sig-test: $(BUILD)/sig_test
	@echo "--- chạy sig_test ---"
	./$(BUILD)/sig_test

feat-test: $(BUILD)/feature_test
	@echo "--- chạy feature_test ---"
	./$(BUILD)/feature_test

model-test: $(BUILD)/model_test
	@echo "--- chạy model_test ---"
	./$(BUILD)/model_test

fusion-test: $(BUILD)/fusion_test
	@echo "--- chạy fusion_test ---"
	./$(BUILD)/fusion_test

engine-test: $(BUILD)/engine_test
	@echo "--- chạy engine_test (pipeline hybrid) ---"
	./$(BUILD)/engine_test


nfq-test: $(BUILD)/nfq_test
	@echo "--- chạy nfq_test (parse, host) ---"
	./$(BUILD)/nfq_test

tls-test: $(BUILD)/tls_clienthello_test
	@echo "--- chạy tls_clienthello_test (parse SNI, host) ---"
	./$(BUILD)/tls_clienthello_test

tls-policy-test: $(BUILD)/tls_policy_test
	@echo "--- chạy tls_policy_test (splice/bump decision, host) ---"
	./$(BUILD)/tls_policy_test

reass-test: $(BUILD)/reass_test
	@echo "--- chạy reass_test (ráp dòng TCP + streaming AC, host) ---"
	./$(BUILD)/reass_test

ctdump-test: $(BUILD)/ctdump_test
	@echo "--- chạy ctdump_test (host, không cần kernel) ---"
	./$(BUILD)/ctdump_test

reload-test: $(BUILD)/reload_test $(BUILD)/reload_test_tsan
	@echo "--- chạy reload_test (ASan) ---"
	./$(BUILD)/reload_test
	@echo "--- chạy reload_test_tsan (TSan T4) ---"
	setarch "$$(uname -m)" -R ./$(BUILD)/reload_test_tsan

ipsd: $(BUILD)/stargazer-ipsd
	@echo "binary: $(BUILD)/stargazer-ipsd"

sig-dump: $(BUILD)/sig_dump
	@echo "dùng: ./$(BUILD)/sig_dump <file.rules> [payload] [dport] [tcp|udp|icmp]"

# Ruleset ET OPEN để thử nạp — nằm trong rules/ cho khỏi mất khi reboot.
# `make et` tự tải về nếu chưa có.
#   make et                                  # nạp + báo cáo
#   make et PAYLOAD="USER root" DPORT=21      # nạp + thử khớp
ET_URL  := https://rules.emergingthreats.net/open/snort-2.9.0/rules/emerging-scan.rules
RULES   ?= rules/emerging-scan.rules
PAYLOAD ?=
DPORT   ?=

rules/emerging-scan.rules:
	@mkdir -p rules
	curl -fsSL --max-time 30 -o $@ $(ET_URL)

rules-fetch: rules/emerging-scan.rules
	@echo "ruleset sẵn sàng: $<"

et: $(BUILD)/sig_dump $(RULES)
	./$(BUILD)/sig_dump "$(RULES)" $(if $(PAYLOAD),"$(PAYLOAD)") $(DPORT)

# --- build rules ---------------------------------------------------------
$(BUILD)/ac_test: ac.c ac.h ac_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ ac.c ac_test.c

$(BUILD)/sig_test: $(CORE) $(HDR) sig_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ $(CORE) proto_buf.c tls_clienthello.c sig_test.c $(PCRE_FLAGS)

$(BUILD)/feature_test: feature.c feature.h feature_test.c | $(BUILD)
	$(CC) $(CFLAGS) $(SANIT) -o $@ feature.c feature_test.c -lm

# Model sinh máy (tl2cgen): build riêng với -w (bỏ cảnh báo code generate),
# không sanitizer cho nhanh. Link vào test/daemon.
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

# stargazer-ipsd binary (host build, không sanitizer để liên kết tốt)
IPSD_SRCS := main.c nfq.c ctdump.c feature.c flow_rule.c \
             sig_rule.c sig_reload.c ac.c reass.c \
             proto_buf.c tls_clienthello.c ml_scan.c \
             engine.c fusion.c ips_model.c

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

# harness không gắn sanitizer để nạp ruleset lớn cho nhanh
$(BUILD)/sig_dump: $(CORE) $(HDR) sig_dump.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $(CORE) sig_dump.c

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
