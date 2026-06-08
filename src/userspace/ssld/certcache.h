/* SPDX-License-Identifier: MIT */
/*
 * certcache.h - Forge + cache leaf cert theo SNI (ký bằng local CA).
 *
 * Mỗi domain bump cần một leaf cert giả CN/SAN = domain đó, ký bằng CA. Forge
 * mỗi lần handshake quá đắt → cache theo SNI. Dùng MỘT leaf keypair chung cho
 * mọi cert (như mitmproxy/sslsplit) để khỏi sinh khóa mỗi domain.
 *
 * Nếu có cert server thật (upstream), mirror notBefore/notAfter để cert giả
 * trông hợp lệ thời gian. Thread-safe (mutex) vì nhiều conn-thread cùng tra.
 */
#ifndef SG_SSLD_CERTCACHE_H
#define SG_SSLD_CERTCACHE_H

#include "ca.h"
#include <openssl/x509.h>
#include <openssl/evp.h>

struct certcache;

/* Tạo cache (tối đa `max` entry, LRU evict). Sinh leaf keypair chung. */
struct certcache *certcache_new(struct ca_ctx *ca, int max);

/*
 * Lấy (forge nếu chưa cache) leaf cert cho `sni`. `upstream` có thể NULL
 * (không mirror thời hạn → dùng mặc định 1 năm). Trả 0 + điền out_cert/out_key
 * (KHÔNG tăng ref — sống theo cache, dùng ngay trong SSL_CTX rồi thôi; cache
 * giữ ref). Trả -1 nếu lỗi.
 */
int certcache_get(struct certcache *cc, const char *sni, X509 *upstream,
		  X509 **out_cert, EVP_PKEY **out_key);

void certcache_free(struct certcache *cc);

#endif /* SG_SSLD_CERTCACHE_H */
