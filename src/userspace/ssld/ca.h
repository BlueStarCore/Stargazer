/* SPDX-License-Identifier: MIT */
/*
 * ca.h - Local CA cho SSL inspection (forge cert ký bằng CA này).
 *
 * CA private key là TÀI SẢN RỦI RO CAO NHẤT của tính năng: rò rỉ = giả mạo
 * được mọi HTTPS của tổ chức. Lưu key 0600, root-only. Cert công khai phải
 * được cài vào trust store của MỌI client thì bump mới không báo lỗi cert.
 *
 * Sinh khóa EC P-256 (nhẹ + nhanh hơn RSA trên ARM), self-signed, CA:TRUE.
 */
#ifndef SG_SSLD_CA_H
#define SG_SSLD_CA_H

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <stddef.h>

struct ca_ctx {
	X509     *cert;   /* cert CA (self-signed)        */
	EVP_PKEY *key;    /* private key CA               */
};

/*
 * Nạp CA từ cert_path/key_path nếu cả hai tồn tại; nếu thiếu thì SINH MỚI và
 * ghi ra hai đường dẫn (key mode 0600). Trả 0 nếu OK, -1 nếu lỗi.
 */
int  ca_load_or_create(struct ca_ctx *ca,
		       const char *cert_path, const char *key_path);

/* Xuất cert CA dạng PEM vào buf (cho client tải về cài). Trả độ dài, -1 lỗi. */
int  ca_export_cert_pem(const struct ca_ctx *ca, char *buf, size_t cap);

void ca_free(struct ca_ctx *ca);

#endif /* SG_SSLD_CA_H */
