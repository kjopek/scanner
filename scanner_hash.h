#ifndef SCANNER_HASH_H
#define SCANNER_HASH_H

#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>

#include <stdint.h>
#include <string.h>

#include <md5.h>
#include <sha256.h>
#include <sha512.h>

typedef enum {
	SCANNER_HASH_MD5,
	SCANNER_HASH_SHA256,
	SCANNER_HASH_SHA512
} scanner_hash_func;

typedef struct {
	union {
		MD5_CTX    md5_ctx;
		SHA256_CTX sha256_ctx;
		SHA512_CTX sha512_ctx;
	} scanner_hash_context;
	int               digest_size;
	unsigned char *   hash;
	scanner_hash_func hash_func;
	char *pass;
} scanner_hash;

int  scanner_hash_init(scanner_hash ** hash, scanner_hash_func func);
void scanner_hash_update(scanner_hash *hash, const void *data, size_t len);
void scanner_hash_final(scanner_hash *hash);
void scanner_hash_free(scanner_hash *hash);

#endif /* SCANNER_HASH_H */
