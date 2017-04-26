#include "scanner_hash.h"

int
scanner_hash_init(scanner_hash ** hash, scanner_hash_func func)
{

	*hash = (scanner_hash*) malloc(sizeof(scanner_hash));
	if (*hash == NULL)
		return (-1);

	switch (func) {
	case SCANNER_HASH_MD5:
		MD5Init(&((*hash)->scanner_hash_context.md5_ctx));
		(*hash)->digest_size = MD5_DIGEST_LENGTH;
		break;
	case SCANNER_HASH_SHA256:
		SHA256_Init(&((*hash)->scanner_hash_context.sha256_ctx));
		(*hash)->digest_size = 256/8;
		break;
	case SCANNER_HASH_SHA512:
		SHA512_Init(&((*hash)->scanner_hash_context.sha512_ctx));
		(*hash)->digest_size = 512/8;
		break;
	}

	(*hash)->hash = (unsigned char*) malloc((*hash)->digest_size);
	if ((*hash)->hash == NULL) {
		free(*hash);
		return (-1);
	}

	(*hash)->hash_func = func;
	return (0);
}

void
scanner_hash_update(scanner_hash *hash, const void *data, size_t len)
{

	switch (hash->hash_func) {
	case SCANNER_HASH_MD5:
		MD5Update(&hash->scanner_hash_context.md5_ctx, data, len);
		break;
	case SCANNER_HASH_SHA256:
		SHA256_Update(&hash->scanner_hash_context.sha256_ctx, data,
			len);
		break;
	case SCANNER_HASH_SHA512:
		SHA512_Update(&hash->scanner_hash_context.sha512_ctx, data,
			len);
		break;
	}
}

void
scanner_hash_final(scanner_hash *hash)
{

	switch (hash->hash_func) {
	case SCANNER_HASH_MD5:
		MD5Final(hash->hash, &hash->scanner_hash_context.md5_ctx);
		break;
	case SCANNER_HASH_SHA256:
		SHA256_Final(hash->hash,
			&hash->scanner_hash_context.sha256_ctx);
		break;
	case SCANNER_HASH_SHA512:
		SHA512_Final(hash->hash,
			&hash->scanner_hash_context.sha512_ctx);
		break;
	}
}

void
scanner_hash_free(scanner_hash *hash)
{

	free(hash->hash);
	free(hash);
}
