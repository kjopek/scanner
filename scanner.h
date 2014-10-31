#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <string.h>

#include <md5.h>
#include <sha256.h>
#include <sha512.h>

typedef enum {
    MD5,
    SHA256,
    SHA512
} scanner_hashing_algos;

typedef struct {
    void (*Init)(void *context);
    void (*Update)(void *context, const unsigned char *data, size_t len);
    void (*Finish)(unsigned char *digest, void *context);
    int digest_size;
} scanner_hashing_algo;

typedef struct {
    char initial[64];

} scanner_properties;

scanner_hashing_algo scanner_hashing_algorithms[] = {
    {
        .Init = MD5Init,
        .Update = MD5Update,
        .Finish = MD5Final,
        .digest_size = MD5_DIGEST_LENGTH
    },
    {
        .Init = SHA256_Init,
        .Update = SHA256_Update,
        .Finish = SHA256_Final,
        .digest_size = 256/8
    },
    {
        .Init = SHA512_Init,
        .Update = SHA512_Update,
        .Finish = SHA512_Final,
        .digest_size = 512/8
    }
};

#endif /* SCANNER_H */
