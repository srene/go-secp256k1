/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_HASH_H
#define kaspa_secp256k1_HASH_H

#include <stdlib.h>
#include <stdint.h>

typedef struct {
    uint32_t s[8];
    uint32_t buf[16]; /* In big endian */
    size_t bytes;
} kaspa_secp256k1_sha256;

static void kaspa_secp256k1_sha256_initialize(kaspa_secp256k1_sha256 *hash);
static void kaspa_secp256k1_sha256_write(kaspa_secp256k1_sha256 *hash, const unsigned char *data, size_t size);
static void kaspa_secp256k1_sha256_finalize(kaspa_secp256k1_sha256 *hash, unsigned char *out32);

typedef struct {
    kaspa_secp256k1_sha256 inner, outer;
} kaspa_secp256k1_hmac_sha256;

static void kaspa_secp256k1_hmac_sha256_initialize(kaspa_secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t size);
static void kaspa_secp256k1_hmac_sha256_write(kaspa_secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size);
static void kaspa_secp256k1_hmac_sha256_finalize(kaspa_secp256k1_hmac_sha256 *hash, unsigned char *out32);

typedef struct {
    unsigned char v[32];
    unsigned char k[32];
    int retry;
} kaspa_secp256k1_rfc6979_hmac_sha256;

static void kaspa_secp256k1_rfc6979_hmac_sha256_initialize(kaspa_secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen);
static void kaspa_secp256k1_rfc6979_hmac_sha256_generate(kaspa_secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen);
static void kaspa_secp256k1_rfc6979_hmac_sha256_finalize(kaspa_secp256k1_rfc6979_hmac_sha256 *rng);

#endif /* kaspa_secp256k1_HASH_H */
