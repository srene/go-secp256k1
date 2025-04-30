/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_MODULE_ECDH_MAIN_H
#define kaspa_secp256k1_MODULE_ECDH_MAIN_H

#include "include/kaspa_secp256k1_ecdh.h"
#include "ecmult_const_impl.h"

static int ecdh_hash_function_sha256(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    unsigned char version = (y32[31] & 0x01) | 0x02;
    kaspa_secp256k1_sha256 sha;
    (void)data;

    kaspa_secp256k1_sha256_initialize(&sha);
    kaspa_secp256k1_sha256_write(&sha, &version, 1);
    kaspa_secp256k1_sha256_write(&sha, x32, 32);
    kaspa_secp256k1_sha256_finalize(&sha, output);

    return 1;
}

const kaspa_secp256k1_ecdh_hash_function kaspa_secp256k1_ecdh_hash_function_sha256 = ecdh_hash_function_sha256;
const kaspa_secp256k1_ecdh_hash_function kaspa_secp256k1_ecdh_hash_function_default = ecdh_hash_function_sha256;

int kaspa_secp256k1_ecdh(const kaspa_secp256k1_context* ctx, unsigned char *output, const kaspa_secp256k1_pubkey *point, const unsigned char *scalar, kaspa_secp256k1_ecdh_hash_function hashfp, void *data) {
    int ret = 0;
    int overflow = 0;
    kaspa_secp256k1_gej res;
    kaspa_secp256k1_ge pt;
    kaspa_secp256k1_scalar s;
    unsigned char x[32];
    unsigned char y[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    if (hashfp == NULL) {
        hashfp = kaspa_secp256k1_ecdh_hash_function_default;
    }

    kaspa_secp256k1_pubkey_load(ctx, &pt, point);
    kaspa_secp256k1_scalar_set_b32(&s, scalar, &overflow);

    overflow |= kaspa_secp256k1_scalar_is_zero(&s);
    kaspa_secp256k1_scalar_cmov(&s, &kaspa_secp256k1_scalar_one, overflow);

    kaspa_secp256k1_ecmult_const(&res, &pt, &s, 256);
    kaspa_secp256k1_ge_set_gej(&pt, &res);

    /* Compute a hash of the point */
    kaspa_secp256k1_fe_normalize(&pt.x);
    kaspa_secp256k1_fe_normalize(&pt.y);
    kaspa_secp256k1_fe_get_b32(x, &pt.x);
    kaspa_secp256k1_fe_get_b32(y, &pt.y);

    ret = hashfp(output, x, y, data);

    memset(x, 0, 32);
    memset(y, 0, 32);
    kaspa_secp256k1_scalar_clear(&s);

    return !!ret & !overflow;
}

#endif /* kaspa_secp256k1_MODULE_ECDH_MAIN_H */
