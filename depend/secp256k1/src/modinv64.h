/***********************************************************************
 * Copyright (c) 2020 Peter Dettman                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef kaspa_secp256k1_MODINV64_H
#define kaspa_secp256k1_MODINV64_H

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"

#ifndef kaspa_secp256k1_WIDEMUL_INT128
#error "modinv64 requires 128-bit wide multiplication support"
#endif

/* A signed 62-bit limb representation of integers.
 *
 * Its value is sum(v[i] * 2^(62*i), i=0..4). */
typedef struct {
    int64_t v[5];
} kaspa_secp256k1_modinv64_signed62;

typedef struct {
    /* The modulus in signed62 notation, must be odd and in [3, 2^256]. */
    kaspa_secp256k1_modinv64_signed62 modulus;

    /* modulus^{-1} mod 2^62 */
    uint64_t modulus_inv62;
} kaspa_secp256k1_modinv64_modinfo;

/* Replace x with its modular inverse mod modinfo->modulus. x must be in range [0, modulus).
 * If x is zero, the result will be zero as well. If not, the inverse must exist (i.e., the gcd of
 * x and modulus must be 1). These rules are automatically satisfied if the modulus is prime.
 *
 * On output, all of x's limbs will be in [0, 2^62).
 */
static void kaspa_secp256k1_modinv64_var(kaspa_secp256k1_modinv64_signed62 *x, const kaspa_secp256k1_modinv64_modinfo *modinfo);

/* Same as kaspa_secp256k1_modinv64_var, but constant time in x (not in the modulus). */
static void kaspa_secp256k1_modinv64(kaspa_secp256k1_modinv64_signed62 *x, const kaspa_secp256k1_modinv64_modinfo *modinfo);

#endif /* kaspa_secp256k1_MODINV64_H */
