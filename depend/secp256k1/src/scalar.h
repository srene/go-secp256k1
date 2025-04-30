/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_SCALAR_H
#define kaspa_secp256k1_SCALAR_H

#include "util.h"

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(EXHAUSTIVE_TEST_ORDER)
#include "scalar_low.h"
#elif defined(kaspa_secp256k1_WIDEMUL_INT128)
#include "scalar_4x64.h"
#elif defined(kaspa_secp256k1_WIDEMUL_INT64)
#include "scalar_8x32.h"
#else
#error "Please select wide multiplication implementation"
#endif

/** Clear a scalar to prevent the leak of sensitive data. */
static void kaspa_secp256k1_scalar_clear(kaspa_secp256k1_scalar *r);

/** Access bits from a scalar. All requested bits must belong to the same 32-bit limb. */
static unsigned int kaspa_secp256k1_scalar_get_bits(const kaspa_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Access bits from a scalar. Not constant time. */
static unsigned int kaspa_secp256k1_scalar_get_bits_var(const kaspa_secp256k1_scalar *a, unsigned int offset, unsigned int count);

/** Set a scalar from a big endian byte array. The scalar will be reduced modulo group order `n`.
 * In:      bin:        pointer to a 32-byte array.
 * Out:     r:          scalar to be set.
 *          overflow:   non-zero if the scalar was bigger or equal to `n` before reduction, zero otherwise (can be NULL).
 */
static void kaspa_secp256k1_scalar_set_b32(kaspa_secp256k1_scalar *r, const unsigned char *bin, int *overflow);

/** Set a scalar from a big endian byte array and returns 1 if it is a valid
 *  seckey and 0 otherwise. */
static int kaspa_secp256k1_scalar_set_b32_seckey(kaspa_secp256k1_scalar *r, const unsigned char *bin);

/** Set a scalar to an unsigned integer. */
static void kaspa_secp256k1_scalar_set_int(kaspa_secp256k1_scalar *r, unsigned int v);

/** Convert a scalar to a byte array. */
static void kaspa_secp256k1_scalar_get_b32(unsigned char *bin, const kaspa_secp256k1_scalar* a);

/** Add two scalars together (modulo the group order). Returns whether it overflowed. */
static int kaspa_secp256k1_scalar_add(kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *a, const kaspa_secp256k1_scalar *b);

/** Conditionally add a power of two to a scalar. The result is not allowed to overflow. */
static void kaspa_secp256k1_scalar_cadd_bit(kaspa_secp256k1_scalar *r, unsigned int bit, int flag);

/** Multiply two scalars (modulo the group order). */
static void kaspa_secp256k1_scalar_mul(kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *a, const kaspa_secp256k1_scalar *b);

/** Shift a scalar right by some amount strictly between 0 and 16, returning
 *  the low bits that were shifted off */
static int kaspa_secp256k1_scalar_shr_int(kaspa_secp256k1_scalar *r, int n);

/** Compute the inverse of a scalar (modulo the group order). */
static void kaspa_secp256k1_scalar_inverse(kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *a);

/** Compute the inverse of a scalar (modulo the group order), without constant-time guarantee. */
static void kaspa_secp256k1_scalar_inverse_var(kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *a);

/** Compute the complement of a scalar (modulo the group order). */
static void kaspa_secp256k1_scalar_negate(kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *a);

/** Check whether a scalar equals zero. */
static int kaspa_secp256k1_scalar_is_zero(const kaspa_secp256k1_scalar *a);

/** Check whether a scalar equals one. */
static int kaspa_secp256k1_scalar_is_one(const kaspa_secp256k1_scalar *a);

/** Check whether a scalar, considered as an nonnegative integer, is even. */
static int kaspa_secp256k1_scalar_is_even(const kaspa_secp256k1_scalar *a);

/** Check whether a scalar is higher than the group order divided by 2. */
static int kaspa_secp256k1_scalar_is_high(const kaspa_secp256k1_scalar *a);

/** Conditionally negate a number, in constant time.
 * Returns -1 if the number was negated, 1 otherwise */
static int kaspa_secp256k1_scalar_cond_negate(kaspa_secp256k1_scalar *a, int flag);

/** Compare two scalars. */
static int kaspa_secp256k1_scalar_eq(const kaspa_secp256k1_scalar *a, const kaspa_secp256k1_scalar *b);

/** Find r1 and r2 such that r1+r2*2^128 = k. */
static void kaspa_secp256k1_scalar_split_128(kaspa_secp256k1_scalar *r1, kaspa_secp256k1_scalar *r2, const kaspa_secp256k1_scalar *k);
/** Find r1 and r2 such that r1+r2*lambda = k,
 * where r1 and r2 or their negations are maximum 128 bits long (see kaspa_secp256k1_ge_mul_lambda). */
static void kaspa_secp256k1_scalar_split_lambda(kaspa_secp256k1_scalar *r1, kaspa_secp256k1_scalar *r2, const kaspa_secp256k1_scalar *k);

/** Multiply a and b (without taking the modulus!), divide by 2**shift, and round to the nearest integer. Shift must be at least 256. */
static void kaspa_secp256k1_scalar_mul_shift_var(kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *a, const kaspa_secp256k1_scalar *b, unsigned int shift);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void kaspa_secp256k1_scalar_cmov(kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *a, int flag);

#endif /* kaspa_secp256k1_SCALAR_H */
