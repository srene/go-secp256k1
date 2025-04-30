/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_FIELD_H
#define kaspa_secp256k1_FIELD_H

/** Field element module.
 *
 *  Field elements can be represented in several ways, but code accessing
 *  it (and implementations) need to take certain properties into account:
 *  - Each field element can be normalized or not.
 *  - Each field element has a magnitude, which represents how far away
 *    its representation is away from normalization. Normalized elements
 *    always have a magnitude of 1, but a magnitude of 1 doesn't imply
 *    normality.
 */

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"

#if defined(kaspa_secp256k1_WIDEMUL_INT128)
#include "field_5x52.h"
#elif defined(kaspa_secp256k1_WIDEMUL_INT64)
#include "field_10x26.h"
#else
#error "Please select wide multiplication implementation"
#endif

/** Normalize a field element. This brings the field element to a canonical representation, reduces
 *  its magnitude to 1, and reduces it modulo field size `p`.
 */
static void kaspa_secp256k1_fe_normalize(kaspa_secp256k1_fe *r);

/** Weakly normalize a field element: reduce its magnitude to 1, but don't fully normalize. */
static void kaspa_secp256k1_fe_normalize_weak(kaspa_secp256k1_fe *r);

/** Normalize a field element, without constant-time guarantee. */
static void kaspa_secp256k1_fe_normalize_var(kaspa_secp256k1_fe *r);

/** Verify whether a field element represents zero i.e. would normalize to a zero value. The field
 *  implementation may optionally normalize the input, but this should not be relied upon. */
static int kaspa_secp256k1_fe_normalizes_to_zero(kaspa_secp256k1_fe *r);

/** Verify whether a field element represents zero i.e. would normalize to a zero value. The field
 *  implementation may optionally normalize the input, but this should not be relied upon. */
static int kaspa_secp256k1_fe_normalizes_to_zero_var(kaspa_secp256k1_fe *r);

/** Set a field element equal to a small integer. Resulting field element is normalized. */
static void kaspa_secp256k1_fe_set_int(kaspa_secp256k1_fe *r, int a);

/** Sets a field element equal to zero, initializing all fields. */
static void kaspa_secp256k1_fe_clear(kaspa_secp256k1_fe *a);

/** Verify whether a field element is zero. Requires the input to be normalized. */
static int kaspa_secp256k1_fe_is_zero(const kaspa_secp256k1_fe *a);

/** Check the "oddness" of a field element. Requires the input to be normalized. */
static int kaspa_secp256k1_fe_is_odd(const kaspa_secp256k1_fe *a);

/** Compare two field elements. Requires magnitude-1 inputs. */
static int kaspa_secp256k1_fe_equal(const kaspa_secp256k1_fe *a, const kaspa_secp256k1_fe *b);

/** Same as kaspa_secp256k1_fe_equal, but may be variable time. */
static int kaspa_secp256k1_fe_equal_var(const kaspa_secp256k1_fe *a, const kaspa_secp256k1_fe *b);

/** Compare two field elements. Requires both inputs to be normalized */
static int kaspa_secp256k1_fe_cmp_var(const kaspa_secp256k1_fe *a, const kaspa_secp256k1_fe *b);

/** Set a field element equal to 32-byte big endian value. If successful, the resulting field element is normalized. */
static int kaspa_secp256k1_fe_set_b32(kaspa_secp256k1_fe *r, const unsigned char *a);

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void kaspa_secp256k1_fe_get_b32(unsigned char *r, const kaspa_secp256k1_fe *a);

/** Set a field element equal to the additive inverse of another. Takes a maximum magnitude of the input
 *  as an argument. The magnitude of the output is one higher. */
static void kaspa_secp256k1_fe_negate(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a, int m);

/** Multiplies the passed field element with a small integer constant. Multiplies the magnitude by that
 *  small integer. */
static void kaspa_secp256k1_fe_mul_int(kaspa_secp256k1_fe *r, int a);

/** Adds a field element to another. The result has the sum of the inputs' magnitudes as magnitude. */
static void kaspa_secp256k1_fe_add(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a);

/** Sets a field element to be the product of two others. Requires the inputs' magnitudes to be at most 8.
 *  The output magnitude is 1 (but not guaranteed to be normalized). */
static void kaspa_secp256k1_fe_mul(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a, const kaspa_secp256k1_fe * kaspa_secp256k1_RESTRICT b);

/** Sets a field element to be the square of another. Requires the input's magnitude to be at most 8.
 *  The output magnitude is 1 (but not guaranteed to be normalized). */
static void kaspa_secp256k1_fe_sqr(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a);

/** If a has a square root, it is computed in r and 1 is returned. If a does not
 *  have a square root, the root of its negation is computed and 0 is returned.
 *  The input's magnitude can be at most 8. The output magnitude is 1 (but not
 *  guaranteed to be normalized). The result in r will always be a square
 *  itself. */
static int kaspa_secp256k1_fe_sqrt(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a);

/** Sets a field element to be the (modular) inverse of another. Requires the input's magnitude to be
 *  at most 8. The output magnitude is 1 (but not guaranteed to be normalized). */
static void kaspa_secp256k1_fe_inv(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a);

/** Potentially faster version of kaspa_secp256k1_fe_inv, without constant-time guarantee. */
static void kaspa_secp256k1_fe_inv_var(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a);

/** Convert a field element to the storage type. */
static void kaspa_secp256k1_fe_to_storage(kaspa_secp256k1_fe_storage *r, const kaspa_secp256k1_fe *a);

/** Convert a field element back from the storage type. */
static void kaspa_secp256k1_fe_from_storage(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void kaspa_secp256k1_fe_storage_cmov(kaspa_secp256k1_fe_storage *r, const kaspa_secp256k1_fe_storage *a, int flag);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void kaspa_secp256k1_fe_cmov(kaspa_secp256k1_fe *r, const kaspa_secp256k1_fe *a, int flag);

#endif /* kaspa_secp256k1_FIELD_H */
