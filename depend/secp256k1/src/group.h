/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_GROUP_H
#define kaspa_secp256k1_GROUP_H

#include "field.h"

/** A group element of the secp256k1 curve, in affine coordinates. */
typedef struct {
    kaspa_secp256k1_fe x;
    kaspa_secp256k1_fe y;
    int infinity; /* whether this represents the point at infinity */
} kaspa_secp256k1_ge;

#define kaspa_secp256k1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {kaspa_secp256k1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), kaspa_secp256k1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define kaspa_secp256k1_GE_CONST_INFINITY {kaspa_secp256k1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), kaspa_secp256k1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

/** A group element of the secp256k1 curve, in jacobian coordinates. */
typedef struct {
    kaspa_secp256k1_fe x; /* actual X: x/z^2 */
    kaspa_secp256k1_fe y; /* actual Y: y/z^3 */
    kaspa_secp256k1_fe z;
    int infinity; /* whether this represents the point at infinity */
} kaspa_secp256k1_gej;

#define kaspa_secp256k1_GEJ_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {kaspa_secp256k1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), kaspa_secp256k1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), kaspa_secp256k1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1), 0}
#define kaspa_secp256k1_GEJ_CONST_INFINITY {kaspa_secp256k1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), kaspa_secp256k1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), kaspa_secp256k1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}

typedef struct {
    kaspa_secp256k1_fe_storage x;
    kaspa_secp256k1_fe_storage y;
} kaspa_secp256k1_ge_storage;

#define kaspa_secp256k1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {kaspa_secp256k1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), kaspa_secp256k1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}

#define kaspa_secp256k1_GE_STORAGE_CONST_GET(t) kaspa_secp256k1_FE_STORAGE_CONST_GET(t.x), kaspa_secp256k1_FE_STORAGE_CONST_GET(t.y)

/** Set a group element equal to the point with given X and Y coordinates */
static void kaspa_secp256k1_ge_set_xy(kaspa_secp256k1_ge *r, const kaspa_secp256k1_fe *x, const kaspa_secp256k1_fe *y);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int kaspa_secp256k1_ge_set_xo_var(kaspa_secp256k1_ge *r, const kaspa_secp256k1_fe *x, int odd);

/** Check whether a group element is the point at infinity. */
static int kaspa_secp256k1_ge_is_infinity(const kaspa_secp256k1_ge *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int kaspa_secp256k1_ge_is_valid_var(const kaspa_secp256k1_ge *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void kaspa_secp256k1_ge_neg(kaspa_secp256k1_ge *r, const kaspa_secp256k1_ge *a);

/** Set a group element equal to another which is given in jacobian coordinates. Constant time. */
static void kaspa_secp256k1_ge_set_gej(kaspa_secp256k1_ge *r, kaspa_secp256k1_gej *a);

/** Set a group element equal to another which is given in jacobian coordinates. */
static void kaspa_secp256k1_ge_set_gej_var(kaspa_secp256k1_ge *r, kaspa_secp256k1_gej *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void kaspa_secp256k1_ge_set_all_gej_var(kaspa_secp256k1_ge *r, const kaspa_secp256k1_gej *a, size_t len);

/** Bring a batch inputs given in jacobian coordinates (with known z-ratios) to
 *  the same global z "denominator". zr must contain the known z-ratios such
 *  that mul(a[i].z, zr[i+1]) == a[i+1].z. zr[0] is ignored. The x and y
 *  coordinates of the result are stored in r, the common z coordinate is
 *  stored in globalz. */
static void kaspa_secp256k1_ge_globalz_set_table_gej(size_t len, kaspa_secp256k1_ge *r, kaspa_secp256k1_fe *globalz, const kaspa_secp256k1_gej *a, const kaspa_secp256k1_fe *zr);

/** Set a group element (affine) equal to the point at infinity. */
static void kaspa_secp256k1_ge_set_infinity(kaspa_secp256k1_ge *r);

/** Set a group element (jacobian) equal to the point at infinity. */
static void kaspa_secp256k1_gej_set_infinity(kaspa_secp256k1_gej *r);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void kaspa_secp256k1_gej_set_ge(kaspa_secp256k1_gej *r, const kaspa_secp256k1_ge *a);

/** Compare the X coordinate of a group element (jacobian). */
static int kaspa_secp256k1_gej_eq_x_var(const kaspa_secp256k1_fe *x, const kaspa_secp256k1_gej *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void kaspa_secp256k1_gej_neg(kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a);

/** Check whether a group element is the point at infinity. */
static int kaspa_secp256k1_gej_is_infinity(const kaspa_secp256k1_gej *a);

/** Set r equal to the double of a. Constant time. */
static void kaspa_secp256k1_gej_double(kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a);

/** Set r equal to the double of a. If rzr is not-NULL this sets *rzr such that r->z == a->z * *rzr (where infinity means an implicit z = 0). */
static void kaspa_secp256k1_gej_double_var(kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a, kaspa_secp256k1_fe *rzr);

/** Set r equal to the sum of a and b. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void kaspa_secp256k1_gej_add_var(kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a, const kaspa_secp256k1_gej *b, kaspa_secp256k1_fe *rzr);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void kaspa_secp256k1_gej_add_ge(kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a, const kaspa_secp256k1_ge *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than kaspa_secp256k1_gej_add_var. It is identical to kaspa_secp256k1_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. If rzr is non-NULL this sets *rzr such that r->z == a->z * *rzr (a cannot be infinity in that case). */
static void kaspa_secp256k1_gej_add_ge_var(kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a, const kaspa_secp256k1_ge *b, kaspa_secp256k1_fe *rzr);

/** Set r equal to the sum of a and b (with the inverse of b's Z coordinate passed as bzinv). */
static void kaspa_secp256k1_gej_add_zinv_var(kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a, const kaspa_secp256k1_ge *b, const kaspa_secp256k1_fe *bzinv);

/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void kaspa_secp256k1_ge_mul_lambda(kaspa_secp256k1_ge *r, const kaspa_secp256k1_ge *a);

/** Clear a kaspa_secp256k1_gej to prevent leaking sensitive information. */
static void kaspa_secp256k1_gej_clear(kaspa_secp256k1_gej *r);

/** Clear a kaspa_secp256k1_ge to prevent leaking sensitive information. */
static void kaspa_secp256k1_ge_clear(kaspa_secp256k1_ge *r);

/** Convert a group element to the storage type. */
static void kaspa_secp256k1_ge_to_storage(kaspa_secp256k1_ge_storage *r, const kaspa_secp256k1_ge *a);

/** Convert a group element back from the storage type. */
static void kaspa_secp256k1_ge_from_storage(kaspa_secp256k1_ge *r, const kaspa_secp256k1_ge_storage *a);

/** If flag is true, set *r equal to *a; otherwise leave it. Constant-time.  Both *r and *a must be initialized.*/
static void kaspa_secp256k1_ge_storage_cmov(kaspa_secp256k1_ge_storage *r, const kaspa_secp256k1_ge_storage *a, int flag);

/** Rescale a jacobian point by b which must be non-zero. Constant-time. */
static void kaspa_secp256k1_gej_rescale(kaspa_secp256k1_gej *r, const kaspa_secp256k1_fe *b);

/** Determine if a point (which is assumed to be on the curve) is in the correct (sub)group of the curve.
 *
 * In normal mode, the used group is secp256k1, which has cofactor=1 meaning that every point on the curve is in the
 * group, and this function returns always true.
 *
 * When compiling in exhaustive test mode, a slightly different curve equation is used, leading to a group with a
 * (very) small subgroup, and that subgroup is what is used for all cryptographic operations. In that mode, this
 * function checks whether a point that is on the curve is in fact also in that subgroup.
 */
static int kaspa_secp256k1_ge_is_in_correct_subgroup(const kaspa_secp256k1_ge* ge);

#endif /* kaspa_secp256k1_GROUP_H */
