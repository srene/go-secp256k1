/***********************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_ECMULT_H
#define kaspa_secp256k1_ECMULT_H

#include "group.h"
#include "scalar.h"
#include "scratch.h"

typedef struct {
    /* For accelerating the computation of a*P + b*G: */
    kaspa_secp256k1_ge_storage (*pre_g)[];    /* odd multiples of the generator */
    kaspa_secp256k1_ge_storage (*pre_g_128)[]; /* odd multiples of 2^128*generator */
} kaspa_secp256k1_ecmult_context;

static const size_t kaspa_secp256k1_ECMULT_CONTEXT_PREALLOCATED_SIZE;
static void kaspa_secp256k1_ecmult_context_init(kaspa_secp256k1_ecmult_context *ctx);
static void kaspa_secp256k1_ecmult_context_build(kaspa_secp256k1_ecmult_context *ctx, void **prealloc);
static void kaspa_secp256k1_ecmult_context_finalize_memcpy(kaspa_secp256k1_ecmult_context *dst, const kaspa_secp256k1_ecmult_context *src);
static void kaspa_secp256k1_ecmult_context_clear(kaspa_secp256k1_ecmult_context *ctx);
static int kaspa_secp256k1_ecmult_context_is_built(const kaspa_secp256k1_ecmult_context *ctx);

/** Double multiply: R = na*A + ng*G */
static void kaspa_secp256k1_ecmult(const kaspa_secp256k1_ecmult_context *ctx, kaspa_secp256k1_gej *r, const kaspa_secp256k1_gej *a, const kaspa_secp256k1_scalar *na, const kaspa_secp256k1_scalar *ng);

typedef int (kaspa_secp256k1_ecmult_multi_callback)(kaspa_secp256k1_scalar *sc, kaspa_secp256k1_ge *pt, size_t idx, void *data);

/**
 * Multi-multiply: R = inp_g_sc * G + sum_i ni * Ai.
 * Chooses the right algorithm for a given number of points and scratch space
 * size. Resets and overwrites the given scratch space. If the points do not
 * fit in the scratch space the algorithm is repeatedly run with batches of
 * points. If no scratch space is given then a simple algorithm is used that
 * simply multiplies the points with the corresponding scalars and adds them up.
 * Returns: 1 on success (including when inp_g_sc is NULL and n is 0)
 *          0 if there is not enough scratch space for a single point or
 *          callback returns 0
 */
static int kaspa_secp256k1_ecmult_multi_var(const kaspa_secp256k1_callback* error_callback, const kaspa_secp256k1_ecmult_context *ctx, kaspa_secp256k1_scratch *scratch, kaspa_secp256k1_gej *r, const kaspa_secp256k1_scalar *inp_g_sc, kaspa_secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n);

#endif /* kaspa_secp256k1_ECMULT_H */
