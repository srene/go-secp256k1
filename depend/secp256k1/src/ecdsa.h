/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_ECDSA_H
#define kaspa_secp256k1_ECDSA_H

#include <stddef.h>

#include "scalar.h"
#include "group.h"
#include "ecmult.h"

static int kaspa_secp256k1_ecdsa_sig_parse(kaspa_secp256k1_scalar *r, kaspa_secp256k1_scalar *s, const unsigned char *sig, size_t size);
static int kaspa_secp256k1_ecdsa_sig_serialize(unsigned char *sig, size_t *size, const kaspa_secp256k1_scalar *r, const kaspa_secp256k1_scalar *s);
static int kaspa_secp256k1_ecdsa_sig_verify(const kaspa_secp256k1_ecmult_context *ctx, const kaspa_secp256k1_scalar* r, const kaspa_secp256k1_scalar* s, const kaspa_secp256k1_ge *pubkey, const kaspa_secp256k1_scalar *message);
static int kaspa_secp256k1_ecdsa_sig_sign(const kaspa_secp256k1_ecmult_gen_context *ctx, kaspa_secp256k1_scalar* r, kaspa_secp256k1_scalar* s, const kaspa_secp256k1_scalar *seckey, const kaspa_secp256k1_scalar *message, const kaspa_secp256k1_scalar *nonce, int *recid);

#endif /* kaspa_secp256k1_ECDSA_H */
