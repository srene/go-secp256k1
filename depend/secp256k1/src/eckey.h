/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_ECKEY_H
#define kaspa_secp256k1_ECKEY_H

#include <stddef.h>

#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int kaspa_secp256k1_eckey_pubkey_parse(kaspa_secp256k1_ge *elem, const unsigned char *pub, size_t size);
static int kaspa_secp256k1_eckey_pubkey_serialize(kaspa_secp256k1_ge *elem, unsigned char *pub, size_t *size, int compressed);

static int kaspa_secp256k1_eckey_privkey_tweak_add(kaspa_secp256k1_scalar *key, const kaspa_secp256k1_scalar *tweak);
static int kaspa_secp256k1_eckey_pubkey_tweak_add(const kaspa_secp256k1_ecmult_context *ctx, kaspa_secp256k1_ge *key, const kaspa_secp256k1_scalar *tweak);
static int kaspa_secp256k1_eckey_privkey_tweak_mul(kaspa_secp256k1_scalar *key, const kaspa_secp256k1_scalar *tweak);
static int kaspa_secp256k1_eckey_pubkey_tweak_mul(const kaspa_secp256k1_ecmult_context *ctx, kaspa_secp256k1_ge *key, const kaspa_secp256k1_scalar *tweak);

#endif /* kaspa_secp256k1_ECKEY_H */
