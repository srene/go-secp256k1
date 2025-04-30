#ifndef kaspa_secp256k1_SCHNORRSIG_H
#define kaspa_secp256k1_SCHNORRSIG_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements a variant of Schnorr signatures compliant with
 *  Bitcoin Improvement Proposal 340 "Schnorr Signatures for secp256k1"
 *  (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
 */

/** A pointer to a function to deterministically generate a nonce.
 *
 *  Same as kaspa_secp256k1_nonce function with the exception of accepting an
 *  additional pubkey argument and not requiring an attempt argument. The pubkey
 *  argument can protect signature schemes with key-prefixed challenge hash
 *  inputs against reusing the nonce when signing with the wrong precomputed
 *  pubkey.
 *
 *  Returns: 1 if a nonce was successfully generated. 0 will cause signing to
 *           return an error.
 *  Out:     nonce32:   pointer to a 32-byte array to be filled by the function.
 *  In:      msg32:     the 32-byte message hash being verified (will not be NULL)
 *           key32:     pointer to a 32-byte secret key (will not be NULL)
 *      xonly_pk32:     the 32-byte serialized xonly pubkey corresponding to key32
 *                      (will not be NULL)
 *           algo16:    pointer to a 16-byte array describing the signature
 *                      algorithm (will not be NULL).
 *           data:      Arbitrary data pointer that is passed through.
 *
 *  Except for test cases, this function should compute some cryptographic hash of
 *  the message, the key, the pubkey, the algorithm description, and data.
 */
typedef int (*kaspa_secp256k1_nonce_function_hardened)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *xonly_pk32,
    const unsigned char *algo16,
    void *data
);

/** An implementation of the nonce generation function as defined in Bitcoin
 *  Improvement Proposal 340 "Schnorr Signatures for secp256k1"
 *  (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
 *
 *  If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
 *  auxiliary random data as defined in BIP-340. If the data pointer is NULL,
 *  schnorrsig_sign does not produce BIP-340 compliant signatures. The algo16
 *  argument must be non-NULL, otherwise the function will fail and return 0.
 *  The hash will be tagged with algo16 after removing all terminating null
 *  bytes. Therefore, to create BIP-340 compliant signatures, algo16 must be set
 *  to "BIP0340/nonce\0\0\0"
 */
kaspa_secp256k1_API extern const kaspa_secp256k1_nonce_function_hardened kaspa_secp256k1_nonce_function_bip340;

/** Create a Schnorr signature.
 *
 *  Does _not_ strictly follow BIP-340 because it does not verify the resulting
 *  signature. Instead, you can manually use kaspa_secp256k1_schnorrsig_verify and
 *  abort if it fails.
 *
 *  Otherwise BIP-340 compliant if the noncefp argument is NULL or
 *  kaspa_secp256k1_nonce_function_bip340 and the ndata argument is 32-byte auxiliary
 *  randomness.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:   sig64: pointer to a 64-byte array to store the serialized signature (cannot be NULL)
 *  In:    msg32: the 32-byte message being signed (cannot be NULL)
 *       keypair: pointer to an initialized keypair (cannot be NULL)
 *       noncefp: pointer to a nonce generation function. If NULL, kaspa_secp256k1_nonce_function_bip340 is used
 *         ndata: pointer to arbitrary data used by the nonce generation
 *                function (can be NULL). If it is non-NULL and
 *                kaspa_secp256k1_nonce_function_bip340 is used, then ndata must be a
 *                pointer to 32-byte auxiliary randomness as per BIP-340.
 */
kaspa_secp256k1_API int kaspa_secp256k1_schnorrsig_sign(
    const kaspa_secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const kaspa_secp256k1_keypair *keypair,
    kaspa_secp256k1_nonce_function_hardened noncefp,
    void *ndata
) kaspa_secp256k1_ARG_NONNULL(1) kaspa_secp256k1_ARG_NONNULL(2) kaspa_secp256k1_ARG_NONNULL(3) kaspa_secp256k1_ARG_NONNULL(4);

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:    sig64: pointer to the 64-byte signature to verify (cannot be NULL)
 *         msg32: the 32-byte message being verified (cannot be NULL)
 *        pubkey: pointer to an x-only public key to verify with (cannot be NULL)
 */
kaspa_secp256k1_API kaspa_secp256k1_WARN_UNUSED_RESULT int kaspa_secp256k1_schnorrsig_verify(
    const kaspa_secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const kaspa_secp256k1_xonly_pubkey *pubkey
) kaspa_secp256k1_ARG_NONNULL(1) kaspa_secp256k1_ARG_NONNULL(2) kaspa_secp256k1_ARG_NONNULL(3) kaspa_secp256k1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* kaspa_secp256k1_SCHNORRSIG_H */
