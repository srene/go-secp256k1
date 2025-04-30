/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include "include/secp256k1.h"
#include "include/secp256k1_preallocated.h"

#include "assumptions.h"
#include "util.h"
#include "field_impl.h"
#include "scalar_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "ecdsa_impl.h"
#include "eckey_impl.h"
#include "hash_impl.h"
#include "scratch_impl.h"
#include "selftest.h"

#if defined(VALGRIND)
# include <valgrind/memcheck.h>
#endif

#define ARG_CHECK(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        kaspa_secp256k1_callback_call(&ctx->illegal_callback, #cond); \
        return 0; \
    } \
} while(0)

#define ARG_CHECK_NO_RETURN(cond) do { \
    if (EXPECT(!(cond), 0)) { \
        kaspa_secp256k1_callback_call(&ctx->illegal_callback, #cond); \
    } \
} while(0)

#ifndef USE_EXTERNAL_DEFAULT_CALLBACKS
#include <stdlib.h>
#include <stdio.h>
static void kaspa_secp256k1_default_illegal_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] illegal argument: %s\n", str);
    abort();
}
static void kaspa_secp256k1_default_error_callback_fn(const char* str, void* data) {
    (void)data;
    fprintf(stderr, "[libsecp256k1] internal consistency check failed: %s\n", str);
    abort();
}
#else
void kaspa_secp256k1_default_illegal_callback_fn(const char* str, void* data);
void kaspa_secp256k1_default_error_callback_fn(const char* str, void* data);
#endif

static const kaspa_secp256k1_callback default_illegal_callback = {
    kaspa_secp256k1_default_illegal_callback_fn,
    NULL
};

static const kaspa_secp256k1_callback default_error_callback = {
    kaspa_secp256k1_default_error_callback_fn,
    NULL
};

struct kaspa_secp256k1_context_struct {
    kaspa_secp256k1_ecmult_context ecmult_ctx;
    kaspa_secp256k1_ecmult_gen_context ecmult_gen_ctx;
    kaspa_secp256k1_callback illegal_callback;
    kaspa_secp256k1_callback error_callback;
    int declassify;
};

static const kaspa_secp256k1_context kaspa_secp256k1_context_no_precomp_ = {
    { 0 },
    { 0 },
    { kaspa_secp256k1_default_illegal_callback_fn, 0 },
    { kaspa_secp256k1_default_error_callback_fn, 0 },
    0
};
const kaspa_secp256k1_context *kaspa_secp256k1_context_no_precomp = &kaspa_secp256k1_context_no_precomp_;

size_t kaspa_secp256k1_context_preallocated_size(unsigned int flags) {
    size_t ret = ROUND_TO_ALIGN(sizeof(kaspa_secp256k1_context));
    /* A return value of 0 is reserved as an indicator for errors when we call this function internally. */
    VERIFY_CHECK(ret != 0);

    if (EXPECT((flags & kaspa_secp256k1_FLAGS_TYPE_MASK) != kaspa_secp256k1_FLAGS_TYPE_CONTEXT, 0)) {
            kaspa_secp256k1_callback_call(&default_illegal_callback,
                                    "Invalid flags");
            return 0;
    }

    if (flags & kaspa_secp256k1_FLAGS_BIT_CONTEXT_SIGN) {
        ret += kaspa_secp256k1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
    }
    if (flags & kaspa_secp256k1_FLAGS_BIT_CONTEXT_VERIFY) {
        ret += kaspa_secp256k1_ECMULT_CONTEXT_PREALLOCATED_SIZE;
    }
    return ret;
}

size_t kaspa_secp256k1_context_preallocated_clone_size(const kaspa_secp256k1_context* ctx) {
    size_t ret = ROUND_TO_ALIGN(sizeof(kaspa_secp256k1_context));
    VERIFY_CHECK(ctx != NULL);
    if (kaspa_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx)) {
        ret += kaspa_secp256k1_ECMULT_GEN_CONTEXT_PREALLOCATED_SIZE;
    }
    if (kaspa_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx)) {
        ret += kaspa_secp256k1_ECMULT_CONTEXT_PREALLOCATED_SIZE;
    }
    return ret;
}

kaspa_secp256k1_context* kaspa_secp256k1_context_preallocated_create(void* prealloc, unsigned int flags) {
    void* const base = prealloc;
    size_t prealloc_size;
    kaspa_secp256k1_context* ret;

    if (!kaspa_secp256k1_selftest()) {
        kaspa_secp256k1_callback_call(&default_error_callback, "self test failed");
    }

    prealloc_size = kaspa_secp256k1_context_preallocated_size(flags);
    if (prealloc_size == 0) {
        return NULL;
    }
    VERIFY_CHECK(prealloc != NULL);
    ret = (kaspa_secp256k1_context*)manual_alloc(&prealloc, sizeof(kaspa_secp256k1_context), base, prealloc_size);
    ret->illegal_callback = default_illegal_callback;
    ret->error_callback = default_error_callback;

    kaspa_secp256k1_ecmult_context_init(&ret->ecmult_ctx);
    kaspa_secp256k1_ecmult_gen_context_init(&ret->ecmult_gen_ctx);

    /* Flags have been checked by kaspa_secp256k1_context_preallocated_size. */
    VERIFY_CHECK((flags & kaspa_secp256k1_FLAGS_TYPE_MASK) == kaspa_secp256k1_FLAGS_TYPE_CONTEXT);
    if (flags & kaspa_secp256k1_FLAGS_BIT_CONTEXT_SIGN) {
        kaspa_secp256k1_ecmult_gen_context_build(&ret->ecmult_gen_ctx, &prealloc);
    }
    if (flags & kaspa_secp256k1_FLAGS_BIT_CONTEXT_VERIFY) {
        kaspa_secp256k1_ecmult_context_build(&ret->ecmult_ctx, &prealloc);
    }
    ret->declassify = !!(flags & kaspa_secp256k1_FLAGS_BIT_CONTEXT_DECLASSIFY);

    return (kaspa_secp256k1_context*) ret;
}

kaspa_secp256k1_context* kaspa_secp256k1_context_create(unsigned int flags) {
    size_t const prealloc_size = kaspa_secp256k1_context_preallocated_size(flags);
    kaspa_secp256k1_context* ctx = (kaspa_secp256k1_context*)checked_malloc(&default_error_callback, prealloc_size);
    if (EXPECT(kaspa_secp256k1_context_preallocated_create(ctx, flags) == NULL, 0)) {
        free(ctx);
        return NULL;
    }

    return ctx;
}

kaspa_secp256k1_context* kaspa_secp256k1_context_preallocated_clone(const kaspa_secp256k1_context* ctx, void* prealloc) {
    size_t prealloc_size;
    kaspa_secp256k1_context* ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(prealloc != NULL);

    prealloc_size = kaspa_secp256k1_context_preallocated_clone_size(ctx);
    ret = (kaspa_secp256k1_context*)prealloc;
    memcpy(ret, ctx, prealloc_size);
    kaspa_secp256k1_ecmult_gen_context_finalize_memcpy(&ret->ecmult_gen_ctx, &ctx->ecmult_gen_ctx);
    kaspa_secp256k1_ecmult_context_finalize_memcpy(&ret->ecmult_ctx, &ctx->ecmult_ctx);
    return ret;
}

kaspa_secp256k1_context* kaspa_secp256k1_context_clone(const kaspa_secp256k1_context* ctx) {
    kaspa_secp256k1_context* ret;
    size_t prealloc_size;

    VERIFY_CHECK(ctx != NULL);
    prealloc_size = kaspa_secp256k1_context_preallocated_clone_size(ctx);
    ret = (kaspa_secp256k1_context*)checked_malloc(&ctx->error_callback, prealloc_size);
    ret = kaspa_secp256k1_context_preallocated_clone(ctx, ret);
    return ret;
}

void kaspa_secp256k1_context_preallocated_destroy(kaspa_secp256k1_context* ctx) {
    ARG_CHECK_NO_RETURN(ctx != kaspa_secp256k1_context_no_precomp);
    if (ctx != NULL) {
        kaspa_secp256k1_ecmult_context_clear(&ctx->ecmult_ctx);
        kaspa_secp256k1_ecmult_gen_context_clear(&ctx->ecmult_gen_ctx);
    }
}

void kaspa_secp256k1_context_destroy(kaspa_secp256k1_context* ctx) {
    if (ctx != NULL) {
        kaspa_secp256k1_context_preallocated_destroy(ctx);
        free(ctx);
    }
}

void kaspa_secp256k1_context_set_illegal_callback(kaspa_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    ARG_CHECK_NO_RETURN(ctx != kaspa_secp256k1_context_no_precomp);
    if (fun == NULL) {
        fun = kaspa_secp256k1_default_illegal_callback_fn;
    }
    ctx->illegal_callback.fn = fun;
    ctx->illegal_callback.data = data;
}

void kaspa_secp256k1_context_set_error_callback(kaspa_secp256k1_context* ctx, void (*fun)(const char* message, void* data), const void* data) {
    ARG_CHECK_NO_RETURN(ctx != kaspa_secp256k1_context_no_precomp);
    if (fun == NULL) {
        fun = kaspa_secp256k1_default_error_callback_fn;
    }
    ctx->error_callback.fn = fun;
    ctx->error_callback.data = data;
}

kaspa_secp256k1_scratch_space* kaspa_secp256k1_scratch_space_create(const kaspa_secp256k1_context* ctx, size_t max_size) {
    VERIFY_CHECK(ctx != NULL);
    return kaspa_secp256k1_scratch_create(&ctx->error_callback, max_size);
}

void kaspa_secp256k1_scratch_space_destroy(const kaspa_secp256k1_context *ctx, kaspa_secp256k1_scratch_space* scratch) {
    VERIFY_CHECK(ctx != NULL);
    kaspa_secp256k1_scratch_destroy(&ctx->error_callback, scratch);
}

/* Mark memory as no-longer-secret for the purpose of analysing constant-time behaviour
 *  of the software. This is setup for use with valgrind but could be substituted with
 *  the appropriate instrumentation for other analysis tools.
 */
static kaspa_secp256k1_INLINE void kaspa_secp256k1_declassify(const kaspa_secp256k1_context* ctx, const void *p, size_t len) {
#if defined(VALGRIND)
    if (EXPECT(ctx->declassify,0)) VALGRIND_MAKE_MEM_DEFINED(p, len);
#else
    (void)ctx;
    (void)p;
    (void)len;
#endif
}

static int kaspa_secp256k1_pubkey_load(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_ge* ge, const kaspa_secp256k1_pubkey* pubkey) {
    if (sizeof(kaspa_secp256k1_ge_storage) == 64) {
        /* When the kaspa_secp256k1_ge_storage type is exactly 64 byte, use its
         * representation inside kaspa_secp256k1_pubkey, as conversion is very fast.
         * Note that kaspa_secp256k1_pubkey_save must use the same representation. */
        kaspa_secp256k1_ge_storage s;
        memcpy(&s, &pubkey->data[0], sizeof(s));
        kaspa_secp256k1_ge_from_storage(ge, &s);
    } else {
        /* Otherwise, fall back to 32-byte big endian for X and Y. */
        kaspa_secp256k1_fe x, y;
        kaspa_secp256k1_fe_set_b32(&x, pubkey->data);
        kaspa_secp256k1_fe_set_b32(&y, pubkey->data + 32);
        kaspa_secp256k1_ge_set_xy(ge, &x, &y);
    }
    ARG_CHECK(!kaspa_secp256k1_fe_is_zero(&ge->x));
    return 1;
}

static void kaspa_secp256k1_pubkey_save(kaspa_secp256k1_pubkey* pubkey, kaspa_secp256k1_ge* ge) {
    if (sizeof(kaspa_secp256k1_ge_storage) == 64) {
        kaspa_secp256k1_ge_storage s;
        kaspa_secp256k1_ge_to_storage(&s, ge);
        memcpy(&pubkey->data[0], &s, sizeof(s));
    } else {
        VERIFY_CHECK(!kaspa_secp256k1_ge_is_infinity(ge));
        kaspa_secp256k1_fe_normalize_var(&ge->x);
        kaspa_secp256k1_fe_normalize_var(&ge->y);
        kaspa_secp256k1_fe_get_b32(pubkey->data, &ge->x);
        kaspa_secp256k1_fe_get_b32(pubkey->data + 32, &ge->y);
    }
}

int kaspa_secp256k1_ec_pubkey_parse(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_pubkey* pubkey, const unsigned char *input, size_t inputlen) {
    kaspa_secp256k1_ge Q;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(input != NULL);
    if (!kaspa_secp256k1_eckey_pubkey_parse(&Q, input, inputlen)) {
        return 0;
    }
    if (!kaspa_secp256k1_ge_is_in_correct_subgroup(&Q)) {
        return 0;
    }
    kaspa_secp256k1_pubkey_save(pubkey, &Q);
    kaspa_secp256k1_ge_clear(&Q);
    return 1;
}

int kaspa_secp256k1_ec_pubkey_serialize(const kaspa_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const kaspa_secp256k1_pubkey* pubkey, unsigned int flags) {
    kaspa_secp256k1_ge Q;
    size_t len;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(*outputlen >= ((flags & kaspa_secp256k1_FLAGS_BIT_COMPRESSION) ? 33u : 65u));
    len = *outputlen;
    *outputlen = 0;
    ARG_CHECK(output != NULL);
    memset(output, 0, len);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK((flags & kaspa_secp256k1_FLAGS_TYPE_MASK) == kaspa_secp256k1_FLAGS_TYPE_COMPRESSION);
    if (kaspa_secp256k1_pubkey_load(ctx, &Q, pubkey)) {
        ret = kaspa_secp256k1_eckey_pubkey_serialize(&Q, output, &len, flags & kaspa_secp256k1_FLAGS_BIT_COMPRESSION);
        if (ret) {
            *outputlen = len;
        }
    }
    return ret;
}

static void kaspa_secp256k1_ecdsa_signature_load(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_scalar* r, kaspa_secp256k1_scalar* s, const kaspa_secp256k1_ecdsa_signature* sig) {
    (void)ctx;
    if (sizeof(kaspa_secp256k1_scalar) == 32) {
        /* When the kaspa_secp256k1_scalar type is exactly 32 byte, use its
         * representation inside kaspa_secp256k1_ecdsa_signature, as conversion is very fast.
         * Note that kaspa_secp256k1_ecdsa_signature_save must use the same representation. */
        memcpy(r, &sig->data[0], 32);
        memcpy(s, &sig->data[32], 32);
    } else {
        kaspa_secp256k1_scalar_set_b32(r, &sig->data[0], NULL);
        kaspa_secp256k1_scalar_set_b32(s, &sig->data[32], NULL);
    }
}

static void kaspa_secp256k1_ecdsa_signature_save(kaspa_secp256k1_ecdsa_signature* sig, const kaspa_secp256k1_scalar* r, const kaspa_secp256k1_scalar* s) {
    if (sizeof(kaspa_secp256k1_scalar) == 32) {
        memcpy(&sig->data[0], r, 32);
        memcpy(&sig->data[32], s, 32);
    } else {
        kaspa_secp256k1_scalar_get_b32(&sig->data[0], r);
        kaspa_secp256k1_scalar_get_b32(&sig->data[32], s);
    }
}

int kaspa_secp256k1_ecdsa_signature_parse_der(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_ecdsa_signature* sig, const unsigned char *input, size_t inputlen) {
    kaspa_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input != NULL);

    if (kaspa_secp256k1_ecdsa_sig_parse(&r, &s, input, inputlen)) {
        kaspa_secp256k1_ecdsa_signature_save(sig, &r, &s);
        return 1;
    } else {
        memset(sig, 0, sizeof(*sig));
        return 0;
    }
}

int kaspa_secp256k1_ecdsa_signature_parse_compact(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_ecdsa_signature* sig, const unsigned char *input64) {
    kaspa_secp256k1_scalar r, s;
    int ret = 1;
    int overflow = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(input64 != NULL);

    kaspa_secp256k1_scalar_set_b32(&r, &input64[0], &overflow);
    ret &= !overflow;
    kaspa_secp256k1_scalar_set_b32(&s, &input64[32], &overflow);
    ret &= !overflow;
    if (ret) {
        kaspa_secp256k1_ecdsa_signature_save(sig, &r, &s);
    } else {
        memset(sig, 0, sizeof(*sig));
    }
    return ret;
}

int kaspa_secp256k1_ecdsa_signature_serialize_der(const kaspa_secp256k1_context* ctx, unsigned char *output, size_t *outputlen, const kaspa_secp256k1_ecdsa_signature* sig) {
    kaspa_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(outputlen != NULL);
    ARG_CHECK(sig != NULL);

    kaspa_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return kaspa_secp256k1_ecdsa_sig_serialize(output, outputlen, &r, &s);
}

int kaspa_secp256k1_ecdsa_signature_serialize_compact(const kaspa_secp256k1_context* ctx, unsigned char *output64, const kaspa_secp256k1_ecdsa_signature* sig) {
    kaspa_secp256k1_scalar r, s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output64 != NULL);
    ARG_CHECK(sig != NULL);

    kaspa_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    kaspa_secp256k1_scalar_get_b32(&output64[0], &r);
    kaspa_secp256k1_scalar_get_b32(&output64[32], &s);
    return 1;
}

int kaspa_secp256k1_ecdsa_signature_normalize(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_ecdsa_signature *sigout, const kaspa_secp256k1_ecdsa_signature *sigin) {
    kaspa_secp256k1_scalar r, s;
    int ret = 0;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sigin != NULL);

    kaspa_secp256k1_ecdsa_signature_load(ctx, &r, &s, sigin);
    ret = kaspa_secp256k1_scalar_is_high(&s);
    if (sigout != NULL) {
        if (ret) {
            kaspa_secp256k1_scalar_negate(&s, &s);
        }
        kaspa_secp256k1_ecdsa_signature_save(sigout, &r, &s);
    }

    return ret;
}

int kaspa_secp256k1_ecdsa_verify(const kaspa_secp256k1_context* ctx, const kaspa_secp256k1_ecdsa_signature *sig, const unsigned char *msghash32, const kaspa_secp256k1_pubkey *pubkey) {
    kaspa_secp256k1_ge q;
    kaspa_secp256k1_scalar r, s;
    kaspa_secp256k1_scalar m;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(kaspa_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(pubkey != NULL);

    kaspa_secp256k1_scalar_set_b32(&m, msghash32, NULL);
    kaspa_secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    return (!kaspa_secp256k1_scalar_is_high(&s) &&
            kaspa_secp256k1_pubkey_load(ctx, &q, pubkey) &&
            kaspa_secp256k1_ecdsa_sig_verify(&ctx->ecmult_ctx, &r, &s, &q, &m));
}

static kaspa_secp256k1_INLINE void buffer_append(unsigned char *buf, unsigned int *offset, const void *data, unsigned int len) {
    memcpy(buf + *offset, data, len);
    *offset += len;
}

static int nonce_function_rfc6979(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *algo16, void *data, unsigned int counter) {
   unsigned char keydata[112];
   unsigned int offset = 0;
   kaspa_secp256k1_rfc6979_hmac_sha256 rng;
   unsigned int i;
   /* We feed a byte array to the PRNG as input, consisting of:
    * - the private key (32 bytes) and message (32 bytes), see RFC 6979 3.2d.
    * - optionally 32 extra bytes of data, see RFC 6979 3.6 Additional Data.
    * - optionally 16 extra bytes with the algorithm name.
    * Because the arguments have distinct fixed lengths it is not possible for
    *  different argument mixtures to emulate each other and result in the same
    *  nonces.
    */
   buffer_append(keydata, &offset, key32, 32);
   buffer_append(keydata, &offset, msg32, 32);
   if (data != NULL) {
       buffer_append(keydata, &offset, data, 32);
   }
   if (algo16 != NULL) {
       buffer_append(keydata, &offset, algo16, 16);
   }
   kaspa_secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, offset);
   memset(keydata, 0, sizeof(keydata));
   for (i = 0; i <= counter; i++) {
       kaspa_secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
   }
   kaspa_secp256k1_rfc6979_hmac_sha256_finalize(&rng);
   return 1;
}

const kaspa_secp256k1_nonce_function kaspa_secp256k1_nonce_function_rfc6979 = nonce_function_rfc6979;
const kaspa_secp256k1_nonce_function kaspa_secp256k1_nonce_function_default = nonce_function_rfc6979;

static int kaspa_secp256k1_ecdsa_sign_inner(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_scalar* r, kaspa_secp256k1_scalar* s, int* recid, const unsigned char *msg32, const unsigned char *seckey, kaspa_secp256k1_nonce_function noncefp, const void* noncedata) {
    kaspa_secp256k1_scalar sec, non, msg;
    int ret = 0;
    int is_sec_valid;
    unsigned char nonce32[32];
    unsigned int count = 0;
    /* Default initialization here is important so we won't pass uninit values to the cmov in the end */
    *r = kaspa_secp256k1_scalar_zero;
    *s = kaspa_secp256k1_scalar_zero;
    if (recid) {
        *recid = 0;
    }
    if (noncefp == NULL) {
        noncefp = kaspa_secp256k1_nonce_function_default;
    }

    /* Fail if the secret key is invalid. */
    is_sec_valid = kaspa_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    kaspa_secp256k1_scalar_cmov(&sec, &kaspa_secp256k1_scalar_one, !is_sec_valid);
    kaspa_secp256k1_scalar_set_b32(&msg, msg32, NULL);
    while (1) {
        int is_nonce_valid;
        ret = !!noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
        if (!ret) {
            break;
        }
        is_nonce_valid = kaspa_secp256k1_scalar_set_b32_seckey(&non, nonce32);
        /* The nonce is still secret here, but it being invalid is is less likely than 1:2^255. */
        kaspa_secp256k1_declassify(ctx, &is_nonce_valid, sizeof(is_nonce_valid));
        if (is_nonce_valid) {
            ret = kaspa_secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, r, s, &sec, &msg, &non, recid);
            /* The final signature is no longer a secret, nor is the fact that we were successful or not. */
            kaspa_secp256k1_declassify(ctx, &ret, sizeof(ret));
            if (ret) {
                break;
            }
        }
        count++;
    }
    /* We don't want to declassify is_sec_valid and therefore the range of
     * seckey. As a result is_sec_valid is included in ret only after ret was
     * used as a branching variable. */
    ret &= is_sec_valid;
    memset(nonce32, 0, 32);
    kaspa_secp256k1_scalar_clear(&msg);
    kaspa_secp256k1_scalar_clear(&non);
    kaspa_secp256k1_scalar_clear(&sec);
    kaspa_secp256k1_scalar_cmov(r, &kaspa_secp256k1_scalar_zero, !ret);
    kaspa_secp256k1_scalar_cmov(s, &kaspa_secp256k1_scalar_zero, !ret);
    if (recid) {
        const int zero = 0;
        kaspa_secp256k1_int_cmov(recid, &zero, !ret);
    }
    return ret;
}

int kaspa_secp256k1_ecdsa_sign(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_ecdsa_signature *signature, const unsigned char *msghash32, const unsigned char *seckey, kaspa_secp256k1_nonce_function noncefp, const void* noncedata) {
    kaspa_secp256k1_scalar r, s;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(kaspa_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msghash32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);

    ret = kaspa_secp256k1_ecdsa_sign_inner(ctx, &r, &s, NULL, msghash32, seckey, noncefp, noncedata);
    kaspa_secp256k1_ecdsa_signature_save(signature, &r, &s);
    return ret;
}

int kaspa_secp256k1_ec_seckey_verify(const kaspa_secp256k1_context* ctx, const unsigned char *seckey) {
    kaspa_secp256k1_scalar sec;
    int ret;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ret = kaspa_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    kaspa_secp256k1_scalar_clear(&sec);
    return ret;
}

static int kaspa_secp256k1_ec_pubkey_create_helper(const kaspa_secp256k1_ecmult_gen_context *ecmult_gen_ctx, kaspa_secp256k1_scalar *seckey_scalar, kaspa_secp256k1_ge *p, const unsigned char *seckey) {
    kaspa_secp256k1_gej pj;
    int ret;

    ret = kaspa_secp256k1_scalar_set_b32_seckey(seckey_scalar, seckey);
    kaspa_secp256k1_scalar_cmov(seckey_scalar, &kaspa_secp256k1_scalar_one, !ret);

    kaspa_secp256k1_ecmult_gen(ecmult_gen_ctx, &pj, seckey_scalar);
    kaspa_secp256k1_ge_set_gej(p, &pj);
    return ret;
}

int kaspa_secp256k1_ec_pubkey_create(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_pubkey *pubkey, const unsigned char *seckey) {
    kaspa_secp256k1_ge p;
    kaspa_secp256k1_scalar seckey_scalar;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    memset(pubkey, 0, sizeof(*pubkey));
    ARG_CHECK(kaspa_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(seckey != NULL);

    ret = kaspa_secp256k1_ec_pubkey_create_helper(&ctx->ecmult_gen_ctx, &seckey_scalar, &p, seckey);
    kaspa_secp256k1_pubkey_save(pubkey, &p);
    kaspa_secp256k1_memczero(pubkey, sizeof(*pubkey), !ret);

    kaspa_secp256k1_scalar_clear(&seckey_scalar);
    return ret;
}

int kaspa_secp256k1_ec_seckey_negate(const kaspa_secp256k1_context* ctx, unsigned char *seckey) {
    kaspa_secp256k1_scalar sec;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);

    ret = kaspa_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    kaspa_secp256k1_scalar_cmov(&sec, &kaspa_secp256k1_scalar_zero, !ret);
    kaspa_secp256k1_scalar_negate(&sec, &sec);
    kaspa_secp256k1_scalar_get_b32(seckey, &sec);

    kaspa_secp256k1_scalar_clear(&sec);
    return ret;
}

int kaspa_secp256k1_ec_privkey_negate(const kaspa_secp256k1_context* ctx, unsigned char *seckey) {
    return kaspa_secp256k1_ec_seckey_negate(ctx, seckey);
}

int kaspa_secp256k1_ec_pubkey_negate(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_pubkey *pubkey) {
    int ret = 0;
    kaspa_secp256k1_ge p;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);

    ret = kaspa_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        kaspa_secp256k1_ge_neg(&p, &p);
        kaspa_secp256k1_pubkey_save(pubkey, &p);
    }
    return ret;
}


static int kaspa_secp256k1_ec_seckey_tweak_add_helper(kaspa_secp256k1_scalar *sec, const unsigned char *tweak32) {
    kaspa_secp256k1_scalar term;
    int overflow = 0;
    int ret = 0;

    kaspa_secp256k1_scalar_set_b32(&term, tweak32, &overflow);
    ret = (!overflow) & kaspa_secp256k1_eckey_privkey_tweak_add(sec, &term);
    kaspa_secp256k1_scalar_clear(&term);
    return ret;
}

int kaspa_secp256k1_ec_seckey_tweak_add(const kaspa_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    kaspa_secp256k1_scalar sec;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = kaspa_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    ret &= kaspa_secp256k1_ec_seckey_tweak_add_helper(&sec, tweak32);
    kaspa_secp256k1_scalar_cmov(&sec, &kaspa_secp256k1_scalar_zero, !ret);
    kaspa_secp256k1_scalar_get_b32(seckey, &sec);

    kaspa_secp256k1_scalar_clear(&sec);
    return ret;
}

int kaspa_secp256k1_ec_privkey_tweak_add(const kaspa_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    return kaspa_secp256k1_ec_seckey_tweak_add(ctx, seckey, tweak32);
}

static int kaspa_secp256k1_ec_pubkey_tweak_add_helper(const kaspa_secp256k1_ecmult_context* ecmult_ctx, kaspa_secp256k1_ge *p, const unsigned char *tweak32) {
    kaspa_secp256k1_scalar term;
    int overflow = 0;
    kaspa_secp256k1_scalar_set_b32(&term, tweak32, &overflow);
    return !overflow && kaspa_secp256k1_eckey_pubkey_tweak_add(ecmult_ctx, p, &term);
}

int kaspa_secp256k1_ec_pubkey_tweak_add(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
    kaspa_secp256k1_ge p;
    int ret = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(kaspa_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    ret = kaspa_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    ret = ret && kaspa_secp256k1_ec_pubkey_tweak_add_helper(&ctx->ecmult_ctx, &p, tweak32);
    if (ret) {
        kaspa_secp256k1_pubkey_save(pubkey, &p);
    }

    return ret;
}

int kaspa_secp256k1_ec_seckey_tweak_mul(const kaspa_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    kaspa_secp256k1_scalar factor;
    kaspa_secp256k1_scalar sec;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(seckey != NULL);
    ARG_CHECK(tweak32 != NULL);

    kaspa_secp256k1_scalar_set_b32(&factor, tweak32, &overflow);
    ret = kaspa_secp256k1_scalar_set_b32_seckey(&sec, seckey);
    ret &= (!overflow) & kaspa_secp256k1_eckey_privkey_tweak_mul(&sec, &factor);
    kaspa_secp256k1_scalar_cmov(&sec, &kaspa_secp256k1_scalar_zero, !ret);
    kaspa_secp256k1_scalar_get_b32(seckey, &sec);

    kaspa_secp256k1_scalar_clear(&sec);
    kaspa_secp256k1_scalar_clear(&factor);
    return ret;
}

int kaspa_secp256k1_ec_privkey_tweak_mul(const kaspa_secp256k1_context* ctx, unsigned char *seckey, const unsigned char *tweak32) {
    return kaspa_secp256k1_ec_seckey_tweak_mul(ctx, seckey, tweak32);
}

int kaspa_secp256k1_ec_pubkey_tweak_mul(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_pubkey *pubkey, const unsigned char *tweak32) {
    kaspa_secp256k1_ge p;
    kaspa_secp256k1_scalar factor;
    int ret = 0;
    int overflow = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(kaspa_secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(tweak32 != NULL);

    kaspa_secp256k1_scalar_set_b32(&factor, tweak32, &overflow);
    ret = !overflow && kaspa_secp256k1_pubkey_load(ctx, &p, pubkey);
    memset(pubkey, 0, sizeof(*pubkey));
    if (ret) {
        if (kaspa_secp256k1_eckey_pubkey_tweak_mul(&ctx->ecmult_ctx, &p, &factor)) {
            kaspa_secp256k1_pubkey_save(pubkey, &p);
        } else {
            ret = 0;
        }
    }

    return ret;
}

int kaspa_secp256k1_context_randomize(kaspa_secp256k1_context* ctx, const unsigned char *seed32) {
    VERIFY_CHECK(ctx != NULL);
    if (kaspa_secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx)) {
        kaspa_secp256k1_ecmult_gen_blind(&ctx->ecmult_gen_ctx, seed32);
    }
    return 1;
}

int kaspa_secp256k1_ec_pubkey_combine(const kaspa_secp256k1_context* ctx, kaspa_secp256k1_pubkey *pubnonce, const kaspa_secp256k1_pubkey * const *pubnonces, size_t n) {
    size_t i;
    kaspa_secp256k1_gej Qj;
    kaspa_secp256k1_ge Q;

    ARG_CHECK(pubnonce != NULL);
    memset(pubnonce, 0, sizeof(*pubnonce));
    ARG_CHECK(n >= 1);
    ARG_CHECK(pubnonces != NULL);

    kaspa_secp256k1_gej_set_infinity(&Qj);

    for (i = 0; i < n; i++) {
        kaspa_secp256k1_pubkey_load(ctx, &Q, pubnonces[i]);
        kaspa_secp256k1_gej_add_ge(&Qj, &Qj, &Q);
    }
    if (kaspa_secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    kaspa_secp256k1_ge_set_gej(&Q, &Qj);
    kaspa_secp256k1_pubkey_save(pubnonce, &Q);
    return 1;
}

#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/main_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/main_impl.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
# include "modules/extrakeys/main_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
# include "modules/schnorrsig/main_impl.h"
#endif
