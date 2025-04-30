/***********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_SCRATCH_IMPL_H
#define kaspa_secp256k1_SCRATCH_IMPL_H

#include "util.h"
#include "scratch.h"

static kaspa_secp256k1_scratch* kaspa_secp256k1_scratch_create(const kaspa_secp256k1_callback* error_callback, size_t size) {
    const size_t base_alloc = ROUND_TO_ALIGN(sizeof(kaspa_secp256k1_scratch));
    void *alloc = checked_malloc(error_callback, base_alloc + size);
    kaspa_secp256k1_scratch* ret = (kaspa_secp256k1_scratch *)alloc;
    if (ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        memcpy(ret->magic, "scratch", 8);
        ret->data = (void *) ((char *) alloc + base_alloc);
        ret->max_size = size;
    }
    return ret;
}

static void kaspa_secp256k1_scratch_destroy(const kaspa_secp256k1_callback* error_callback, kaspa_secp256k1_scratch* scratch) {
    if (scratch != NULL) {
        VERIFY_CHECK(scratch->alloc_size == 0); /* all checkpoints should be applied */
        if (kaspa_secp256k1_memcmp_var(scratch->magic, "scratch", 8) != 0) {
            kaspa_secp256k1_callback_call(error_callback, "invalid scratch space");
            return;
        }
        memset(scratch->magic, 0, sizeof(scratch->magic));
        free(scratch);
    }
}

static size_t kaspa_secp256k1_scratch_checkpoint(const kaspa_secp256k1_callback* error_callback, const kaspa_secp256k1_scratch* scratch) {
    if (kaspa_secp256k1_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        kaspa_secp256k1_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    return scratch->alloc_size;
}

static void kaspa_secp256k1_scratch_apply_checkpoint(const kaspa_secp256k1_callback* error_callback, kaspa_secp256k1_scratch* scratch, size_t checkpoint) {
    if (kaspa_secp256k1_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        kaspa_secp256k1_callback_call(error_callback, "invalid scratch space");
        return;
    }
    if (checkpoint > scratch->alloc_size) {
        kaspa_secp256k1_callback_call(error_callback, "invalid checkpoint");
        return;
    }
    scratch->alloc_size = checkpoint;
}

static size_t kaspa_secp256k1_scratch_max_allocation(const kaspa_secp256k1_callback* error_callback, const kaspa_secp256k1_scratch* scratch, size_t objects) {
    if (kaspa_secp256k1_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        kaspa_secp256k1_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    /* Ensure that multiplication will not wrap around */
    if (ALIGNMENT > 1 && objects > SIZE_MAX/(ALIGNMENT - 1)) {
        return 0;
    }
    if (scratch->max_size - scratch->alloc_size <= objects * (ALIGNMENT - 1)) {
        return 0;
    }
    return scratch->max_size - scratch->alloc_size - objects * (ALIGNMENT - 1);
}

static void *kaspa_secp256k1_scratch_alloc(const kaspa_secp256k1_callback* error_callback, kaspa_secp256k1_scratch* scratch, size_t size) {
    void *ret;
    size_t rounded_size;

    rounded_size = ROUND_TO_ALIGN(size);
    /* Check that rounding did not wrap around */
    if (rounded_size < size) {
        return NULL;
    }
    size = rounded_size;

    if (kaspa_secp256k1_memcmp_var(scratch->magic, "scratch", 8) != 0) {
        kaspa_secp256k1_callback_call(error_callback, "invalid scratch space");
        return NULL;
    }

    if (size > scratch->max_size - scratch->alloc_size) {
        return NULL;
    }
    ret = (void *) ((char *) scratch->data + scratch->alloc_size);
    memset(ret, 0, size);
    scratch->alloc_size += size;

    return ret;
}

#endif
