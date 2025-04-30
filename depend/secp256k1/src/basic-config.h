/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef kaspa_secp256k1_BASIC_CONFIG_H
#define kaspa_secp256k1_BASIC_CONFIG_H

#ifdef USE_BASIC_CONFIG

#undef USE_ASM_X86_64
#undef USE_ECMULT_STATIC_PRECOMPUTATION
#undef USE_EXTERNAL_ASM
#undef USE_EXTERNAL_DEFAULT_CALLBACKS
#undef USE_FORCE_WIDEMUL_INT64
#undef USE_FORCE_WIDEMUL_INT128
#undef ECMULT_WINDOW_SIZE

#define USE_WIDEMUL_64 1
#define ECMULT_WINDOW_SIZE 15

#endif /* USE_BASIC_CONFIG */

#endif /* kaspa_secp256k1_BASIC_CONFIG_H */
