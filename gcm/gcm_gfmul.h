//	gcm_gfmul.h
//	2020-03-23	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Core GHASH finite field operations

#ifndef _GCM_GFMUL_H_
#define _GCM_GFMUL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

//	A GF(2^128) element type -- just for alignment and to avoid casts

typedef union {
	uint8_t b[16];
	uint32_t w[4];
	uint64_t d[2];
} gf128_t;

//	bit reversal, 32-bit variants (rv32_ghash.c)
void ghash_rev_rv32(gf128_t * z);

//	32-bit compact version (rv32_ghash.c)
void ghash_mul_rv32(gf128_t * z, const gf128_t * x, const gf128_t * h);

//	32-bit karatsuba version (rv32_ghash.c)
void ghash_mul_rv32_kar(gf128_t * z, const gf128_t * x, const gf128_t * h);

//	bit reversal, 64-bit variant (rv64_ghash.c)
void ghash_rev_rv64(gf128_t * z);

//	64-bit version (Karatsuba optional) (rv64_ghash.c)
void ghash_mul_rv64(gf128_t * z, const gf128_t * x, const gf128_t * h);

//	Function pointers so that different versions can be tested. (aes_gcm.c)

//	reverse bits in bytes of a 128-bit block; do this for h and final value
extern void (*ghash_rev)(gf128_t * z);

//	finite field multiply z = ( z ^ rev(x) ) * h
extern void (*ghash_mul)(gf128_t * z, const gf128_t * x, const gf128_t * h);

#ifdef __cplusplus
}
#endif

#endif										//	_GCM_GFMUL_H_
