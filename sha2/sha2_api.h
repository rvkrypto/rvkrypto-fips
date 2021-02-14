//	sha2_api.h
//	2020-03-09	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 180-4 (SHA-2) -- traditional "MD" type hash API interface.

#ifndef _SHA2_API_H_
#define _SHA2_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

//	=== Single-call hash wrappers ===

//	SHA2-224: Compute 28-byte hash to "md" from "in" which has "mlen" bytes.
void sha2_224(uint8_t *md, const void *m, size_t mlen);

//	SHA2-256: Compute 32-byte hash to "md" from "in" which has "mlen" bytes.
void sha2_256(uint8_t *md, const void *m, size_t mlen);

//	SHA2-384: Compute 48-byte hash to "md" from "in" which has "mlen" bytes.
void sha2_384(uint8_t *md, const void *m, size_t mlen);

//	SHA2-512: Compute 64-byte hash to "md" from "in" which has "mlen" bytes.
void sha2_512(uint8_t *md, const void *m, size_t mlen);

//	=== Compression Functions ===

//	function pointer to the compression function used by the test wrappers
extern void (*sha256_compress)(void *);
extern void (*sha512_compress)(void *);

void sha2_cf256_rvk(void *s);			//	SHA-224/256 CF for RV32 & RV64
void sha2_cf512_rvk64(void *s);			//	SHA-384/512 CF for RV64
void sha2_cf512_rvk32(void *s);			//	SHA-384/512 CF for RV32

#ifdef __cplusplus
}
#endif

#endif	//	_SHA2_API_H_
