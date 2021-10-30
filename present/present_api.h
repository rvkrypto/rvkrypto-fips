//	present_api.h
//	2021-10-30	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Prototypes for lightweight block cipher PRESENT
//	(A. Bogdanov et al, "PRESENT: An Ultra-Lightweight Block Cipher",
//	CHES 2007.	Standardized in ISO/IEC 29192-2:2019(EN).

#ifndef _PRESENT_API_H_
#define _PRESENT_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

//	80 bit key expansion
void present80_key(uint64_t rk[32], const uint8_t key[10]);

//	128 bit key expansion
void present128_key(uint64_t rk[32], const uint8_t key[16]);

//	handles encrypt/decrypt input and output as 64-bit words
uint64_t present_64rk_enc(uint64_t x, const uint64_t rk[32]);
uint64_t present_64rk_dec(uint64_t x, const uint64_t rk[32]);

//	single call test interface that include the key schedule and endianess
void present80_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[10]);
void present80_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[10]);
void present128_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[16]);
void present128_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[16]);

#ifdef __cplusplus
}
#endif

#endif	//	_PRESENT_API_H_
