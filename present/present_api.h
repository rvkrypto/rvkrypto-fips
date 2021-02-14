//	present_api.h
//	2021-10-30	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Prototypes for lightweight block cipher PRESENT
//	A. Bogdanov et al, "PRESENT: An Ultra-Lightweight Block Cipher",
//	CHES 2007.	Standardized in ISO/IEC 29192-2:2019(EN).

#ifndef _PRESENT_API_H_
#define _PRESENT_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

//	present_rv32.c
uint64_t present_enc_rv32(uint64_t x, const uint64_t rk[32]);
uint64_t present_dec_rv32(uint64_t x, const uint64_t rk[32]);

//	present rv64.c
uint64_t present_enc_rv64(uint64_t x, const uint64_t rk[32]);
uint64_t present_dec_rv64(uint64_t x, const uint64_t rk[32]);

//	pointers to simple block encrypt/decrypt functions
extern uint64_t (*present_rk_enc)(uint64_t x, const uint64_t rk[32]);
extern uint64_t (*present_rk_dec)(uint64_t x, const uint64_t rk[32]);

//	present.c:
//	80 bit key expansion
void present80_key(uint64_t rk[32], const uint8_t key[10]);

//	128 bit key expansion
void present128_key(uint64_t rk[32], const uint8_t key[16]);

//	single call test interface that include the key schedule and endianess
void present80_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[10]);
void present80_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[10]);
void present128_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[16]);
void present128_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[16]);

#ifdef __cplusplus
}
#endif

#endif	//	_PRESENT_API_H_
