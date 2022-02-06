//	present.c
//	2021-10-30	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Block Cipher PRESENT-80/128 (CHES 2007 / ISO/IEC 29192-2:2019).

#include "present_api.h"
#include "rv_endian.h"
#include "riscv_crypto.h"

#define SBOX64_ENC 0x21748FE3DA09B65CLLU

#ifdef RVKINTRIN_RV32
uint64_t (*present_rk_enc)(uint64_t x,
						   const uint64_t rk[32]) = present_enc_rv32;
uint64_t (*present_rk_dec)(uint64_t x,
						   const uint64_t rk[32]) = present_dec_rv32;
#else
uint64_t (*present_rk_enc)(uint64_t x,
						   const uint64_t rk[32]) = present_enc_rv64;
uint64_t (*present_rk_dec)(uint64_t x,
						   const uint64_t rk[32]) = present_dec_rv64;
#endif

//	80 bit key expansion

void present80_key(uint64_t rk[32], const uint8_t key[10])
{
	int i;
	uint64_t t, k0, k1;

	//	k1 has key bits 79..16, k0 has bits 15..0 in low bits
	k1 = get64u_be(key);
	k0 = get16u_be(key + 8);
	rk[0] = k1;

	for (i = 1; i < 32; i++) {

		//	1.	key register is rotated by 61 bit positions to the left
		t = (k1 << 61) | (k0 << (61 - 16)) | (k1 >> (80 - 61));
		k0 = (k1 >> (64 - 61));

		//	2.	left-most four bits are passed through the PRESENT S-box
		k1 = (t & ~(0xFllu << 60)) |
			 (((SBOX64_ENC) >> ((t >> 58) & 0x3C)) << 60);

		//	3.	round_counter value i is exclusive-ORed with bits k09..k05
		k1 ^= i >> 1;
		k0 ^= i << 15;
		k0 &= 0xFFFF;

		rk[i] = k1;
	}
}

//	128 bit key expansion

void present128_key(uint64_t rk[32], const uint8_t key[16])
{
	int i;
	uint64_t t, k0, k1;

	//	k1 has key bits 127..64, k0 has bits 63..0
	k1 = get64u_be(key);
	k0 = get64u_be(key + 8);
	rk[0] = k1;

	for (i = 1; i < 32; i++) {

		//	1.	key register is rotated by 61 bit positions to the left
		t = (k1 << 61) | (k0 >> (64 - 61));
		k0 = (k0 << 61) | (k1 >> (64 - 61));

		//	2.	left-most eight bits are passed through two PRESENT S-boxes
		k1 = (t & ~(0xFFllu << 56)) |
			 (((SBOX64_ENC) >> ((t >> 58) & 0x3C)) << 60) |
			 ((((SBOX64_ENC) >> ((t >> 54) & 0x3C)) & 0xF) << 56);

		//	3.	round_counter value i is exclusive-ORed with bits k09..k05
		k1 ^= i >> 2;
		k0 ^= ((uint64_t) i) << 62;

		rk[i] = k1;
	}
}

//	single call test interface

void present80_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[10])
{
	uint64_t x, rk[32];

	present80_key(rk, key);
	x = get64u_be(pt);
	x = present_rk_enc(x, rk);
	put64u_be(ct, x);
}

void present80_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[10])
{
	uint64_t x, rk[32];

	present80_key(rk, key);
	x = get64u_be(ct);
	x = present_rk_dec(x, rk);
	put64u_be(pt, x);
}

void present128_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[16])
{
	uint64_t x, rk[32];

	present128_key(rk, key);
	x = get64u_be(pt);
	x = present_rk_enc(x, rk);
	put64u_be(ct, x);
}

void present128_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[16])
{
	uint64_t x, rk[32];

	present128_key(rk, key);
	x = get64u_be(ct);
	x = present_rk_dec(x, rk);
	put64u_be(pt, x);
}
