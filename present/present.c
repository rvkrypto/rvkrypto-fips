//	present.c
//	2021-10-30	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Block Cipher PRESENT-80/128 (CHES 2007 / ISO/IEC 29192-2:2019).

#include "rvkintrin.h"
#include "present_api.h"
#include "rv_endian.h"

//	Forward S-Box and Permutation

static const uint8_t present_enc_sbox[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
	0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

static const uint8_t present_enc_perm[64] = {
	0,	16, 32, 48, 1,	17, 33, 49, 2,	18, 34, 50, 3,	19, 35, 51,
	4,	20, 36, 52, 5,	21, 37, 53, 6,	22, 38, 54, 7,	23, 39, 55,
	8,	24, 40, 56, 9,	25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
	12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63
};

//	Inverse S-Box and Permutation

static const uint8_t present_dec_sbox[16] = {
	0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD,
	0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA
};

static const uint8_t present_dec_perm[64] = {
	0,	4,	8,	12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
	1,	5,	9,	13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
	2,	6,	10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
	3,	7,	11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63
};

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
		t  = (k1 << 61) | ( k0 << (61-16) ) | ( k1 >> (80 - 61) );
		k0 = (k1 >> (64 - 61));

		//	2.	left-most four bits are passed through the PRESENT S-box
		k1 = (t & ~(0xFllu << 60)) |
				(((uint64_t) present_enc_sbox[(t >> 60) & 0xF]) << 60);

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
		t  = (k1 << 61) | (k0 >> (64 - 61));
		k0 = (k0 << 61) | (k1 >> (64 - 61));

		//	2.	left-most eight bits are passed through two PRESENT S-boxes
		k1 = (t & ~(0xFFllu << 56)) |
				(((uint64_t) present_enc_sbox[(t >> 56) & 0xF]) << 56) |
				(((uint64_t) present_enc_sbox[(t >> 60) & 0xF]) << 60);

		//	3.	round_counter value i is exclusive-ORed with bits k09..k05
		k1 ^= i >> 2;
		k0 ^= ((uint64_t) i) << 62;

		rk[i] = k1;
	}
}

//	Reference sBoxlayer

static uint64_t s_layer(uint64_t x, const uint8_t sbox[16])
{
	int i;
	uint64_t y;

	y = 0;
	for (i = 0; i < 64; i += 4) {
		y |= ((uint64_t) sbox[(x >> i) & 0xF]) << i;
	}

	return y;
}

//	Reference pLayer

static uint64_t p_layer(uint64_t x, const uint8_t perm[64])
{

	int i;
	uint64_t y;

	y = 0;
	for (i = 0; i < 64; i++) {
		y |= ((x >> i) & 1LLU) << perm[i];
	}

	return y;
}

//	handles input and output as 64-bit words

uint64_t present_64rk_enc(uint64_t x, const uint64_t rk[32])
{
	int i;

	for (i = 0; i < 31; i++) {
		x ^= rk[i];
		x = s_layer(x, present_enc_sbox);
		x = p_layer(x, present_enc_perm);
	}
	x ^= rk[i];

	return x;
}

uint64_t present_64rk_dec(uint64_t x, const uint64_t rk[32])
{
	int i;

	for (i = 31; i > 0; i--) {
		x ^= rk[i];
		x = p_layer(x, present_dec_perm);
		x = s_layer(x, present_dec_sbox);
	}
	x ^= rk[i];

	return x;
}

//	single call test interface

void present80_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[10])
{
	uint64_t x, rk[32];

	present80_key(rk, key);
	x = get64u_be(pt);
	x = present_64rk_enc(x, rk);
	put64u_be(ct, x);
}

void present80_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[10])
{
	uint64_t x, rk[32];

	present80_key(rk, key);
	x = get64u_be(ct);
	x = present_64rk_dec(x, rk);
	put64u_be(pt, x);
}

void present128_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[16])
{
	uint64_t x, rk[32];

	present128_key(rk, key);
	x = get64u_be(pt);
	x = present_64rk_enc(x, rk);
	put64u_be(ct, x);
}

void present128_dec(uint8_t pt[8], const uint8_t ct[8], const uint8_t key[16])
{
	uint64_t x, rk[32];

	present128_key(rk, key);
	x = get64u_be(ct);
	x = present_64rk_dec(x, rk);
	put64u_be(pt, x);
}

