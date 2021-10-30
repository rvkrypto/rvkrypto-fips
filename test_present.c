//	test_present.c
//	2021-10-30	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Unit tests for Block Cipher Present (CHES 2007 / ISO/IEC 29192-2:2019).

#include <stdio.h>
#include <string.h>

#include "rvkintrin.h"
#include "test_rvkat.h"
#include "sm4/sm4_api.h"
#include "rv_endian.h"


const uint8_t present_sbox[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
	0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2
};

const uint8_t present_pperm[64] = {
	0,	16,	32,	48,	1,	17,	33,	49,	2,	18,	34,	50,	3,	19,	35,	51,
	4,	20,	36,	52,	5,	21,	37,	53,	6,	22,	38,	54,	7,	23,	39,	55,
	8,	24,	40,	56,	9,	25,	41,	57,	10,	26,	42,	58,	11,	27,	43,	59,
	12,	28,	44,	60,	13,	29,	45,	61,	14,	30,	46,	62,	15,	31,	47,	63
};


//	key expansion

void key80(uint64_t rk[32], const uint8_t key[10])
{
	int i;
	uint64_t t, k0, k1;

	//	k0 has key bits 79..16, k1 has bits 15..0 in low bits
	k0 = get64u_be(key);
	k1 = get16u_be(key + 8);
	rk[0] = k0;
	
	for (i = 1; i < 32; i++) {

		//	1.	key register is rotated by 61 bit positions to the left
		t  = (k0 << 61) | ( k1 << (61-16) ) | ( k0 >> (80 - 61) );
		k1 = (k0 >> (64 - 61));

		//	2.	left-most four bits are passed through the PRESENT S-box
		k0 = (t & ~(0xFllu << 60)) | 
				(((uint64_t) present_sbox[(t >> 60) & 0xF]) << 60);

		//	3.	round_counter value i is exclusive-ORed with bits k19..k15 
		k0 ^= i >> 1;
		k1 ^= i << 15;
		k1 &= 0xFFFF;
		
		rk[i] = k0;
	}
}


//	Reference sBoxlayer

uint64_t s_layer(uint64_t x)
{
	int i;
	uint64_t y;

	y = 0;
	for (i = 0; i < 64; i += 4) {	
		y |= ((uint64_t) present_sbox[(x >> i) & 0xF]) << i;
	}
	
	return y;
}

//	Reference pLayer

uint64_t p_layer(uint64_t x)
{

	int i;
	uint64_t y;

	y = 0;
	for (i = 0; i < 64; i++) {	
		y |= ((x >> i) & 1LLU) << present_pperm[i];
	}
	
	return y;
}

//	handles pt/ct and key schedule as 64-bit words

uint64_t present_u64rk_enc(uint64_t x, const uint64_t rk[32])
{
	int i;

	for (i = 0; i < 31; i++) {
		x ^= rk[i];
		x = s_layer(x);
		x = p_layer(x);
	}
	x ^= rk[i];
	
	return x;
}

//	byte test interface

void present80_enc(uint8_t ct[8], const uint8_t pt[8], const uint8_t key[10])
{
	uint64_t x;
	uint64_t rk[32];

	key80(rk, key);

	x = get64u_be(pt);
	x = present_u64rk_enc(x, rk);
	put64u_be(ct, x);	
}

int kek()
{
	int i;
	uint8_t key[10] = { 0 };
	uint64_t rk[32] = { -1 };
	uint64_t x = -1;
	
//	memset(key, 0xFF, 10);
	
	key80(rk, key);
	
	for (i = 0; i < 31; i++) {
	
		x ^= rk[i];
		x = s_layer(x);
		x = p_layer(x);
	
		printf("r= %2d  x= %016lX  k= %016lX\n", i, x, rk[i]);
	}
	x ^= rk[i];
	
	printf("r= %2d  x= %016lX  k= %016lX\n", i, x, rk[1]);
	
	return 0;
}


int test_present()
{
	//	(key, pt, ct) from the Ches 2007 paper
	const char *present80_tv[4][3] = {
		{	"00000000000000000000",	"0000000000000000",	"5579C1387B228445"	},
		{	"FFFFFFFFFFFFFFFFFFFF",	"0000000000000000",	"E72C46C0F5945049"	},
		{	"00000000000000000000",	"FFFFFFFFFFFFFFFF",	"A112FFC72F68417B"	},
		{	"FFFFFFFFFFFFFFFFFFFF",	"FFFFFFFFFFFFFFFF",	"3333DCD3213210D2"	}
	};

	int fail = 0;
	int i;

	uint8_t pt[8], ct[8], key[16];

	for (i = 0; i < 4; i++) {
		rvkat_gethex(key, sizeof(key), present80_tv[i][0]);
		rvkat_gethex(pt, sizeof(pt), present80_tv[i][1]);
		memset(ct, 0x55, sizeof(ct));

		present80_enc(ct, pt, key);
		fail += rvkat_chkhex("PRESENT-80 Encrypt",
								ct, 8, present80_tv[i][2]);
	}
	
	return fail;
}

