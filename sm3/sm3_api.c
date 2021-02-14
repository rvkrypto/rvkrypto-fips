//	sm3_api.c
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	The Chinese Standard SM3 Hash Function
//	GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018

//	Simple wrapper for the compression function

#include <string.h>
#include "sm3_api.h"

//	pointer to the compression functions
void (*sm3_compress)(void *s) = &sm3_cf256_rvk;

//	Compute 32-byte message digest to "md" from "in" which has "inlen" bytes

void sm3_256(uint8_t * md, const void *in, size_t inlen)
{
	size_t i;
	uint64_t x;
	uint32_t t, s[8 + 16];

	uint8_t *mp = (uint8_t *) & s[8];
	const uint8_t *p = in;

	//	initial values
	s[0] = 0x7380166F;
	s[1] = 0x4914B2B9;
	s[2] = 0x172442D7;
	s[3] = 0xDA8A0600;
	s[4] = 0xA96F30BC;
	s[5] = 0x163138AA;
	s[6] = 0xE38DEE4D;
	s[7] = 0xB0FB0E4E;

	//	"md padding"
	x = inlen << 3;							//	length in bits

	while (inlen >= 64) {					//	full blocks
		memcpy(mp, p, 64);
		sm3_compress(s);
		inlen -= 64;
		p += 64;
	}
	memcpy(mp, p, inlen);					//	last data block
	mp[inlen++] = 0x80;
	if (inlen > 56) {
		memset(mp + inlen, 0x00, 64 - inlen);
		sm3_compress(s);
		inlen = 0;
	}
	i = 64;									//	process length
	while (x > 0) {
		mp[--i] = x & 0xFF;
		x >>= 8;
	}
	memset(&mp[inlen], 0x00, i - inlen);
	sm3_compress(s);

	//	store big endian output
	for (i = 0; i < 32; i += 4) {
		t = s[i >> 2];
		md[i] = t >> 24;
		md[i + 1] = (t >> 16) & 0xFF;
		md[i + 2] = (t >> 8) & 0xFF;
		md[i + 3] = t & 0xFF;
	}
}
