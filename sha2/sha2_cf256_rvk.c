//	sha2_cf256_rvk.c
//	2020-03-08	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 180-4 SHA2-224/256 compression function for RV32 & RV64

#include "rvkintrin.h"
#include "sha2_api.h"

//	processing step, sets "d" and "h" as a function of all 8 inputs
//	and message schedule "mi", round constant "ki"
#define STEP_SHA256_R(a, b, c, d, e, f, g, h, mi, ki) { \
	h = h + (g ^ (e & (f ^ g))) + mi + ki;			\
	h = h + _rv_sha256sum1(e);						\
	d = d + h;										\
	h = h + _rv_sha256sum0(a);						\
	h = h + (((a | c) & b) | (c & a));				}

//	keying step, sets x0 as a function of 4 inputs
#define STEP_SHA256_K(x0, x1, x9, xe) { \
	x0 = x0 + x9;					\
	x0 = x0 + _rv_sha256sig0(x1);	\
	x0 = x0 + _rv_sha256sig1(xe);	}

void sha2_cf256_rvk(void *s)
{
	//	4.2.2 SHA-224 and SHA-256 Constants

	const uint32_t ck[64] = {
		0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
		0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
		0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
		0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
		0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
		0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
		0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
		0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
		0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
		0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
		0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
		0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
		0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
		0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
		0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
		0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
	};

	uint32_t a, b, c, d, e, f, g, h;
	uint32_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;

	uint32_t *sp = s;
	const uint32_t *mp = sp + 8;
	const uint32_t *kp = ck;

	a = sp[0];
	b = sp[1];
	c = sp[2];
	d = sp[3];
	e = sp[4];
	f = sp[5];
	g = sp[6];
	h = sp[7];

	//	load and reverse bytes
	
	m0 = _rv_grev(mp[0], 0x18);
	m1 = _rv_grev(mp[1], 0x18);
	m2 = _rv_grev(mp[2], 0x18);
	m3 = _rv_grev(mp[3], 0x18);
	m4 = _rv_grev(mp[4], 0x18);
	m5 = _rv_grev(mp[5], 0x18);
	m6 = _rv_grev(mp[6], 0x18);
	m7 = _rv_grev(mp[7], 0x18);
	m8 = _rv_grev(mp[8], 0x18);
	m9 = _rv_grev(mp[9], 0x18);
	ma = _rv_grev(mp[10], 0x18);
	mb = _rv_grev(mp[11], 0x18);
	mc = _rv_grev(mp[12], 0x18);
	md = _rv_grev(mp[13], 0x18);
	me = _rv_grev(mp[14], 0x18);
	mf = _rv_grev(mp[15], 0x18);

	while (1) {

		STEP_SHA256_R(a, b, c, d, e, f, g, h, m0, kp[0]);	//	rounds
		STEP_SHA256_R(h, a, b, c, d, e, f, g, m1, kp[1]);
		STEP_SHA256_R(g, h, a, b, c, d, e, f, m2, kp[2]);
		STEP_SHA256_R(f, g, h, a, b, c, d, e, m3, kp[3]);
		STEP_SHA256_R(e, f, g, h, a, b, c, d, m4, kp[4]);
		STEP_SHA256_R(d, e, f, g, h, a, b, c, m5, kp[5]);
		STEP_SHA256_R(c, d, e, f, g, h, a, b, m6, kp[6]);
		STEP_SHA256_R(b, c, d, e, f, g, h, a, m7, kp[7]);
		STEP_SHA256_R(a, b, c, d, e, f, g, h, m8, kp[8]);
		STEP_SHA256_R(h, a, b, c, d, e, f, g, m9, kp[9]);
		STEP_SHA256_R(g, h, a, b, c, d, e, f, ma, kp[10]);
		STEP_SHA256_R(f, g, h, a, b, c, d, e, mb, kp[11]);
		STEP_SHA256_R(e, f, g, h, a, b, c, d, mc, kp[12]);
		STEP_SHA256_R(d, e, f, g, h, a, b, c, md, kp[13]);
		STEP_SHA256_R(c, d, e, f, g, h, a, b, me, kp[14]);
		STEP_SHA256_R(b, c, d, e, f, g, h, a, mf, kp[15]);

		if (kp == &ck[64 - 16])
			break;
		kp += 16;

		STEP_SHA256_K(m0, m1, m9, me);	//	message schedule
		STEP_SHA256_K(m1, m2, ma, mf);
		STEP_SHA256_K(m2, m3, mb, m0);
		STEP_SHA256_K(m3, m4, mc, m1);
		STEP_SHA256_K(m4, m5, md, m2);
		STEP_SHA256_K(m5, m6, me, m3);
		STEP_SHA256_K(m6, m7, mf, m4);
		STEP_SHA256_K(m7, m8, m0, m5);
		STEP_SHA256_K(m8, m9, m1, m6);
		STEP_SHA256_K(m9, ma, m2, m7);
		STEP_SHA256_K(ma, mb, m3, m8);
		STEP_SHA256_K(mb, mc, m4, m9);
		STEP_SHA256_K(mc, md, m5, ma);
		STEP_SHA256_K(md, me, m6, mb);
		STEP_SHA256_K(me, mf, m7, mc);
		STEP_SHA256_K(mf, m0, m8, md);
	}

	sp[0] = sp[0] + a;
	sp[1] = sp[1] + b;
	sp[2] = sp[2] + c;
	sp[3] = sp[3] + d;
	sp[4] = sp[4] + e;
	sp[5] = sp[5] + f;
	sp[6] = sp[6] + g;
	sp[7] = sp[7] + h;
}
