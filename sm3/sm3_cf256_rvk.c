//	sm3_rv32_cf.c
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	===	The Chinese Standard SM3 Hash -- Compression Function
//	GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018

#include "riscv_crypto.h"
#include "sm3_api.h"

//	key schedule

#define STEP_SM3_KEY(w0, w3, w7, wa, wd) {	\
	t = w0 ^ w7 ^ _rv32_ror(wd, 17);		\
	t = _rv_sm3p1(t);						\
	w0 = wa ^ _rv32_ror(w3, 25) ^ t;	}

//	rounds 0..15

#define STEP_SM3_RF0(a, b, c, d, e, f, g, h, w0, w4) {	\
	h = h + w0;										\
	t = _rv32_ror(a, 20);							\
	u = t + e + tj;									\
	u = _rv32_ror(u, 25);							\
	d = d + (t ^ u) + (a ^ b ^ c);					\
	b = _rv32_ror(b, 23);							\
	h = h + u + (e ^ f ^ g);						\
	h = _rv_sm3p0(h);								\
	f = _rv32_ror(f, 13);							\
	d = d + (w0 ^ w4);								\
	tj = _rv32_ror(tj, 31);	}

//	rounds 16..63

#define STEP_SM3_RF1(a, b, c, d, e, f, g, h, w0, w4) {	\
	h = h + w0;										\
	t = _rv32_ror(a, 20);							\
	u = t + e + tj;									\
	u = _rv32_ror(u, 25);							\
	d = d + (t ^ u) + (((a | c) & b) | (a & c));	\
	b = _rv32_ror(b, 23);							\
	h = h + u + ((e & f) ^ (g &~ e));				\
	h = _rv_sm3p0(h);								\
	f = _rv32_ror(f, 13);							\
	d = d + (w0 ^ w4);								\
	tj = _rv32_ror(tj, 31);	}


//	compression function (this one does *not* modify mp[])

void sm3_cf256_rvk(void *s)
{
	int i;
	uint32_t a, b, c, d, e, f, g, h;
	uint32_t m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, ma, mb, mc, md, me, mf;
	uint32_t tj, t, u;

	uint32_t *sp = s;
	const uint32_t *mp = sp + 8;

	a = sp[0];
	b = sp[1];
	c = sp[2];
	d = sp[3];
	e = sp[4];
	f = sp[5];
	g = sp[6];
	h = sp[7];

	//	load and reverse bytes

	m0 = __builtin_bswap32(mp[0]);
	m1 = __builtin_bswap32(mp[1]);
	m2 = __builtin_bswap32(mp[2]);
	m3 = __builtin_bswap32(mp[3]);
	m4 = __builtin_bswap32(mp[4]);
	m5 = __builtin_bswap32(mp[5]);
	m6 = __builtin_bswap32(mp[6]);
	m7 = __builtin_bswap32(mp[7]);
	m8 = __builtin_bswap32(mp[8]);
	m9 = __builtin_bswap32(mp[9]);
	ma = __builtin_bswap32(mp[10]);
	mb = __builtin_bswap32(mp[11]);
	mc = __builtin_bswap32(mp[12]);
	md = __builtin_bswap32(mp[13]);
	me = __builtin_bswap32(mp[14]);
	mf = __builtin_bswap32(mp[15]);
	
	tj = 0x79CC4519;

	STEP_SM3_RF0(a, b, c, d, e, f, g, h, m0, m4);
	STEP_SM3_RF0(d, a, b, c, h, e, f, g, m1, m5);
	STEP_SM3_RF0(c, d, a, b, g, h, e, f, m2, m6);
	STEP_SM3_RF0(b, c, d, a, f, g, h, e, m3, m7);

	STEP_SM3_RF0(a, b, c, d, e, f, g, h, m4, m8);
	STEP_SM3_RF0(d, a, b, c, h, e, f, g, m5, m9);
	STEP_SM3_RF0(c, d, a, b, g, h, e, f, m6, ma);
	STEP_SM3_RF0(b, c, d, a, f, g, h, e, m7, mb);

	STEP_SM3_RF0(a, b, c, d, e, f, g, h, m8, mc);
	STEP_SM3_RF0(d, a, b, c, h, e, f, g, m9, md);
	STEP_SM3_RF0(c, d, a, b, g, h, e, f, ma, me);
	STEP_SM3_RF0(b, c, d, a, f, g, h, e, mb, mf);

	STEP_SM3_KEY(m0, m3, m7, ma, md);
	STEP_SM3_KEY(m1, m4, m8, mb, me);
	STEP_SM3_KEY(m2, m5, m9, mc, mf);
	STEP_SM3_KEY(m3, m6, ma, md, m0);

	STEP_SM3_RF0(a, b, c, d, e, f, g, h, mc, m0);
	STEP_SM3_RF0(d, a, b, c, h, e, f, g, md, m1);
	STEP_SM3_RF0(c, d, a, b, g, h, e, f, me, m2);
	STEP_SM3_RF0(b, c, d, a, f, g, h, e, mf, m3);

	tj = 0x9D8A7A87;

	for (i = 0; i < 3; i++) {

		STEP_SM3_KEY(m4, m7, mb, me, m1);
		STEP_SM3_KEY(m5, m8, mc, mf, m2);
		STEP_SM3_KEY(m6, m9, md, m0, m3);
		STEP_SM3_KEY(m7, ma, me, m1, m4);
		STEP_SM3_KEY(m8, mb, mf, m2, m5);
		STEP_SM3_KEY(m9, mc, m0, m3, m6);
		STEP_SM3_KEY(ma, md, m1, m4, m7);
		STEP_SM3_KEY(mb, me, m2, m5, m8);
		STEP_SM3_KEY(mc, mf, m3, m6, m9);
		STEP_SM3_KEY(md, m0, m4, m7, ma);
		STEP_SM3_KEY(me, m1, m5, m8, mb);
		STEP_SM3_KEY(mf, m2, m6, m9, mc);

		STEP_SM3_RF1(a, b, c, d, e, f, g, h, m0, m4);
		STEP_SM3_RF1(d, a, b, c, h, e, f, g, m1, m5);
		STEP_SM3_RF1(c, d, a, b, g, h, e, f, m2, m6);
		STEP_SM3_RF1(b, c, d, a, f, g, h, e, m3, m7);

		STEP_SM3_RF1(a, b, c, d, e, f, g, h, m4, m8);
		STEP_SM3_RF1(d, a, b, c, h, e, f, g, m5, m9);
		STEP_SM3_RF1(c, d, a, b, g, h, e, f, m6, ma);
		STEP_SM3_RF1(b, c, d, a, f, g, h, e, m7, mb);

		STEP_SM3_RF1(a, b, c, d, e, f, g, h, m8, mc);
		STEP_SM3_RF1(d, a, b, c, h, e, f, g, m9, md);
		STEP_SM3_RF1(c, d, a, b, g, h, e, f, ma, me);
		STEP_SM3_RF1(b, c, d, a, f, g, h, e, mb, mf);

		STEP_SM3_KEY(m0, m3, m7, ma, md);
		STEP_SM3_KEY(m1, m4, m8, mb, me);
		STEP_SM3_KEY(m2, m5, m9, mc, mf);
		STEP_SM3_KEY(m3, m6, ma, md, m0);

		STEP_SM3_RF1(a, b, c, d, e, f, g, h, mc, m0);
		STEP_SM3_RF1(d, a, b, c, h, e, f, g, md, m1);
		STEP_SM3_RF1(c, d, a, b, g, h, e, f, me, m2);
		STEP_SM3_RF1(b, c, d, a, f, g, h, e, mf, m3);

	}

	sp[0] = sp[0] ^ a;
	sp[1] = sp[1] ^ b;
	sp[2] = sp[2] ^ c;
	sp[3] = sp[3] ^ d;
	sp[4] = sp[4] ^ e;
	sp[5] = sp[5] ^ f;
	sp[6] = sp[6] ^ g;
	sp[7] = sp[7] ^ h;
}
