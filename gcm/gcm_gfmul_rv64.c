//	gcm_gfmul_rv64.c
//	2020-03-23	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	64-bit GHASH bit-reverse and multiplication for GCM

#include "riscv_crypto.h"

#ifdef RVKINTRIN_RV64

#include "gcm_gfmul.h"

//	disable shift reduction
//#define NO_SHIFTRED
//	disable karatsuba multiplication
//#define NO_KARATSUBA

//	reverse bits in bytes of a 128-bit block; do this for h and final value

void ghash_rev_rv64(gf128_t * z)
{
	z->d[0] = _rv64_brev8(z->d[0]);
	z->d[1] = _rv64_brev8(z->d[1]);
}

//	multiply z = ( z ^ rev(x) ) * h

void ghash_mul_rv64(gf128_t * z, const gf128_t * x, const gf128_t * h)
{
	uint64_t x0, x1, y0, y1;
	uint64_t z0, z1, z2, z3, t0, t1, t2;

	x0 = x->d[0];							//	new input
	x1 = x->d[1];

	z0 = z->d[0];							//	inline to avoid these loads
	z1 = z->d[1];

	y0 = h->d[0];							//	h value already reversed
	y1 = h->d[1];

	//	2 x GREVW, 2 x XOR
	x0 = _rv64_brev8(x0);					//	reverse input x only
	x1 = _rv64_brev8(x1);
	x0 = x0 ^ z0;							//	z is updated
	x1 = x1 ^ z1;

#ifdef NO_KARATSUBA

	(void) t2;								//	unused

	//	Without Karatsuba; 4 x CLMULH, 4 x CLMUL, 4 x XOR
	z3 = _rv64_clmulh(x1, y1);
	z2 = _rv64_clmul(x1, y1);
	t1 = _rv64_clmulh(x0, y1);
	z1 = _rv64_clmul(x0, y1);
	z2 = z2 ^ t1;
	t1 = _rv64_clmulh(x1, y0);
	t0 = _rv64_clmul(x1, y0);
	z2 = z2 ^ t1;
	z1 = z1 ^ t0;
	t1 = _rv64_clmulh(x0, y0);
	z0 = _rv64_clmul(x0, y0);
	z1 = z1 ^ t1;

#else

	//	With Karatsuba; 3 x CLMULH, 3 x CLMUL, 8 x XOR
	z3 = _rv64_clmulh(x1, y1);
	z2 = _rv64_clmul(x1, y1);
	z1 = _rv64_clmulh(x0, y0);
	z0 = _rv64_clmul(x0, y0);
	t0 = x0 ^ x1;
	t2 = y0 ^ y1;
	t1 = _rv64_clmulh(t0, t2);
	t0 = _rv64_clmul(t0, t2);
	t1 = t1 ^ z1 ^ z3;
	t0 = t0 ^ z0 ^ z2;
	z2 = z2 ^ t1;
	z1 = z1 ^ t0;

#endif

#ifdef NO_SHIFTRED

	//	Mul reduction: 2 x CLMULH, 2 x CLMUL, 4 x XOR
	t1 = _rv64_clmulh(z3, 0x87);
	t0 = _rv64_clmul(z3, 0x87);
	z2 = z2 ^ t1;
	z1 = z1 ^ t0;
	t1 = _rv64_clmulh(z2, 0x87);
	t0 = _rv64_clmul(z2, 0x87);
	z1 = z1 ^ t1;
	z0 = z0 ^ t0;

#else

	//	Shift reduction: 12 x SHIFT, 14 x XOR
	z2 = z2 ^ (z3 >> 63) ^ (z3 >> 62) ^ (z3 >> 57);
	z1 = z1 ^ z3 ^ (z3 << 1) ^ (z3 << 2) ^ (z3 << 7) ^
		(z2 >> 63) ^ (z2 >> 62) ^ (z2 >> 57);
	z0 = z0 ^ z2 ^ (z2 << 1) ^ (z2 << 2) ^ (z2 << 7);

#endif

	z->d[0] = z0;							//	inline to avoid these stores
	z->d[1] = z1;
}

#endif	//	RVKINTRIN_RV64

