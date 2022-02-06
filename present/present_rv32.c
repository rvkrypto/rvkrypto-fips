//	present_rv32.c
//	2021-11-03	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== RV32: Block Cipher PRESENT-80/128 (CHES 2007 / ISO/IEC 29192-2:2019).

#include "present_api.h"
#include "rv_endian.h"
#include "riscv_crypto.h"

#ifdef RVKINTRIN_RV32

//	S-Box (sLayer) 
#define SBOX64_ENC 0x21748FE3DA09B65CLLU
#define SBOX64_DEC 0xA970364BD21C8FE5LLU

//	Nybble shuffle for pLayer
#define P64_NYBBLE 0xFB73EA62D951C840LLU

//	Decompose a permutation into two for rv32

#define RV32_XPERM4_S64(p, x)             \
	(_rv32_xperm4((p) &0xFFFFFFFF, (x)) | \
	 _rv32_xperm4((p) >> 32, (x) ^ 0x88888888))

#define RV32_XPERM4_Q64(x0, x1, p) \
	(_rv32_xperm4((x0), (p)) | _rv32_xperm4((x1), (p) ^ 0x88888888))

//	---	TV32 block encrypt (PRESENT-80/128)

uint64_t present_enc_rv32(uint64_t x, const uint64_t rk[32])
{
	int i;
	uint32_t x0, x1, y0, y1, z0, z1;

	x0 = (uint32_t) x;
	x1 = (uint32_t) (x >> 32);

	for (i = 0; i < 31; i++) {

		//	key addition
		x0 ^= ((const uint32_t *) &rk[i])[0];
		x1 ^= ((const uint32_t *) &rk[i])[1];

		//	sLayer
		x0 = RV32_XPERM4_S64(SBOX64_ENC, x0);
		x1 = RV32_XPERM4_S64(SBOX64_ENC, x1);

		//	pLayer
		y0 = x0 & 0x11111111;
		y1 = x1 & 0x11111111;
		y0 |= y0 >> 6;
		y1 |= y1 >> 6;
		y0 |= y0 >> 3;
		y1 |= y1 >> 3;
		z0 = y0 & 0x000F000F;
		z1 = y1 & 0x000F000F;

		y0 = x0 & 0x22222222;
		y1 = x1 & 0x22222222;
		y0 |= y0 >> 6;
		y1 |= y1 >> 6;
		y0 |= y0 << 3;
		y1 |= y1 << 3;
		z0 |= y0 & 0x00F000F0;
		z1 |= y1 & 0x00F000F0;

		y0 = x0 & 0x44444444;
		y1 = x1 & 0x44444444;
		y0 |= y0 << 6;
		y1 |= y1 << 6;
		y0 |= y0 >> 3;
		y1 |= y1 >> 3;
		z0 |= y0 & 0x0F000F00;
		z1 |= y1 & 0x0F000F00;

		y0 = x0 & 0x88888888;
		y1 = x1 & 0x88888888;
		y0 |= y0 << 6;
		y1 |= y1 << 6;
		y0 |= y0 << 3;
		y1 |= y1 << 3;
		z0 |= y0 & 0xF000F000;
		z1 |= y1 & 0xF000F000;

		x0 = RV32_XPERM4_Q64(z0, z1, P64_NYBBLE & 0xFFFFFFFF);
		x1 = RV32_XPERM4_Q64(z0, z1, P64_NYBBLE >> 32);
	}
	x0 ^= ((const uint32_t *) &rk[i])[0];
	x1 ^= ((const uint32_t *) &rk[i])[1];

	x = ((uint64_t) x0) | (((uint64_t) x1) << 32);

	return x;
}

//	---	RV32 block decrypt (PRESENT-80/128)

uint64_t present_dec_rv32(uint64_t x, const uint64_t rk[32])
{
	int i;
	uint32_t x0, x1, y0, y1, z0, z1;

	x0 = (uint32_t) x;
	x1 = (uint32_t) (x >> 32);

	for (i = 31; i > 0; i--) {

		//	key addition
		x0 ^= ((const uint32_t *) &rk[i])[0];
		x1 ^= ((const uint32_t *) &rk[i])[1];

		//	inverse pLayer
		z0 = RV32_XPERM4_Q64(x0, x1, P64_NYBBLE & 0xFFFFFFFF);
		z1 = RV32_XPERM4_Q64(x0, x1, P64_NYBBLE >> 32);

		y0 = z0 & 0x000F000F;
		y1 = z1 & 0x000F000F;
		y0 |= y0 << 3;
		y1 |= y1 << 3;
		y0 |= y0 << 6;
		y1 |= y1 << 6;
		x0 = y0 & 0x11111111;
		x1 = y1 & 0x11111111;

		y0 = z0 & 0x00F000F0;
		y1 = z1 & 0x00F000F0;
		y0 |= y0 >> 3;
		y1 |= y1 >> 3;
		y0 |= y0 << 6;
		y1 |= y1 << 6;
		x0 |= y0 & 0x22222222;
		x1 |= y1 & 0x22222222;

		y0 = z0 & 0x0F000F00;
		y1 = z1 & 0x0F000F00;
		y0 |= y0 << 3;
		y1 |= y1 << 3;
		y0 |= y0 >> 6;
		y1 |= y1 >> 6;
		x0 |= y0 & 0x44444444;
		x1 |= y1 & 0x44444444;

		y0 = z0 & 0xF000F000;
		y1 = z1 & 0xF000F000;
		y0 |= y0 >> 3;
		y1 |= y1 >> 3;
		y0 |= y0 >> 6;
		y1 |= y1 >> 6;
		x0 |= y0 & 0x88888888;
		x1 |= y1 & 0x88888888;

		//	inverse sLayer
		x0 = RV32_XPERM4_S64(SBOX64_DEC, x0);
		x1 = RV32_XPERM4_S64(SBOX64_DEC, x1);
	}
	x0 ^= ((const uint32_t *) &rk[i])[0];
	x1 ^= ((const uint32_t *) &rk[i])[1];

	x = ((uint64_t) x0) | (((uint64_t) x1) << 32);

	return x;
}

#endif
