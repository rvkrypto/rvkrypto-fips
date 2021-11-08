//	rvk_emu_intrin.h
//	2021-02-13	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Platform-independent emulation for scalar cryptography intrinsics.
//	Requires tables in rvk_emu_intrin.c (prefix _rvk_emu)

#ifndef _RVK_EMU_INTRIN_H
#define _RVK_EMU_INTRIN_H

#ifdef RVKINTRIN_EMULATE

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stdint.h>

//	=== RVKINTRIN_EMULATE ==============================================

#if UINT_MAX != 0xffffffffU
#  error "<rvk_emu_intrin.h> supports systems with sizeof(int) = 4."
#endif

#if (ULLONG_MAX == 0xffffffffLLU) || (ULLONG_MAX != 0xffffffffffffffffLLU)
#  error "<rvk_emu_intrin.h> supports systems with sizeof(long long) = 8."
#endif

#if !defined(RVKINTRIN_RV32) && !defined(RVKINTRIN_RV64)
#if UINT_MAX == ULONG_MAX
#  define RVKINTRIN_RV32
#else
#  define RVKINTRIN_RV64
#endif
#endif

//	=== (emulated)	Zbkb:	Bitmanipulation instructions for Cryptography

//	shift helpers (that mask/limit the amount of shift)

static inline int32_t _rvk_emu_sll_32(int32_t rs1, int32_t rs2)
	{ return rs1 << (rs2 & 31); }
static inline int32_t _rvk_emu_srl_32(int32_t rs1, int32_t rs2)
	{ return (uint32_t)rs1 >> (rs2 & 31); }
static inline int64_t _rvk_emu_sll_64(int64_t rs1, int64_t rs2)
	{ return rs1 << (rs2 & 63); }
static inline int64_t _rvk_emu_srl_64(int64_t rs1, int64_t rs2)
	{ return (uint64_t)rs1 >> (rs2 & 63); }

//	rotate (a part of the extension). no separate intrinsic for rori

static inline int32_t _rvk_emu_rol_32(int32_t rs1, int32_t rs2)
	{ return _rvk_emu_sll_32(rs1, rs2) | _rvk_emu_srl_32(rs1, -rs2); }
static inline int32_t _rvk_emu_ror_32(int32_t rs1, int32_t rs2)
	{ return _rvk_emu_srl_32(rs1, rs2) | _rvk_emu_sll_32(rs1, -rs2); }

static inline int64_t _rvk_emu_rol_64(int64_t rs1, int64_t rs2)
	{ return _rvk_emu_sll_64(rs1, rs2) | _rvk_emu_srl_64(rs1, -rs2); }
static inline int64_t _rvk_emu_ror_64(int64_t rs1, int64_t rs2)
	{ return _rvk_emu_srl_64(rs1, rs2) | _rvk_emu_sll_64(rs1, -rs2); }

//	additional logic

static inline long _rvk_emu_andn(long rs1, long rs2)
	{ return rs1 & ~rs2; }
static inline long _rvk_emu_orn(long rs1, long rs2)
	{ return rs1 | ~rs2; }
static inline long _rvk_emu_xnor(long rs1, long rs2)
	{ return rs1 ^ ~rs2; }

//	pack, packh

static inline int32_t _rvk_emu_pack_32(int32_t rs1, int32_t rs2)
	{ return (rs1 & 0x0000ffff) | (rs2 << 16); }
static inline int64_t _rvk_emu_pack_64(int64_t rs1, int64_t rs2)
	{ return (rs1 & 0xffffffffLL) | (rs2 << 32); }

static inline int32_t _rvk_emu_packh_32(int32_t rs1, int32_t rs2)
	{ return (rs1 & 0xff) | ((rs2 & 0xff) << 8); }
static inline int64_t _rvk_emu_packh_64(int64_t rs1, int64_t rs2)
	{ return (rs1 & 0xff) | ((rs2 & 0xff) << 8); }

//	brev8, rev8

static inline int32_t _rvk_emu_grev_32(int32_t rs1, int32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 31;
	if (shamt &	 1) x = ((x & 0x55555555) <<  1) | ((x & 0xAAAAAAAA) >>	 1);
	if (shamt &	 2) x = ((x & 0x33333333) <<  2) | ((x & 0xCCCCCCCC) >>	 2);
	if (shamt &	 4) x = ((x & 0x0F0F0F0F) <<  4) | ((x & 0xF0F0F0F0) >>	 4);
	if (shamt &	 8) x = ((x & 0x00FF00FF) <<  8) | ((x & 0xFF00FF00) >>	 8);
	if (shamt & 16) x = ((x & 0x0000FFFF) << 16) | ((x & 0xFFFF0000) >> 16);
	return x;
}

static inline int64_t _rvk_emu_grev_64(int64_t rs1, int64_t rs2)
{
	uint64_t x = rs1;
	int shamt = rs2 & 63;
	if (shamt &	 1)
		x = ((x & 0x5555555555555555LL) <<	1) |
			((x & 0xAAAAAAAAAAAAAAAALL) >>	1);
	if (shamt &	 2)
		x = ((x & 0x3333333333333333LL) <<	2) |
			((x & 0xCCCCCCCCCCCCCCCCLL) >>	2);
	if (shamt &	 4)
		x = ((x & 0x0F0F0F0F0F0F0F0FLL) <<	4) |
			((x & 0xF0F0F0F0F0F0F0F0LL) >>	4);
	if (shamt &	 8)
		x = ((x & 0x00FF00FF00FF00FFLL) <<	8) |
			((x & 0xFF00FF00FF00FF00LL) >>	8);
	if (shamt & 16)
		x = ((x & 0x0000FFFF0000FFFFLL) << 16) |
			((x & 0xFFFF0000FFFF0000LL) >> 16);
	if (shamt & 32)
		x = ((x & 0x00000000FFFFFFFFLL) << 32) |
			((x & 0xFFFFFFFF00000000LL) >> 32);
	return x;
}

static inline int32_t _rvk_emu_brev8_32(int32_t rs1)
	{ return _rvk_emu_grev_32(rs1, 7); }
static inline int32_t _rvk_emu_rev8_32(int32_t rs1)
	{ return _rvk_emu_grev_32(rs1, 24); }

static inline int64_t _rvk_emu_brev8_64(int64_t rs1)
	{ return _rvk_emu_grev_64(rs1, 7); }
static inline int64_t _rvk_emu_rev8_64(int64_t rs1)
	{ return _rvk_emu_grev_64(rs1, 56); }

//	shuffle (zip and unzip, RV32 only)

static inline uint32_t _rvk_emu_shuffle32_stage(uint32_t src, uint32_t maskL, uint32_t maskR, int N)
{
	uint32_t x = src & ~(maskL | maskR);
	x |= ((src <<  N) & maskL) | ((src >>  N) & maskR);
	return x;
}
static inline int32_t _rvk_emu_shfl_32(int32_t rs1, int32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 8) x = _rvk_emu_shuffle32_stage(x, 0x00ff0000, 0x0000ff00, 8);
	if (shamt & 4) x = _rvk_emu_shuffle32_stage(x, 0x0f000f00, 0x00f000f0, 4);
	if (shamt & 2) x = _rvk_emu_shuffle32_stage(x, 0x30303030, 0x0c0c0c0c, 2);
	if (shamt & 1) x = _rvk_emu_shuffle32_stage(x, 0x44444444, 0x22222222, 1);

	return x;
}

static inline int32_t _rvk_emu_unshfl_32(int32_t rs1, int32_t rs2)
{
	uint32_t x = rs1;
	int shamt = rs2 & 15;

	if (shamt & 1) x = _rvk_emu_shuffle32_stage(x, 0x44444444, 0x22222222, 1);
	if (shamt & 2) x = _rvk_emu_shuffle32_stage(x, 0x30303030, 0x0c0c0c0c, 2);
	if (shamt & 4) x = _rvk_emu_shuffle32_stage(x, 0x0f000f00, 0x00f000f0, 4);
	if (shamt & 8) x = _rvk_emu_shuffle32_stage(x, 0x00ff0000, 0x0000ff00, 8);

	return x;
}

static inline int32_t _rvk_emu_zip_32(int32_t rs1)
	{ return _rvk_emu_shfl_32(rs1, 15); }
static inline int32_t _rvk_emu_unzip_32(int32_t rs1)
	{ return _rvk_emu_unshfl_32(rs1, 15); }

//	=== (emulated)	Zbkc: Carry-less multiply instructions

static inline int32_t _rvk_emu_clmul_32(int32_t rs1, int32_t rs2)
{
	uint32_t a = rs1, b = rs2, x = 0;
	for (int i = 0; i < 32; i++) {
		if ((b >> i) & 1)
			x ^= a << i;
	}
	return x;
}

static inline int32_t _rvk_emu_clmulh_32(int32_t rs1, int32_t rs2)
{
	uint32_t a = rs1, b = rs2, x = 0;
	for (int i = 1; i < 32; i++) {
		if ((b >> i) & 1)
			x ^= a >> (32-i);
	}
	return x;
}

static inline int64_t _rvk_emu_clmul_64(int64_t rs1, int64_t rs2)
{
	uint64_t a = rs1, b = rs2, x = 0;

	for (int i = 0; i < 64; i++) {
		if ((b >> i) & 1)
			x ^= a << i;
	}
	return x;
}

static inline int64_t _rvk_emu_clmulh_64(int64_t rs1, int64_t rs2)
{
	uint64_t a = rs1, b = rs2, x = 0;

	for (int i = 1; i < 64; i++) {
		if ((b >> i) & 1)
			x ^= a >> (64-i);
	}
	return x;
}

//	=== (emulated)	Zbkx: Crossbar permutation instructions

static inline uint32_t _rvk_emu_xperm32(uint32_t rs1, uint32_t rs2, int sz_log2)
{
	uint32_t r = 0;
	uint32_t sz = 1LL << sz_log2;
	uint32_t mask = (1LL << sz) - 1;
	for (int i = 0; i < 32; i += sz) {
		uint32_t pos = ((rs2 >> i) & mask) << sz_log2;
		if (pos < 32)
			r |= ((rs1 >> pos) & mask) << i;
	}
	return r;
}

static inline int32_t _rvk_emu_xperm4_32(int32_t rs1, int32_t rs2)
	{ return _rvk_emu_xperm32(rs1, rs2, 2); }

static inline int32_t _rvk_emu_xperm8_32(int32_t rs1, int32_t rs2)
	{ return _rvk_emu_xperm32(rs1, rs2, 3); }

static inline uint64_t _rvk_emu_xperm64(uint64_t rs1, uint64_t rs2, int sz_log2)
{
	uint64_t r = 0;
	uint64_t sz = 1LL << sz_log2;
	uint64_t mask = (1LL << sz) - 1;
	for (int i = 0; i < 64; i += sz) {
		uint64_t pos = ((rs2 >> i) & mask) << sz_log2;
		if (pos < 64)
			r |= ((rs1 >> pos) & mask) << i;
	}
	return r;
}

static inline int64_t _rvk_emu_xperm4_64(int64_t rs1, int64_t rs2)
	{ return _rvk_emu_xperm64(rs1, rs2, 2); }

static inline int64_t _rvk_emu_xperm8_64(int64_t rs1, int64_t rs2)
	{ return _rvk_emu_xperm64(rs1, rs2, 3); }

/*
 *	_rvk_emu_*(...)
 *	  Some INTERNAL tables (rvk_emu.c) and functions.
 */

extern const uint8_t _rvk_emu_aes_fwd_sbox[256];	//	AES Forward S-Box
extern const uint8_t _rvk_emu_aes_inv_sbox[256];	//	AES Inverse S-Box
extern const uint8_t _rvk_emu_sm4_sbox[256];		//	SM4 S-Box

//	rvk_emu internal: multiply by 0x02 in AES's GF(256) - LFSR style.

static inline uint8_t _rvk_emu_aes_xtime(uint8_t x)
{
	return (x << 1) ^ ((x & 0x80) ? 0x11B : 0x00);
}

//	rvk_emu internal: AES forward MixColumns 8->32 bits

static inline uint32_t _rvk_emu_aes_fwd_mc_8(uint32_t x)
{
	uint32_t x2;

	x2 = _rvk_emu_aes_xtime(x);				//	double x
	x = ((x ^ x2) << 24) |					//	0x03	MixCol MDS Matrix
		(x << 16) |							//	0x01
		(x << 8) |							//	0x01
		x2;									//	0x02

	return x;
}

//	rvk_emu internal: AES forward MixColumns 32->32 bits

static inline uint32_t _rvk_emu_aes_fwd_mc_32(uint32_t x)
{
	return	_rvk_emu_aes_fwd_mc_8(x & 0xFF) ^
		_rvk_emu_rol_32(_rvk_emu_aes_fwd_mc_8((x >>	 8) & 0xFF),	8) ^
		_rvk_emu_rol_32(_rvk_emu_aes_fwd_mc_8((x >> 16) & 0xFF), 16) ^
		_rvk_emu_rol_32(_rvk_emu_aes_fwd_mc_8((x >> 24) & 0xFF), 24);
}

//	rvk_emu internal: AES inverse MixColumns 8->32 bits

static inline uint32_t _rvk_emu_aes_inv_mc_8(uint32_t x)
{
	uint32_t x2, x4, x8;

	x2 = _rvk_emu_aes_xtime(x);				//	double x
	x4 = _rvk_emu_aes_xtime(x2);			//	double to 4*x
	x8 = _rvk_emu_aes_xtime(x4);			//	double to 8*x

	x = ((x ^ x2 ^ x8) << 24) |				//	0x0B	Inv MixCol MDS Matrix
		((x ^ x4 ^ x8) << 16) |				//	0x0D
		((x ^ x8) << 8) |					//	0x09
		(x2 ^ x4 ^ x8);						//	0x0E

	return x;
}

//	rvk_emu internal: AES inverse MixColumns 32->32 bits

static inline uint32_t _rvk_emu_aes_inv_mc_32(uint32_t x)
{
	return	_rvk_emu_aes_inv_mc_8(x & 0xFF) ^
		_rvk_emu_rol_32(_rvk_emu_aes_inv_mc_8((x >>	 8) & 0xFF),	8) ^
		_rvk_emu_rol_32(_rvk_emu_aes_inv_mc_8((x >> 16) & 0xFF), 16) ^
		_rvk_emu_rol_32(_rvk_emu_aes_inv_mc_8((x >> 24) & 0xFF), 24);
}

//	=== (emulated)	Zknd:	NIST Suite: AES Decryption

static inline int32_t _rvk_emu_aes32dsi(int32_t rs1, int32_t rs2, uint8_t bs)
{
	int32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_inv_sbox[x];			//	AES inverse s-box

	return rs1 ^ _rvk_emu_rol_32(x, bs);
}

static inline int32_t _rvk_emu_aes32dsmi(int32_t rs1, int32_t rs2, uint8_t bs)
{
	int32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_inv_sbox[x];			//	AES inverse s-box
	x = _rvk_emu_aes_inv_mc_8(x);			//	inverse MixColumns

	return rs1 ^ _rvk_emu_rol_32(x, bs);
}

static inline int64_t _rvk_emu_aes64ds(int64_t rs1, int64_t rs2)
{
	//	Half of inverse ShiftRows and SubBytes (last round)
	return ((int64_t) _rvk_emu_aes_inv_sbox[rs1 & 0xFF]) |
		(((int64_t) _rvk_emu_aes_inv_sbox[(rs2 >> 40) & 0xFF]) <<  8) |
		(((int64_t) _rvk_emu_aes_inv_sbox[(rs2 >> 16) & 0xFF]) << 16) |
		(((int64_t) _rvk_emu_aes_inv_sbox[(rs1 >> 56) & 0xFF]) << 24) |
		(((int64_t) _rvk_emu_aes_inv_sbox[(rs1 >> 32) & 0xFF]) << 32) |
		(((int64_t) _rvk_emu_aes_inv_sbox[(rs1 >>  8) & 0xFF]) << 40) |
		(((int64_t) _rvk_emu_aes_inv_sbox[(rs2 >> 48) & 0xFF]) << 48) |
		(((int64_t) _rvk_emu_aes_inv_sbox[(rs2 >> 24) & 0xFF]) << 56);
}

static inline int64_t _rvk_emu_aes64im(int64_t rs1)
{
	return ((int64_t) _rvk_emu_aes_inv_mc_32(rs1)) |
		(((int64_t) _rvk_emu_aes_inv_mc_32(rs1 >> 32)) << 32);
}

static inline int64_t _rvk_emu_aes64dsm(int64_t rs1, int64_t rs2)
{
	int64_t x;

	x = _rvk_emu_aes64ds(rs1, rs2);			//	Inverse ShiftRows, SubBytes
	x = _rvk_emu_aes64im(x);					//	Inverse MixColumns
	return x;
}

static inline int64_t _rvk_emu_aes64ks1i(int64_t rs1, int rnum)
{
	//	AES Round Constants
	const uint8_t aes_rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
	};

	uint32_t t, rc;

	t = rs1 >> 32;							//	high word
	rc = 0;

	if (rnum < 10) {						//	10: don't do it
		t = _rvk_emu_ror_32(t, 8);
		rc = aes_rcon[rnum];				//	round constant
	}
	//	SubWord
	t = ((uint32_t) _rvk_emu_aes_fwd_sbox[t & 0xFF]) |
		(((uint32_t) _rvk_emu_aes_fwd_sbox[(t >> 8) & 0xFF]) << 8) |
		(((uint32_t) _rvk_emu_aes_fwd_sbox[(t >> 16) & 0xFF]) << 16) |
		(((uint32_t) _rvk_emu_aes_fwd_sbox[(t >> 24) & 0xFF]) << 24);

	t ^= rc;

	return ((int64_t) t) | (((int64_t) t) << 32);
}

static inline int64_t _rvk_emu_aes64ks2(int64_t rs1, int64_t rs2)
{
	uint32_t t;

	t = (rs1 >> 32) ^ (rs2 & 0xFFFFFFFF);	//	wrap 32 bits

	return ((int64_t) t) ^					//	low 32 bits
		(((int64_t) t) << 32) ^ (rs2 & 0xFFFFFFFF00000000ULL);
}

//	=== (emulated)	Zkne:	NIST Suite: AES Encryption

static inline int32_t _rvk_emu_aes32esi(int32_t rs1, int32_t rs2, uint8_t bs)
{
	int32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_fwd_sbox[x];			//	AES forward s-box

	return rs1 ^ _rvk_emu_rol_32(x, bs);
}

static inline int32_t _rvk_emu_aes32esmi(int32_t rs1, int32_t rs2, uint8_t bs)
{
	uint32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_fwd_sbox[x];			//	AES forward s-box
	x = _rvk_emu_aes_fwd_mc_8(x);			//	forward MixColumns

	return rs1 ^ _rvk_emu_rol_32(x, bs);
}

static inline int64_t _rvk_emu_aes64es(int64_t rs1, int64_t rs2)
{
	//	Half of forward ShiftRows and SubBytes (last round)
	return ((int64_t) _rvk_emu_aes_fwd_sbox[rs1 & 0xFF]) |
		(((int64_t) _rvk_emu_aes_fwd_sbox[(rs1 >> 40) & 0xFF]) <<  8) |
		(((int64_t) _rvk_emu_aes_fwd_sbox[(rs2 >> 16) & 0xFF]) << 16) |
		(((int64_t) _rvk_emu_aes_fwd_sbox[(rs2 >> 56) & 0xFF]) << 24) |
		(((int64_t) _rvk_emu_aes_fwd_sbox[(rs1 >> 32) & 0xFF]) << 32) |
		(((int64_t) _rvk_emu_aes_fwd_sbox[(rs2 >>  8) & 0xFF]) << 40) |
		(((int64_t) _rvk_emu_aes_fwd_sbox[(rs2 >> 48) & 0xFF]) << 48) |
		(((int64_t) _rvk_emu_aes_fwd_sbox[(rs1 >> 24) & 0xFF]) << 56);
}

static inline int64_t _rvk_emu_aes64esm(int64_t rs1, int64_t rs2)
{
	int64_t x;

	x = _rvk_emu_aes64es(rs1, rs2);			//	ShiftRows and SubBytes
	x = ((int64_t) _rvk_emu_aes_fwd_mc_32(x)) |		//	MixColumns
		(((int64_t) _rvk_emu_aes_fwd_mc_32(x >> 32)) << 32);
	return x;
}

//	=== (emulated)	Zknh:	NIST Suite: Hash Function Instructions

static inline long _rvk_emu_sha256sig0(long rs1)
{
	int32_t x;

	x = _rvk_emu_ror_32(rs1, 7) ^ _rvk_emu_ror_32(rs1, 18) ^
		_rvk_emu_srl_32(rs1, 3);
	return (long) x;
}

static inline long _rvk_emu_sha256sig1(long rs1)
{
	int32_t x;

	x = _rvk_emu_ror_32(rs1, 17) ^ _rvk_emu_ror_32(rs1, 19) ^
		_rvk_emu_srl_32(rs1, 10);
	return (long) x;
}

static inline long _rvk_emu_sha256sum0(long rs1)
{
	int32_t x;

	x = _rvk_emu_ror_32(rs1, 2) ^ _rvk_emu_ror_32(rs1, 13) ^
		_rvk_emu_ror_32(rs1, 22);
	return (long) x;
}

static inline long _rvk_emu_sha256sum1(long rs1)
{
	int32_t x;

	x = _rvk_emu_ror_32(rs1, 6) ^ _rvk_emu_ror_32(rs1, 11) ^
		_rvk_emu_ror_32(rs1, 25);
	return (long) x;
}

static inline int32_t  _rvk_emu_sha512sig0h(int32_t rs1, int32_t rs2)
{
	return	_rvk_emu_srl_32(rs1, 1) ^ _rvk_emu_srl_32(rs1, 7) ^
			_rvk_emu_srl_32(rs1, 8) ^ _rvk_emu_sll_32(rs2, 31) ^
			_rvk_emu_sll_32(rs2, 24);
}

static inline int32_t  _rvk_emu_sha512sig0l(int32_t rs1, int32_t rs2)
{
	return	_rvk_emu_srl_32(rs1, 1) ^ _rvk_emu_srl_32(rs1, 7) ^
			_rvk_emu_srl_32(rs1, 8) ^ _rvk_emu_sll_32(rs2, 31) ^
			_rvk_emu_sll_32(rs2, 25) ^ _rvk_emu_sll_32(rs2, 24);
}

static inline int32_t  _rvk_emu_sha512sig1h(int32_t rs1, int32_t rs2)
{
	return	_rvk_emu_sll_32(rs1, 3) ^ _rvk_emu_srl_32(rs1, 6) ^
			_rvk_emu_srl_32(rs1, 19) ^ _rvk_emu_srl_32(rs2, 29) ^
			_rvk_emu_sll_32(rs2, 13);
}

static inline int32_t  _rvk_emu_sha512sig1l(int32_t rs1, int32_t rs2)
{
	return	_rvk_emu_sll_32(rs1, 3) ^ _rvk_emu_srl_32(rs1, 6) ^
			_rvk_emu_srl_32(rs1,19) ^ _rvk_emu_srl_32(rs2, 29) ^
			_rvk_emu_sll_32(rs2, 26) ^ _rvk_emu_sll_32(rs2, 13);
}

static inline int32_t  _rvk_emu_sha512sum0r(int32_t rs1, int32_t rs2)
{
	return	_rvk_emu_sll_32(rs1, 25) ^ _rvk_emu_sll_32(rs1, 30) ^
			_rvk_emu_srl_32(rs1, 28) ^ _rvk_emu_srl_32(rs2, 7) ^
			_rvk_emu_srl_32(rs2, 2) ^ _rvk_emu_sll_32(rs2, 4);
}

static inline int32_t  _rvk_emu_sha512sum1r(int32_t rs1, int32_t rs2)
{
	return	_rvk_emu_sll_32(rs1, 23) ^ _rvk_emu_srl_32(rs1,14) ^
			_rvk_emu_srl_32(rs1, 18) ^ _rvk_emu_srl_32(rs2, 9) ^
			_rvk_emu_sll_32(rs2, 18) ^ _rvk_emu_sll_32(rs2, 14);
}

static inline int64_t  _rvk_emu_sha512sig0(int64_t rs1)
{
	return	_rvk_emu_ror_64(rs1, 1) ^ _rvk_emu_ror_64(rs1, 8) ^
			_rvk_emu_srl_64(rs1,7);
}

static inline int64_t  _rvk_emu_sha512sig1(int64_t rs1)
{
	return	_rvk_emu_ror_64(rs1, 19) ^ _rvk_emu_ror_64(rs1, 61) ^
			_rvk_emu_srl_64(rs1, 6);
}

static inline int64_t  _rvk_emu_sha512sum0(int64_t rs1)
{
	return	_rvk_emu_ror_64(rs1, 28) ^ _rvk_emu_ror_64(rs1, 34) ^
			_rvk_emu_ror_64(rs1, 39);
}

static inline int64_t  _rvk_emu_sha512sum1(int64_t rs1)
{
	return	_rvk_emu_ror_64(rs1, 14) ^ _rvk_emu_ror_64(rs1, 18) ^
			_rvk_emu_ror_64(rs1, 41);
}

//	=== (emulated)	Zksed:	ShangMi Suite: SM4 Block Cipher Instructions

static inline long _rvk_emu_sm4ed(long rs1, long rs2, uint8_t bs)
{
	int32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_sm4_sbox[x];				//	SM4 s-box

	//	SM4 linear transform L
	x = x ^ (x << 8) ^ (x << 2) ^ (x << 18) ^
			((x & 0x3F) << 26) ^ ((x & 0xC0) << 10);
	x = rs1 ^ _rvk_emu_rol_32(x, bs);
	return (long) x;
}

static inline long _rvk_emu_sm4ks(long rs1, long rs2, uint8_t bs)
{
	int32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_sm4_sbox[x];				//	SM4 s-box

	//	SM4 transform L' (key)
	x = x ^ ((x & 0x07) << 29) ^ ((x & 0xFE) << 7) ^
		((x & 1) << 23) ^ ((x & 0xF8) << 13);
	x = rs1 ^ _rvk_emu_rol_32(x, bs);
	return (long) x;
}

//	=== (emulated)	Zksh:	ShangMi Suite: SM3 Hash Function Instructions

static inline int32_t  _rvk_emu_sm3p0(long rs1)
{
	int32_t x;

	x = rs1 ^ _rvk_emu_rol_32(rs1, 9) ^ _rvk_emu_rol_32(rs1, 17);
	return (long) x;
}

static inline int32_t  _rvk_emu_sm3p1(long rs1)
{
	int32_t x;

	x = rs1 ^ _rvk_emu_rol_32(rs1, 15) ^ _rvk_emu_rol_32(rs1, 23);
	return (long) x;
}


#endif		//	RVKINTRIN_EMULATE
#endif		//	_RVK_EMU_INTRIN_H
