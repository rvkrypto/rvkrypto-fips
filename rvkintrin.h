//	rvkintrin.h
//	2021-02-13	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	RISC-V "K" extension proposal intrinsics and emulation

/*
 *	Krypto intrinsics follow the conventions of rvintrin.h from bitmanip:
 *
 *	_rv_*(...)
 *	  RV32/64 intrinsics that operate on the "long" data type
 *
 *	_rv32_*(...)
 *	  RV32/64 intrinsics that operate on the "int32_t" data type
 *
 *	_rv64_*(...)
 *	  RV64-only intrinsics that operate on the "int64_t" data type
 */

#ifndef _RVKINTRIN_H_
#define _RVKINTRIN_H_

#include <limits.h>
#include <stdint.h>

//	always include bitmanip intrinsics; architecture macros defined there
#include "rvintrin.h"

//	IMPORTANT:

//	Compilers should not emit emulation code for machine intrinsics.
//	(especially conditionals or table lookups), just the machine instructions.
//	If architecture is not enabled, fail.

#if !defined(__riscv_xlen) && !defined(RVINTRIN_EMULATE)
#  warning "Target is not RISC-V. Enabling <rvkintrin.h> emulation mode."
#  define RVINTRIN_EMULATE 1
#endif

//	TODO: Also emit warnings if FIPS mode is enabled and emulation flag is on.

#ifndef RVINTRIN_EMULATE

//	=== AES32: Zkn (RV32), Zknd, Zkne 

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_aes32dsi(int32_t rs1, int32_t rs2, int bs)
	{__asm__("aes32dsi	%0, %1, %2" : "+r"(rs1) : "r"(rs2), "i"(bs)); return rs1;}
static inline int32_t _rv32_aes32dsmi(int32_t rs1, int32_t rs2, int bs)
	{__asm__("aes32dsmi %0, %1, %2" : "+r"(rs1) : "r"(rs2), "i"(bs)); return rs1;}
static inline int32_t _rv32_aes32esi(int32_t rs1, int32_t rs2, int bs)
	{__asm__("aes32esi	%0, %1, %2" : "+r"(rs1) : "r"(rs2), "i"(bs)); return rs1;}
static inline int32_t _rv32_aes32esmi(int32_t rs1, int32_t rs2, int bs)
	{__asm__("aes32esmi %0, %1, %2" : "+r"(rs1) : "r"(rs2), "i"(bs)); return rs1;}
#endif

//	=== AES64: Zkn (RV32), Zknd, Zkne

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_aes64dsm(int64_t rs1, int64_t rs2)
	{int64_t rd; __asm__("aes64dsm  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int64_t _rv64_aes64ds(int64_t rs1, int64_t rs2)
	{int64_t rd; __asm__("aes64ds	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int64_t _rv64_aes64ks1i(int64_t rs1, int rcon)
	{int64_t rd; __asm__("aes64ks1i	%0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rcon)); return rd;}
static inline int64_t _rv64_aes64ks2(int64_t rs1, int64_t rs2)
	{int64_t rd; __asm__("aes64ks2  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int64_t _rv64_aes64im(int64_t rs1)
	{int64_t rd; __asm__("aes64im	%0, %1	 " : "=r"(rd) : "r"(rs1)); return rd;}
static inline int64_t _rv64_aes64esm(int64_t rs1, int64_t rs2)
	{int64_t rd; __asm__("aes64esm  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int64_t _rv64_aes64es(int64_t rs1, int64_t rs2)
	{int64_t rd; __asm__("aes64es	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#endif

//	=== SHA256: Zkn (RV32, RV64), Zknh

static inline long _rv_sha256sig0 (long rs1)
	{long rd; __asm__ ("sha256sig0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline long _rv_sha256sig1 (long rs1)
	{long rd; __asm__ ("sha256sig1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline long _rv_sha256sum0 (long rs1)
	{long rd; __asm__ ("sha256sum0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline long _rv_sha256sum1 (long rs1)
	{long rd; __asm__ ("sha256sum1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}

//	=== SHA512: Zkn (RV32), Zknh

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_sha512sig0l(int32_t rs1, int32_t rs2)
	{int32_t rd; __asm__ ("sha512sig0l	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int32_t _rv32_sha512sig0h(int32_t rs1, int32_t rs2)
	{int32_t rd; __asm__ ("sha512sig0h	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int32_t _rv32_sha512sig1l(int32_t rs1, int32_t rs2)
	{int32_t rd; __asm__ ("sha512sig1l	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int32_t _rv32_sha512sig1h(int32_t rs1, int32_t rs2)
	{int32_t rd; __asm__ ("sha512sig1h	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int32_t _rv32_sha512sum0r(int32_t rs1, int32_t rs2)
	{int32_t rd; __asm__ ("sha512sum0r	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
static inline int32_t _rv32_sha512sum1r(int32_t rs1, int32_t rs2)
	{int32_t rd; __asm__ ("sha512sum1r	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd;}
#endif

//	=== SHA512: Zkn (RV64), Zknh

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_sha512sig0(int64_t rs1)
	{int64_t rd; __asm__ ("sha512sig0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline int64_t _rv64_sha512sig1(int64_t rs1)
	{int64_t rd; __asm__ ("sha512sig1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline int64_t _rv64_sha512sum0(int64_t rs1)
	{int64_t rd; __asm__ ("sha512sum0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline int64_t _rv64_sha512sum1(int64_t rs1)
	{int64_t rd; __asm__ ("sha512sum1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
#endif

//	=== SM3:	Zks (RV32, RV64), Zksh 
static inline long _rv_sm3p0 (long rs1)
	{long rd; __asm__("sm3p0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}
static inline long _rv_sm3p1 (long rs1)
	{long rd; __asm__("sm3p1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd;}

//	=== SM4:	Zks (RV32, RV64), Zkse
static inline long _rv_sm4ks (long rs1, long rs2, int bs)
	{__asm__("sm4ks	%0, %1, %2" : "+r"(rs1) : "r"(rs2), "i"(bs)); return rs1;}
static inline long _rv_sm4ed (long rs1, long rs2, int bs)
	{__asm__("sm4ed	%0, %1, %2" : "+r"(rs1) : "r"(rs2), "i"(bs)); return rs1;}

//	Entropy source: Zkr (RV32, RV64)

static inline long _rv_pollentropy()
	{long rd; __asm__ volatile ("pollentropy %0" : "=r"(rd)); return rd;}
static inline long _rv_getnoise()
	{long rd; __asm__ volatile ("getnoise %0" : "=r"(rd)); return rd;}

#else // RVINTRIN_EMULATE

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
		_rv32_rol(_rvk_emu_aes_fwd_mc_8((x >>  8) & 0xFF),	8) ^
		_rv32_rol(_rvk_emu_aes_fwd_mc_8((x >> 16) & 0xFF), 16) ^
		_rv32_rol(_rvk_emu_aes_fwd_mc_8((x >> 24) & 0xFF), 24);
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
		_rv32_rol(_rvk_emu_aes_inv_mc_8((x >>  8) & 0xFF),	8) ^
		_rv32_rol(_rvk_emu_aes_inv_mc_8((x >> 16) & 0xFF), 16) ^
		_rv32_rol(_rvk_emu_aes_inv_mc_8((x >> 24) & 0xFF), 24);
}

//	=== AES32: Zkn (RV32), Zknd

static inline int32_t _rv32_aes32dsi(int32_t rs1, int32_t rs2, int bs)
{
	uint32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_inv_sbox[x];			//	AES inverse s-box

	return rs1 ^ _rv32_rol(x, bs);
}

static inline int32_t _rv32_aes32dsmi(int32_t rs1, int32_t rs2, int bs)
{
	uint32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_inv_sbox[x];			//	AES inverse s-box
	x = _rvk_emu_aes_inv_mc_8(x);			//	inverse MixColumns

	return rs1 ^ _rv32_rol(x, bs);
}

//	=== AES32: ZKn (RV32), Zkne

static inline int32_t _rv32_aes32esi(int32_t rs1, int32_t rs2, int bs)
{
	uint32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_fwd_sbox[x];			//	AES forward s-box

	return rs1 ^ _rv32_rol(x, bs);
}

static inline int32_t _rv32_aes32esmi(int32_t rs1, int32_t rs2, int bs)
{
	uint32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_aes_fwd_sbox[x];			//	AES forward s-box
	x = _rvk_emu_aes_fwd_mc_8(x);			//	forward MixColumns

	return rs1 ^ _rv32_rol(x, bs);
}

//	=== AES64: Zkn (RV64), Zknd

static inline int64_t _rv64_aes64ds(int64_t rs1, int64_t rs2)
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

static inline int64_t _rv64_aes64im(int64_t rs1)
{
	return ((int64_t) _rvk_emu_aes_inv_mc_32(rs1)) |
		(((int64_t) _rvk_emu_aes_inv_mc_32(rs1 >> 32)) << 32);
}

static inline int64_t _rv64_aes64dsm(int64_t rs1, int64_t rs2)
{
	int64_t x;

	x = _rv64_aes64ds(rs1, rs2);			//	Inverse ShiftRows, SubBytes
	x = _rv64_aes64im(x);					//	Inverse MixColumns

	return x;
}

//	=== AES64: Zkn (RV64), Zkne

static inline int64_t _rv64_aes64es(int64_t rs1, int64_t rs2)
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

static inline int64_t _rv64_aes64esm(int64_t rs1, int64_t rs2)
{
	int64_t x;

	x = _rv64_aes64es(rs1, rs2);			//	ShiftRows and SubBytes
	x = ((int64_t) _rvk_emu_aes_fwd_mc_32(x)) |		//	MixColumns
		(((int64_t) _rvk_emu_aes_fwd_mc_32(x >> 32)) << 32);

	return x;
}

static inline int64_t _rv64_aes64ks1i(int64_t rs1, int rcon)
{
	//	AES Round Constants
	const uint8_t aes_rcon[] = {
		0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
	};

	uint32_t t, rc;

	t = rs1 >> 32;							//	high word
	rc = 0;

	if (rcon < 10) {						//	10: don't do it
		t = _rv32_ror(t, 8);
		rc = aes_rcon[rcon];				//	round constant
	}
	//	SubWord
	t = ((uint32_t) _rvk_emu_aes_fwd_sbox[t & 0xFF]) |
		(((uint32_t) _rvk_emu_aes_fwd_sbox[(t >> 8) & 0xFF]) << 8) |
		(((uint32_t) _rvk_emu_aes_fwd_sbox[(t >> 16) & 0xFF]) << 16) |
		(((uint32_t) _rvk_emu_aes_fwd_sbox[(t >> 24) & 0xFF]) << 24);

	t ^= rc;

	return ((int64_t) t) | (((int64_t) t) << 32);
}

static inline int64_t _rv64_aes64ks2(int64_t rs1, int64_t rs2)
{
	uint32_t t;

	t = (rs1 >> 32) ^ (rs2 & 0xFFFFFFFF);	//	wrap 32 bits

	return ((int64_t) t) ^					//	low 32 bits
		(((int64_t) t) << 32) ^ (rs2 & 0xFFFFFFFF00000000ULL);
}

//	=== SHA256: Zkn (RV32 & RV64), Zknh

static inline long _rv_sha256sig0(long rs1)
{
	return _rv32_ror(rs1, 7) ^ _rv32_ror(rs1, 18) ^ _rv32_srl(rs1, 3);
}

static inline long _rv_sha256sig1(long rs1)
{
	return _rv32_ror(rs1, 17) ^ _rv32_ror(rs1, 19) ^ _rv32_srl(rs1, 10);
}

static inline long _rv_sha256sum0(long rs1)
{
	return _rv32_ror(rs1, 2) ^ _rv32_ror(rs1, 13) ^ _rv32_ror(rs1, 22);
}

static inline long _rv_sha256sum1(long rs1)
{
	return _rv32_ror(rs1, 6) ^ _rv32_ror(rs1, 11) ^ _rv32_ror(rs1, 25);
}

//	=== SHA512: ZKn (RV32), Zknh

static inline int32_t _rv32_sha512sig0h(int32_t rs1, int32_t rs2)
{
	return	_rv32_srl(rs1, 1) ^ _rv32_srl(rs1, 7) ^ _rv32_srl(rs1, 8) ^
			_rv32_sll(rs2, 31) ^ _rv32_sll(rs2, 24);
}

static inline int32_t _rv32_sha512sig0l(int32_t rs1, int32_t rs2)
{
	return	_rv32_srl(rs1, 1) ^ _rv32_srl(rs1, 7) ^ _rv32_srl(rs1, 8) ^
			_rv32_sll(rs2, 31) ^ _rv32_sll(rs2, 25) ^ _rv32_sll(rs2, 24);
}

static inline int32_t _rv32_sha512sig1h(int32_t rs1, int32_t rs2)
{
	return	_rv32_sll(rs1, 3) ^ _rv32_srl(rs1, 6) ^ _rv32_srl(rs1, 19) ^
			_rv32_srl(rs2, 29) ^ _rv32_sll(rs2, 13);
}

static inline int32_t _rv32_sha512sig1l(int32_t rs1, int32_t rs2)
{
	return	_rv32_sll(rs1, 3) ^ _rv32_srl(rs1, 6) ^ _rv32_srl(rs1, 19) ^
			_rv32_srl(rs2, 29) ^ _rv32_sll(rs2, 26) ^ _rv32_sll(rs2, 13);
}

static inline int32_t _rv32_sha512sum0r(int32_t rs1, int32_t rs2)
{
	return	_rv32_sll(rs1, 25) ^ _rv32_sll(rs1, 30) ^ _rv32_srl(rs1, 28) ^
			_rv32_srl(rs2, 7) ^ _rv32_srl(rs2, 2) ^ _rv32_sll(rs2, 4);
}

static inline int32_t _rv32_sha512sum1r(int32_t rs1, int32_t rs2)
{
	return	_rv32_sll(rs1, 23) ^ _rv32_srl(rs1, 14) ^ _rv32_srl(rs1, 18) ^
			_rv32_srl(rs2, 9) ^ _rv32_sll(rs2, 18) ^ _rv32_sll(rs2, 14);
}

//	=== SHA512: Zkn (RV64), Zknh

static inline int64_t _rv64_sha512sig0(int64_t rs1)
{
	return _rv64_ror(rs1, 1) ^ _rv64_ror(rs1, 8) ^ _rv64_srl(rs1, 7);
}

static inline int64_t _rv64_sha512sig1(int64_t rs1)
{
	return _rv64_ror(rs1, 19) ^ _rv64_ror(rs1, 61) ^ _rv64_srl(rs1, 6);
}

static inline int64_t _rv64_sha512sum0(int64_t rs1)
{
	return _rv64_ror(rs1, 28) ^ _rv64_ror(rs1, 34) ^ _rv64_ror(rs1, 39);
}

static inline int64_t _rv64_sha512sum1(int64_t rs1)
{
	return _rv64_ror(rs1, 14) ^ _rv64_ror(rs1, 18) ^ _rv64_ror(rs1, 41);
}

//	=== SM3: Zks (RV32 & RV64), Zksh

static inline long _rv_sm3p0(long rs1)
{
	return rs1 ^ _rv32_ror(rs1, 15) ^ _rv32_ror(rs1, 23);
}

static inline long _rv_sm3p1(long rs1)
{
	return rs1 ^ _rv32_ror(rs1, 9) ^ _rv32_ror(rs1, 17);
}

//	=== SM4: Zks (RV32 & RV64), Zkse

static inline long _rv_sm4ed(long rs1, long rs2, int bs)
{
	uint32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_sm4_sbox[x];				//	SM4 s-box

	//	SM4 linear transform L
	x = x ^ (x << 8) ^ (x << 2) ^ (x << 18) ^
			((x & 0x3F) << 26) ^ ((x & 0xC0) << 10);

	return rs1 ^ _rv32_rol(x, bs);
}

static inline long _rv_sm4ks(long rs1, long rs2, int bs)
{
	uint32_t x;

	bs = (bs & 3) << 3;						//	byte select
	x = (rs2 >> bs) & 0xFF;
	x = _rvk_emu_sm4_sbox[x];				//	SM4 s-box

	//	SM4 transform L' (key)
	x = x ^ ((x & 0x07) << 29) ^ ((x & 0xFE) << 7) ^
		((x & 1) << 23) ^ ((x & 0xF8) << 13);

	return rs1 ^ _rv32_rol(x, bs);
}

//	=== Entropy source:	Zkr (RV32 & RV64) -- function prototypes only for emu.

long _rv_pollentropy();
long _rv_getnoise();

#endif	// RVINTRIN_EMULATE

#endif	// _RVKINTRIN_H_
