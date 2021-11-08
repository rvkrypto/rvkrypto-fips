//	rvk_inline.h
//	2021-11-08	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	===	Inline assembler definitions for scalar cryptography intrinsics.

#ifndef _RVK_INLINE_H
#define _RVK_INLINE_H

#include <stdint.h>

#if __riscv_xlen == 32
#define RVINTRIN_RV32
#elif __riscv_xlen == 64
#define RVINTRIN_RV64
#else
#error "__riscv_xlen not valid."
#endif

//	=== (inline)	Zbkb:	Bitmanipulation instructions for Cryptography

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_ror(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("ror	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_rol(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 & -rs2)); else __asm__ ("rol	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int32_t _rv32_ror(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("roriw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("rorw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_rol(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("roriw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 & -rs2)); else __asm__ ("rolw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_ror(int64_t rs1, int64_t rs2)
	{ int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(63 &  rs2)); else __asm__ ("ror	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_rol(int64_t rs1, int64_t rs2)
	{ int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(63 & -rs2)); else __asm__ ("rol	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

static inline long _rv_andn(long rs1, long rs2)
	{ long rd; __asm__ ("andn %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline long _rv_orn (long rs1, long rs2)
	{ long rd; __asm__ ("orn  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline long _rv_xnor(long rs1, long rs2)
	{ long rd; __asm__ ("xnor %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_pack(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("pack  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_packh(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("packh  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_pack(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("pack  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_packh(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("packh  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_pack(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("packw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_brev8(int32_t rs1)
	{ int32_t rd; __asm__ ("grevi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(7)); return rd; }
static inline int32_t _rv32_rev8(int32_t rs1)
	{ int32_t rd; __asm__ ("grevi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(24)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_brev8(int64_t rs1)
	{ int64_t rd; __asm__ ("grevi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(7)); return rd; }
static inline int64_t _rv64_rev8(int64_t rs1)
	{ int64_t rd; __asm__ ("grevi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(56)); return rd; }
#endif

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_zip(int32_t rs1)
	{ int32_t rd; __asm__ ("shfli  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15)); return rd; }
static inline int32_t _rv32_unzip(int32_t rs1)
	{ int32_t rd; __asm__ ("unshfli	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15)); return rd; }
#endif

//	=== (inline)	Zbkc:	Carry-less multiply instructions

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_clmul(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("clmul  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_clmulh(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("clmulh	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_clmul(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("clmul  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_clmulh(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("clmulh	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zbkx:	Crossbar permutation instructions

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_xperm8(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("xperm8	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_xperm4(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("xperm4	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_xperm8(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("xperm8	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_xperm4(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("xperm4	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zknd:	NIST Suite: AES Decryption

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_aes32dsi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32dsi	 %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
static inline int32_t _rv32_aes32dsmi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32dsmi  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_aes64ds(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64ds	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_aes64dsm(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64dsm %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_aes64im(int64_t rs1)
	{ int64_t rd; __asm__("aes64im	%0, %1	 " : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rv64_aes64ks1i(int64_t rs1, int rnum)
	{ int64_t rd; __asm__("aes64ks1i %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rnum)); return rd; }
static inline int64_t _rv64_aes64ks2(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64ks2 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zkne:	NIST Suite: AES Encryption

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_aes32esi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32esi	 %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
static inline int32_t _rv32_aes32esmi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32esmi %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_aes64es(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64es	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rv64_aes64esm(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64esm %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zknh:	NIST Suite: Hash Function Instructions

static inline long _rv_sha256sig0(long rs1)
	{ long rd; __asm__ ("sha256sig0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rv_sha256sig1(long rs1)
	{ long rd; __asm__ ("sha256sig1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rv_sha256sum0(long rs1)
	{ long rd; __asm__ ("sha256sum0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rv_sha256sum1(long rs1)
	{ long rd; __asm__ ("sha256sum1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }

#ifdef RVINTRIN_RV32
static inline int32_t _rv32_sha512sig0h(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig0h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_sha512sig0l(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig0l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_sha512sig1h(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig1h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_sha512sig1l(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig1l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_sha512sum0r(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sum0r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rv32_sha512sum1r(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sum1r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVINTRIN_RV64
static inline int64_t _rv64_sha512sig0(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sig0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rv64_sha512sig1(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sig1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rv64_sha512sum0(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sum0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rv64_sha512sum1(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sum1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
#endif

//	=== (inline)	Zksed:	ShangMi Suite: SM4 Block Cipher Instructions

static inline long _rv_sm4ks(int32_t rs1, int32_t rs2, int bs)
	{ long rd; __asm__("sm4ks %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
static inline long _rv_sm4ed(int32_t rs1, int32_t rs2, int bs)
	{ long rd; __asm__("sm4ed %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }

//	=== (inline)	Zksh:	ShangMi Suite: SM3 Hash Function Instructions

static inline long _rv_sm3p0(long rs1)
	{ long rd; __asm__("sm3p0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rv_sm3p1(long rs1)
	{ long rd; __asm__("sm3p1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }

#endif
//	_RVK_INLINE_H
