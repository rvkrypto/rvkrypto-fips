//	rvk_asm_intrin.h
//	2021-11-08	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Inline assembler definitions for scalar cryptography intrinsics.

#ifndef _RVK_ASM_INTRIN_H
#define _RVK_ASM_INTRIN_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#if __riscv_xlen == 32
#define RVKINTRIN_RV32
#elif __riscv_xlen == 64
#define RVKINTRIN_RV64
#else
#error "__riscv_xlen not valid."
#endif

//	=== (inline)	Zbkb:	Bitmanipulation instructions for Cryptography

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_ror_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("ror	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_rol_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 & -rs2)); else __asm__ ("rol	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVKINTRIN_RV64
static inline int32_t _rvk_asm_ror_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("roriw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 &  rs2)); else __asm__ ("rorw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_rol_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; if (__builtin_constant_p(rs2)) __asm__ ("roriw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(31 & -rs2)); else __asm__ ("rolw  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rvk_asm_ror_64(int64_t rs1, int64_t rs2)
	{ int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(63 &  rs2)); else __asm__ ("ror	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rvk_asm_rol_64(int64_t rs1, int64_t rs2)
	{ int64_t rd; if (__builtin_constant_p(rs2)) __asm__ ("rori	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(63 & -rs2)); else __asm__ ("rol	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_brev8_32(int32_t rs1)
	{ int32_t rd; __asm__ ("grevi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(7)); return rd; }
#endif

#ifdef RVKINTRIN_RV64
static inline int64_t _rvk_asm_brev8_64(int64_t rs1)
	{ int64_t rd; __asm__ ("grevi  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(7)); return rd; }
#endif

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_zip_32(int32_t rs1)
	{ int32_t rd; __asm__ ("shfli  %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15)); return rd; }
static inline int32_t _rvk_asm_unzip_32(int32_t rs1)
	{ int32_t rd; __asm__ ("unshfli	 %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(15)); return rd; }
#endif

//	=== (inline)	Zbkc:	Carry-less multiply instructions

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_clmul_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("clmul  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_clmulh_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("clmulh	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVKINTRIN_RV64
static inline int64_t _rvk_asm_clmul_64(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("clmul  %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rvk_asm_clmulh_64(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("clmulh	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zbkx:	Crossbar permutation instructions

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_xperm8_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("xperm8	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_xperm4_32(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("xperm4	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVKINTRIN_RV64
static inline int64_t _rvk_asm_xperm8_64(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("xperm8	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rvk_asm_xperm4_64(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__ ("xperm4	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zknd:	NIST Suite: AES Decryption

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_aes32dsi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32dsi	 %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
static inline int32_t _rvk_asm_aes32dsmi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32dsmi  %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
#endif

#ifdef RVKINTRIN_RV64
static inline int64_t _rvk_asm_aes64ds(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64ds	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rvk_asm_aes64dsm(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64dsm %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rvk_asm_aes64im(int64_t rs1)
	{ int64_t rd; __asm__("aes64im	%0, %1	 " : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rvk_asm_aes64ks1i(int64_t rs1, int rnum)
	{ int64_t rd; __asm__("aes64ks1i %0, %1, %2" : "=r"(rd) : "r"(rs1), "i"(rnum)); return rd; }
static inline int64_t _rvk_asm_aes64ks2(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64ks2 %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zkne:	NIST Suite: AES Encryption

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_aes32esi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32esi	 %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
static inline int32_t _rvk_asm_aes32esmi(int32_t rs1, int32_t rs2, int bs)
	{ int32_t rd; __asm__("aes32esmi %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
#endif

#ifdef RVKINTRIN_RV64
static inline int64_t _rvk_asm_aes64es(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64es	%0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int64_t _rvk_asm_aes64esm(int64_t rs1, int64_t rs2)
	{ int64_t rd; __asm__("aes64esm %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

//	=== (inline)	Zknh:	NIST Suite: Hash Function Instructions

static inline long _rvk_asm_sha256sig0(long rs1)
	{ long rd; __asm__ ("sha256sig0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rvk_asm_sha256sig1(long rs1)
	{ long rd; __asm__ ("sha256sig1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rvk_asm_sha256sum0(long rs1)
	{ long rd; __asm__ ("sha256sum0 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rvk_asm_sha256sum1(long rs1)
	{ long rd; __asm__ ("sha256sum1 %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }

#ifdef RVKINTRIN_RV32
static inline int32_t _rvk_asm_sha512sig0h(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig0h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_sha512sig0l(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig0l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_sha512sig1h(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig1h %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_sha512sig1l(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sig1l %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_sha512sum0r(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sum0r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
static inline int32_t _rvk_asm_sha512sum1r(int32_t rs1, int32_t rs2)
	{ int32_t rd; __asm__ ("sha512sum1r %0, %1, %2" : "=r"(rd) : "r"(rs1), "r"(rs2)); return rd; }
#endif

#ifdef RVKINTRIN_RV64
static inline int64_t _rvk_asm_sha512sig0(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sig0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rvk_asm_sha512sig1(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sig1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rvk_asm_sha512sum0(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sum0	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline int64_t _rvk_asm_sha512sum1(int64_t rs1)
	{ int64_t rd; __asm__ ("sha512sum1	%0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
#endif

//	=== (inline)	Zksed:	ShangMi Suite: SM4 Block Cipher Instructions

static inline long _rvk_asm_sm4ks(int32_t rs1, int32_t rs2, int bs)
	{ long rd; __asm__("sm4ks %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }
static inline long _rvk_asm_sm4ed(int32_t rs1, int32_t rs2, int bs)
	{ long rd; __asm__("sm4ed %0, %1, %2, %3" : "=r"(rd) : "r"(rs1), "r"(rs2), "i"(bs)); return rd; }

//	=== (inline)	Zksh:	ShangMi Suite: SM3 Hash Function Instructions

static inline long _rvk_asm_sm3p0(long rs1)
	{ long rd; __asm__("sm3p0  %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }
static inline long _rvk_asm_sm3p1(long rs1)
	{ long rd; __asm__("sm3p1  %0, %1" : "=r"(rd) : "r"(rs1)); return rd; }


#ifdef __cplusplus
}
#endif

#endif	//	_RVK_ASM_INTRIN_H
