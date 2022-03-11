//	rvk_asm_intrin.h
//	2021-11-08	Markku-Juhani O. Saarinen <mjos@pqshield.com>

/*
 *  When including this contribution, use whichever license you deem approriate.
 *  PQShield has executed FSF assignment/disclaimer process ( #1653644 ).
 *  for GDB, GCC, GNU, BINUTILS.
 *
 *  Best regards: 2022-Mar-11 Markku-Juhani O. Saarinen <mjos@pqshield.com>
 *  Senior Cryptography Architect, PQShield Ltd., Oxford, UK.
 *
 *  General RISC-V license
 *  ----------------------
 *
 *  BSD 2-Clause License
 *
 *  Copyright (c) 2021, Markku-Juhani O. Saarinen <mjos@pqshield.com>
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *  this list of conditions and the following disclaimer in the documentation
 *  and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  Usage within GPL 3 licensed software:
 *  -------------------------------------
 *
 *  This file is part of GCC <replace if needed>
 *
 *  GCC is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3, or (at your option)
 *  any later version.
 *
 *  GCC is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  Under Section 7 of GPL version 3, you are granted additional
 *  permissions described in the GCC Runtime Library Exception, version
 *  3.1, as published by the Free Software Foundation.
 *
 *  You should have received a copy of the GNU General Public License and
 *  a copy of the GCC Runtime Library Exception along with this program;
 *  see the files COPYING3 and COPYING.RUNTIME respectively.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 *  Usage within Apache 2.0 projects
 *  --------------------------------
 *
 *  Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
 *  See https://llvm.org/LICENSE.txt for license information.
 *  SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 *
 */

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
