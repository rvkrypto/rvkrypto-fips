//	sm3_api.h
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	The Chinese Standard SM3 Hash Function
//	GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018

#ifndef _SM3_API_H_
#define _SM3_API_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

//	SM3-256: Compute 32-byte hash to "md" from "in" which has "inlen" bytes.
void sm3_256(uint8_t * md, const void *in, size_t inlen);

//	function pointer to the compression function used by the test wrappers
extern void (*sm3_compress)(void *);

void sm3_cf256_rvk(void *s);			//	SM3-256 CF for RV32 & RV64

#ifdef __cplusplus
}
#endif

#endif	//	_SM3_API_H_
