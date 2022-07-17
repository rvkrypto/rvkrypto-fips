//	rv_endian.h
//	2020-11-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	=== endianess conversions and unaligned load/store

#ifndef _RV_ENDIAN_H_
#define _RV_ENDIAN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

//	little-endian loads and stores (unaligned)

static inline uint16_t get16u_le(const uint8_t* v)
{
	return (((uint16_t)v[1]) << 8) | ((uint16_t)v[0]);
}

static inline void put16u_le(uint8_t* v, uint16_t x)
{
	v[0] = x;
	v[1] = x >> 8;
}

static inline uint32_t get32u_le(const uint8_t* v)
{
	return ((uint32_t)v[0]) | (((uint32_t)v[1]) << 8) |
		   (((uint32_t)v[2]) << 16) | (((uint32_t)v[3]) << 24);
}

static inline void put32u_le(uint8_t* v, uint32_t x)
{
	v[0] = x;
	v[1] = x >> 8;
	v[2] = x >> 16;
	v[3] = x >> 24;
}

static inline uint64_t get64u_le(const uint8_t* v)
{
	return ((uint64_t)v[0]) | (((uint64_t)v[1]) << 8) |
		   (((uint64_t)v[2]) << 16) | (((uint64_t)v[3]) << 24) |
		   (((uint64_t)v[4]) << 32) | (((uint64_t)v[5]) << 40) |
		   (((uint64_t)v[6]) << 48) | (((uint64_t)v[7]) << 56);
}

static inline void put64u_le(uint8_t* v, uint64_t x)
{
	v[0] = x;
	v[1] = x >> 8;
	v[2] = x >> 16;
	v[3] = x >> 24;
	v[4] = x >> 32;
	v[5] = x >> 40;
	v[6] = x >> 48;
	v[7] = x >> 56;
}

//	big-endian loads and stores (unaligned)

static inline uint16_t get16u_be(const uint8_t* v)
{
	return (((uint16_t)v[0]) << 8) | ((uint16_t)v[1]);
}

static inline void put16u_be(uint8_t* v, uint16_t x)
{
	v[0] = x >> 8;
	v[1] = x;
}

static inline uint32_t get32u_be(const uint8_t* v)
{
	return (((uint32_t)v[0]) << 24) | (((uint32_t)v[1]) << 16) |
		   (((uint32_t)v[2]) << 8) | ((uint32_t)v[3]);
}

static inline void put32u_be(uint8_t* v, uint32_t x)
{
	v[0] = x >> 24;
	v[1] = x >> 16;
	v[2] = x >> 8;
	v[3] = x;
}

static inline uint64_t get64u_be(const uint8_t* v)
{
	return (((uint64_t)v[0]) << 56) | (((uint64_t)v[1]) << 48) |
		   (((uint64_t)v[2]) << 40) | (((uint64_t)v[3]) << 32) |
		   (((uint64_t)v[4]) << 24) | (((uint64_t)v[5]) << 16) |
		   (((uint64_t)v[6]) << 8) | ((uint64_t)v[7]);
}

static inline void put64u_be(uint8_t* v, uint64_t x)
{
	v[0] = x >> 56;
	v[1] = x >> 48;
	v[2] = x >> 40;
	v[3] = x >> 32;
	v[4] = x >> 24;
	v[5] = x >> 16;
	v[6] = x >> 8;
	v[7] = x;
}

#ifdef __cplusplus
}
#endif

#endif	//	_RV_ENDIAN_H_
