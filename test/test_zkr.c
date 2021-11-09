//	test_zkr.c
//	2021-11-09	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	=== Simple test for Zkr

#include "rvkintrin.h"

#ifdef RVKINTRIN_ZKR

#include "test_rvkat.h"

static inline uint32_t _rvk_asm_zkr_seed()
	{ uint32_t rd; __asm__ ("csrrw  %0, 0x015, x0" : "=r"(rd)); return rd; }

//	SM4: test vectors and algorithm tests

int test_zkr()
{
	int fail = 0;
	int i;
	uint32_t seed;

	rvkat_info("=== Zkr seed ===");

	for (i = 0; i < 10; i++) {
		seed = _rvk_asm_zkr_seed();
		rvkat_hexu32(seed);
	}
	
	return fail;
}

#endif
