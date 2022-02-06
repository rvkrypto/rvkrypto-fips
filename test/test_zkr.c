//	test_zkr.c
//	2021-11-09	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	=== Simple test for Zkr

#include "riscv_crypto.h"

#ifdef RVKINTRIN_ZKR

#include "test_rvkat.h"

static inline uint32_t _rvk_asm_zkr_seed()
{
	uint32_t rd; 
	__asm__ __volatile__ ("csrrw %0, 0x015, x0" : "=r"(rd));	
	return rd; 
}

//	SM4: test vectors and algorithm tests

int test_zkr()
{
	int fail = 0;
	int i;
	uint32_t seed, v[10];

	rvkat_info("=== Zkr seed ===");

	//	load the seeds quick (to reveal wait states)
	for (i = 0; i < 10; i++) {
		v[i] = _rvk_asm_zkr_seed();
	}

	for (i = 0; i < 10; i++) {
		sio_puts("[INFO] ");
		seed = v[i];
		switch((seed >> 30) & 3) {
			case 0:	sio_puts("BIST"); break;
			case 1:	sio_puts("WAIT"); break;
			case 2:	sio_puts("ES16"); break;
			case 3:	sio_puts("DEAD"); break;
		}

		rvkat_hexu32(seed);
		sio_putc('\n');	
	}
	
	return fail;
}

#endif
