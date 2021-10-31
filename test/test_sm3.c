//	test_sm3.c
//	2020-03-30	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	The Chinese Standard SM3 Hash Function
//	GB/T 32905-2016, GM/T 0004-2012, ISO/IEC 10118-3:2018

#include "rvkintrin.h"
#include "test_rvkat.h"
#include "sm3/sm3_api.h"

//	SM3: test vectors and algorithm tests

int test_sm3()
{
	uint8_t md[32], in[256];
	int fail = 0;

	rvkat_info("=== SM3 ===");

	//	simplified test with "abc" test vector from the standard
	sm3_256(md, "abc", 3);
	fail += rvkat_chkhex("SM3-256", md, 32,
		"66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0");

	//	we only have two vectors currently
	sm3_256(md, in, rvkat_gethex(in, sizeof(in),
		"6162636461626364616263646162636461626364616263646162636461626364"
		"6162636461626364616263646162636461626364616263646162636461626364"));
	fail += rvkat_chkhex("SM3-256", md, 32,
		"DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732");

	return fail;
}
