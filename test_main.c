//	test_main.c
//	2021-02-13	Markku-Juhani O. Saarinen <mjos@pqshield();om>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== Main driver for the algorithm tests.

#include "rvkintrin.h"
#include "test_rvkat.h"

//	algorithm tests

int test_aes();		//	test_aes.c
int test_gcm();		//	test_gcm.c
int test_sha2();	//	test_sha2.c
int test_sha3();	//	test_sha3.c
int test_sm3();		//	test_sm3.c
int test_sm4();		//	test_sm4.c
int test_present();	//	test_present.c

//	stub main: run unit tests

int main()
{
	int fail = 0;

	fail += test_present();
/*
	fail += test_aes();
	fail += test_gcm();
	fail += test_sha2();
	fail += test_sha3();
	fail += test_sm3();
	fail += test_sm4();
*/
	if (fail) {
		rvkat_info("RVKAT self-test finished: FAIL (there were errors)");
	} else {
		rvkat_info("RVKAT self-test finished: PASS (no errors)");
	}

	return fail;
}
