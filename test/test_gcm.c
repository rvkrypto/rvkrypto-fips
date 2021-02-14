//	test_gcm.c
//	2020-03-21	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Unit tests for GCM AES-128/192/256 (800-38D) in simple mode. Selected from
//	https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip

#include <string.h>
#include "rvkintrin.h"
#include "test_rvkat.h"

#include "gcm/gcm_api.h"
#include "gcm/gcm_gfmul.h"

//	replace with a random function if you wish
#ifndef RAND_CNST
#define RAND_CNST 314159265
#endif

//	A GCM test vectors

int test_gcm_tv()
{
	uint8_t pt[100], ct[100], xt[100], k[32], iv[12];
	size_t mlen, clen;
	int flag, fail = 0;

	//	GCM AES-128, one-block message

	rvkat_gethex(k, sizeof(k),
		"7FDDB57453C241D03EFBED3AC44E371C");
	rvkat_gethex(iv, sizeof(iv),
		"EE283A3FC75575E33EFD4887");
	mlen = rvkat_gethex(pt, sizeof(pt),
		"D5DE42B461646C255C87BD2962D3B9A2");
	clen = mlen + 16;
	memset(ct, 0, clen);
	aes128_enc_gcm(ct, pt, mlen, k, iv);
	fail += rvkat_chkhex("GCM AES-128", ct, clen,
		"2CCDA4A5415CB91E135C2A0F78C9B2FD"
		"B36D1DF9B9D5E596F83E8B7F52971CB3");

	memset(xt, 0, mlen);
	flag = aes128_dec_vfy_gcm(xt, ct, clen, k, iv) ||
		memcmp(xt, pt, mlen) != 0;

	ct[RAND_CNST % clen] ^= 1 << (RAND_CNST & 7);	//	corrupt

	flag |= !(aes128_dec_vfy_gcm(xt, ct, clen, k, iv) ||
			  memcmp(xt, pt, mlen) != 0);
	fail += rvkat_chkret("GCM AES-128 verify / corrupt test", 0, flag);

	//	GCM AES-192, two-block message

	rvkat_gethex(k, sizeof(k),
		"165C4AA5D78EE15F297D5D2EAE39EAAC"
		"3480FC50A6D9A98E");
	rvkat_gethex(iv, sizeof(iv),
		"0E321E714C4A262350FC50FC");
	mlen = rvkat_gethex(pt, sizeof(pt),
		"5AFA41EFE94C0193FC9FE62FD6CFACC8"
		"868725AB4965A5C9132D74179F0AEE72");
	clen = mlen + 16;
	memset(ct, 0, clen);
	aes192_enc_gcm(ct, pt, mlen, k, iv);
	fail += rvkat_chkhex("GCM AES-192", ct, clen,
		"5AB8AC904E7D4A627EE327B4629B6863"
		"19936ABC709E8C0FB6817CB16D0C4F76"
		"62BFEA782D6A05CD04030C433639B969");

	memset(xt, 0, mlen);
	flag = aes192_dec_vfy_gcm(xt, ct, clen, k, iv) ||
		memcmp(xt, pt, mlen) != 0;

	ct[RAND_CNST % clen] ^= 1 << (RAND_CNST & 7);	//	corrupt

	flag |= !(aes192_dec_vfy_gcm(xt, ct, clen, k, iv) ||
			  memcmp(xt, pt, mlen) != 0);
	fail += rvkat_chkret("GCM AES-192 verify / corrupt test", 0, flag);

	//	GCM AES-256, 51-byte message

	rvkat_gethex(k, sizeof(k),
		"1FDED32D5999DE4A76E0F8082108823A"
		"EF60417E1896CF4218A2FA90F632EC8A");
	rvkat_gethex(iv, sizeof(iv),
		"1F3AFA4711E9474F32E70462");
	mlen = rvkat_gethex(pt, sizeof(pt),
		"06B2C75853DF9AEB17BEFD33CEA81C63"
		"0B0FC53667FF45199C629C8E15DCE41E"
		"530AA792F796B8138EEAB2E86C7B7BEE"
		"1D40B0");
	clen = mlen + 16;
	memset(ct, 0, clen);
	aes256_enc_gcm(ct, pt, mlen, k, iv);
	fail += rvkat_chkhex("GCM AES-256", ct, clen,
		"91FBD061DDC5A7FCC9513FCDFDC9C3A7"
		"C5D4D64CEDF6A9C24AB8A77C36EEFBF1"
		"C5DC00BC50121B96456C8CD8B6FF1F8B"
		"3E480F"
		"30096D340F3D5C42D82A6F475DEF23EB");
	memset(xt, 0, mlen);
	flag = aes256_dec_vfy_gcm(xt, ct, clen, k, iv) ||
		memcmp(xt, pt, mlen) != 0;

	ct[RAND_CNST % clen] ^= 1 << (RAND_CNST & 7);	//	corrupt

	flag |= !(aes256_dec_vfy_gcm(xt, ct, clen, k, iv) ||
			  memcmp(xt, pt, mlen) != 0);
	fail += rvkat_chkret("GCM AES-256 verify / corrupt test", 0, flag);

	return fail;
}

//	GCM implementation tests

int test_gcm()
{
	int fail = 0;

#ifdef RVINTRIN_RV64
	rvkat_info("=== GCM using ghash_mul_rv64() ===");
	ghash_rev = ghash_rev_rv64;			//	set UUT = ghash_mul_rv64
	ghash_mul = ghash_mul_rv64;
	fail += test_gcm_tv();
#endif

#ifdef RVINTRIN_RV32
	rvkat_info("=== GCM using ghash_mul_rv32() ===");
	ghash_rev = ghash_rev_rv32;			//	set UUT = ghash_mul_rv32
	ghash_mul = ghash_mul_rv32;
	fail += test_gcm_tv();
#endif

#ifdef RVINTRIN_RV32
	rvkat_info("=== GCM using ghash_mul_rv32_kar() ===");
	ghash_rev = ghash_rev_rv32;			//	set UUT = ghash_mul_rv32_kar
	ghash_mul = ghash_mul_rv32_kar;
	fail += test_gcm_tv();
#endif

	return fail;
}

