//	sha3_test.c
//	2020-03-09	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Unit tests for FIPS 202 -- SHA-3 HASH and SHAKE XOF.

#include "rvkintrin.h"
#include "test_rvkat.h"
#include "sha3/sha3_api.h"

#include <string.h>

//	Test the Keccak-p[1600,24](S) permutation.

int test_keccakp_tv()
{
	int i;
	uint8_t st[200];
	int fail = 0;

	memset(st, 0, sizeof(st));
	for (i = 0; i < 25; i++) {
		st[8 * i] = i;
	}
	sha3_keccakp(st);

	fail += rvkat_chkhex("KECCAK-P", st, sizeof(st),
		"1581ED5252B07483009456B676A6F71D7D79518A4B1965F7450576D1437B4720"
		"6A60F6F3A48B5FD193D48D7C4F14D7A13FFD38519693D130BEE31B9572947E48"
		"5A7ADACB58A8F30C887FB19B384EE52F8F269F0DDE38730B7F6D258BF5DFEF55"
		"6A3E2CEB943E35C8111F908C94F62A2EA69D30CA0CDE73E8E2314D946CC2AFF7"
		"D715C48C80EAF5A0CFD83E7E4331F55321D2A4433B1F7F7785E999B43CA60CFD"
		"3023D1C5C055C0D4DFA7E0A68AE52FA7A348997C93F51A42880834713010165E"
		"334A7E293AF453D1");

	return fail;
}

//	Simple test for SHA-3.

int test_sha3_tv()
{
	//	message / digest pairs

	const char *sha3_tv[][3] = {
		{ "SHA3-224",						//	corner case with 0-length message
		 "",
		 "6B4E03423667DBB73B6E15454F0EB1ABD4597F9A1B078E3F5B5A6BC7" },
		{ "SHA3-256",						//	short message
		 "C178CE0F720A6D73C6CF1CAA905EE724D5BA941C2E2628136E3AAD7D853733BA",
		 "64537B87892835FF0963EF9AD5145AB4CFCE5D303A0CB0415B3B03F9D16E7D6B" },
		{ "SHA3-384",						//	exact block size
		 "E35780EB9799AD4C77535D4DDB683CF33EF367715327CF4C4A58ED9CBDCDD486"
		 "F669F80189D549A9364FA82A51A52654EC721BB3AAB95DCEB4A86A6AFA93826D"
		 "B923517E928F33E3FBA850D45660EF83B9876ACCAFA2A9987A254B137C6E140A"
		 "21691E1069413848",
		 "D1C0FA85C8D183BEFF99AD9D752B263E286B477F79F0710B0103170173978133"
		 "44B99DAF3BB7B1BC5E8D722BAC85943A" },
		{ "SHA3-512",						//	multiblock message
		 "3A3A819C48EFDE2AD914FBF00E18AB6BC4F14513AB27D0C178A188B61431E7F5"
		 "623CB66B23346775D386B50E982C493ADBBFC54B9A3CD383382336A1A0B2150A"
		 "15358F336D03AE18F666C7573D55C4FD181C29E6CCFDE63EA35F0ADF5885CFC0"
		 "A3D84A2B2E4DD24496DB789E663170CEF74798AA1BBCD4574EA0BBA40489D764"
		 "B2F83AADC66B148B4A0CD95246C127D5871C4F11418690A5DDF01246A0C80A43"
		 "C70088B6183639DCFDA4125BD113A8F49EE23ED306FAAC576C3FB0C1E256671D"
		 "817FC2534A52F5B439F72E424DE376F4C565CCA82307DD9EF76DA5B7C4EB7E08"
		 "5172E328807C02D011FFBF33785378D79DC266F6A5BE6BB0E4A92ECEEBAEB1",
		 "6E8B8BD195BDD560689AF2348BDC74AB7CD05ED8B9A57711E9BE71E9726FDA45"
		 "91FEE12205EDACAF82FFBBAF16DFF9E702A708862080166C2FF6BA379BC7FFC2" }
	};

	size_t i, mdlen, inlen;
	uint8_t md[64], in[256];
	int fail = 0;

	for (i = 0; i < 4; i++) {
		memset(in, 0, sizeof(in));
		memset(md, 0, sizeof(md));
		inlen = rvkat_gethex(in, sizeof(in), sha3_tv[i][1]);
		mdlen = strlen(sha3_tv[i][2]) / 2;

		sha3(md, mdlen, in, inlen);
		fail += rvkat_chkhex(sha3_tv[i][0], md, mdlen, sha3_tv[i][2]);
	}

	return fail;
}

//	A test for SHAKE128 and SHAKE256.

int test_shake_tv()
{
	//	Test vectors have bytes 480..511 of XOF output for given inputs.
	//	From http://csrc.nist.gov/groups/ST/toolkit/examples.html#aHashing

	const char *shake_tv[4][2] = {
		{ "SHAKE128",						// SHAKE128, message of length 0
		"43E41B45A653F2A5C4492C1ADD544512DDA2529833462B71A41A45BE97290B6F" },
		{ "SHAKE256",						// SHAKE256, message of length 0
		 "AB0BAE316339894304E35877B0C28A9B1FD166C796B9CC258A064A8F57E27F2A" },
		{ "SHAKE128",						// SHAKE128, 1600-bit test pattern
		 "44C9FB359FD56AC0A9A75A743CFF6862F17D7259AB075216C0699511643B6439" },
		{ "SHAKE256",						// SHAKE256, 1600-bit test pattern
		 "6A1A9D7846436E4DCA5728B6F760EEF0CA92BF0BE5615E96959D767197A0BEEB" }
	};


	int i, j, fail;
	sha3_ctx_t sha3;
	uint8_t md[32], in[256];

	fail = 0;

	//	simple initial output tests

	shake128_init(&sha3);
	shake_update(&sha3, in, rvkat_gethex(in, sizeof(in), "7216A825029DA1"));
	shake_xof(&sha3);
	shake_out(md, 16, &sha3);
	fail += rvkat_chkhex("SHAKE128", md, 16,
		"9DE6FFACF3E59693A3DE81B02F7DB77A");

	shake256_init(&sha3);
	shake_update(&sha3, in, rvkat_gethex(in, sizeof(in),
		"FDBFF9BF3FB910A92D25651EBBFBA365"));
	shake_xof(&sha3);
	shake_out(md, 32, &sha3);
	fail += rvkat_chkhex("SHAKE256", md, 32,
		"89F2373E131A899B4BA27F6DA606716A5E289FD530AE066BB8B11DC023DACBD6");

	memset(in, 0xA3, 200);					// 1600-bit test pattern

	for (i = 0; i < 4; i++) {

		if ((i & 1) == 0) {					// test each twice
			shake128_init(&sha3);
		} else {
			shake256_init(&sha3);
		}
		if (i >= 2)
			shake_update(&sha3, in, 200);
		shake_xof(&sha3);					// switch to extensible output

		for (j = 0; j < 512; j += 32)		// output. discard bytes 0..479
			shake_out(md, 32, &sha3);

		// compare to reference

		fail += rvkat_chkhex(shake_tv[i][0], md, 32, shake_tv[i][1]);
	}

	return fail;
}

//	FIPS 202: algorithm tests

int test_sha3()
{
	int fail = 0;

#ifdef RVKINTRIN_RV32
	rvkat_info("=== SHA3 using sha3_f1600_rvb32() ===");
	sha3_keccakp = sha3_f1600_rvb32;
	fail += test_keccakp_tv();
	fail += test_sha3_tv();
	fail += test_shake_tv();
#endif

#ifdef RVKINTRIN_RV64
	rvkat_info("=== SHA3 using sha3_f1600_rvb64() ===");
	sha3_keccakp = sha3_f1600_rvb64;
	fail += test_keccakp_tv();
	fail += test_sha3_tv();
	fail += test_shake_tv();
#endif

	return fail;
}
