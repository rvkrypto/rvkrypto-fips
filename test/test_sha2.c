//	test_sha2.c
//	2020-03-09	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	Unit tests for FIPS 180-4 SHA-2 and FIPS 198 HMAC.

#include "riscv_crypto.h"
#include "test_rvkat.h"
#include "sha2/sha2_api.h"

//	SHA2-224/256 testvectors

int test_sha2_256_tv()
{
	//	Padding tests

	const char *sha256_tv[][2] = {
		{ "",
		 "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855" },
		{ "3EBFB06DB8C38D5BA037F1363E118550AAD94606E26835A01AF05078533CC25F"
		 "2F39573C04B632F62F68C294AB31F2A3E2A1A0D8C2BE51",
		 "6595A2EF537A69BA8583DFBF7F5BEC0AB1F93CE4C8EE1916EFF44A93AF5749C4" },
		{ "2D52447D1244D2EBC28650E7B05654BAD35B3A68EEDC7F8515306B496D75F3E7"
		 "3385DD1B002625024B81A02F2FD6DFFB6E6D561CB7D0BD7A",
		 "CFB88D6FAF2DE3A69D36195ACEC2E255E2AF2B7D933997F348E09F6CE5758360" },
		{ "5A86B737EAEA8EE976A0A24DA63E7ED7EEFAD18A101C1211E2B3650C5187C2A8"
		 "A650547208251F6D4237E661C7BF4C77F335390394C37FA1A9F9BE836AC28509",
		 "42E61E174FBB3897D6DD6CEF3DD2802FE67B331953B06114A65C772859DFC1AA" },
		{ "451101250EC6F26652249D59DC974B7361D571A8101CDFD36ABA3B5854D3AE08"
		 "6B5FDD4597721B66E3C0DC5D8C606D9657D0E323283A5217D1F53F2F284F57B8"
		 "5C8A61AC8924711F895C5ED90EF17745ED2D728ABD22A5F7A13479A462D71B56"
		 "C19A74A40B655C58EDFE0A188AD2CF46CBF30524F65D423C837DD1FF2BF462AC"
		 "4198007345BB44DBB7B1C861298CDF61982A833AFC728FAE1EDA2F87AA2C9480"
		 "858BEC",
		 "3C593AA539FDCDAE516CDF2F15000F6634185C88F505B39775FB9AB137A10AA2" },
		{ NULL, NULL }
	};

	uint8_t md[32], d[256];
	int fail = 0;
	int i;

	//	SHA2-256
	sha2_256(md, "abc", 3);
	fail += rvkat_chkhex("SHA2-256", md, 32,
				   "BA7816BF8F01CFEA414140DE5DAE2223"
				   "B00361A396177A9CB410FF61F20015AD");

	//	SHA2-224
	sha2_224(md, d, rvkat_gethex(d, sizeof(d), "10713B894DE4A734C0"));
	fail += rvkat_chkhex("SHA2-224", md, 28,
				   "03842600C86F5CD60C3A2147A067CB96"
				   "2A05303C3488B05CB45327BD");

	//	padding tests
	for (i = 0; sha256_tv[i][0] != NULL; i++) {
		sha2_256(md, d, rvkat_gethex(d, sizeof(d), sha256_tv[i][0]));
		fail += rvkat_chkhex("SHA2-256", md, 32, sha256_tv[i][1]);
	}

	return fail;
}

//	SHA2-384/512 test vectors

int test_sha2_512_tv()
{
	uint8_t md[64], d[256];
	size_t dlen;
	int fail = 0;

	//	SHA2-512
	sha2_512(md, "abc", 3);
	fail += rvkat_chkhex("SHA2-512", md, 64,
				   "DDAF35A193617ABACC417349AE204131"
				   "12E6FA4E89A97EA20A9EEEE64B55D39A"
				   "2192992A274FC1A836BA3C23A3FEEBBD"
				   "454D4423643CE80E2A9AC94FA54CA49F");

	//	SHA2-512
	sha2_512(md, "abcdefghbcdefghicdefghijdefghijk"
			 "efghijklfghijklmghijklmnhijklmno"
			 "ijklmnopjklmnopqklmnopqrlmnopqrs" "mnopqrstnopqrstu", 112);
	fail += rvkat_chkhex("SHA2-512", md, 64,
				   "8E959B75DAE313DA8CF4F72814FC143F"
				   "8F7779C6EB9F7FA17299AEADB6889018"
				   "501D289E4900F7E4331B99DEC4B5433A"
				   "C7D329EEB6DD26545E96E55B874BE909");

	//	SHA2-384
	sha2_384(md, "", 0);
	fail += rvkat_chkhex("SHA2-384", md, 48,
				   "38B060A751AC96384CD9327EB1B1E36A"
				   "21FDB71114BE07434C0CC7BF63F6E1DA"
				   "274EDEBFE76F65FBD51AD2F14898B95B");
	dlen = rvkat_gethex(d, sizeof(d),
				   "A04F390A9CC2EFFAD05DB80D9076A8D4"
				   "B6CC8BBA97B27B423670B290B8E69C2B"
				   "187230011C1481AC88D090F391546594"
				   "94DB5E410851C6E8B2B8A93717CAE760"
				   "37E0881978124FE7E1A0929D8891491F"
				   "4E99646CC94062DC82411FA66130EDA4"
				   "6560E75B98048236439465125E737B");
	sha2_384(md, d, dlen);
	fail += rvkat_chkhex("SHA2-384", md, 48,
				   "E7089D72945CEF851E689B4409CFB63D"
				   "135F0B5CDFB0DAC6C3A292DD70371AB4"
				   "B79DA1997D7992906AC7213502662920");

	return fail;
}

//	SHA2: algorithm tests

int test_sha2()
{
	int fail = 0;

	rvkat_info("=== SHA2-256 using sha2_cf256_rvk() ===");
	sha256_compress = sha2_cf256_rvk;
	fail += test_sha2_256_tv();

#ifdef RVKINTRIN_RV64
	rvkat_info("=== SHA2-512 using sha2_cf512_rvk64() ===");
	sha512_compress = sha2_cf512_rvk64;
	fail += test_sha2_512_tv();
#endif

#ifdef RVKINTRIN_RV32
	rvkat_info("=== SHA2-512 using sha2_cf512_rvk32() ===");
	sha512_compress = sha2_cf512_rvk32;
	fail += test_sha2_512_tv();
#endif

	return fail;
}
