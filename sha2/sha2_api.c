//	sha2_api.c
//	2020-03-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 180-4 SHA-2 hash code for testing purposes.
//	Typical MD/SHA type API interface.

#include "sha2_api.h"
#include "rv_endian.h"
#include "test_rvkat.h"

#include <string.h>

//	pointers to the compression functions

static void sha2_compress_undef(void *s)
{
	(void) s;
	rvkat_info("undefined pointer: sha2_compress_undef()");
}

void (*sha256_compress)(void *s) = &sha2_compress_undef;
void (*sha512_compress)(void *s) = &sha2_compress_undef;

//	SHA-224 initial values H0, Sect 5.3.2.

static const uint32_t sha2_224_h0[8] = {
	0xC1059ED8, 0x367CD507, 0x3070DD17,
	0xF70E5939, 0xFFC00B31, 0x68581511,
	0x64F98FA7, 0xBEFA4FA4
};

//	SHA-256 initial values H0, Sect 5.3.3.

static const uint32_t sha2_256_h0[8] = {
	0x6A09E667, 0xBB67AE85, 0x3C6EF372,
	0xA54FF53A, 0x510E527F, 0x9B05688C,
	0x1F83D9AB, 0x5BE0CD19
};

//	SHA-384 initial values H0, Sect 5.3.4.

static const uint64_t sha2_384_h0[8] = {
	0xCBBB9D5DC1059ED8ULL, 0x629A292A367CD507ULL, 0x9159015A3070DD17ULL,
	0x152FECD8F70E5939ULL, 0x67332667FFC00B31ULL, 0x8EB44A8768581511ULL,
	0xDB0C2E0D64F98FA7ULL, 0x47B5481DBEFA4FA4LL
};

//	SHA-512 initial values H0, Sect 5.3.5.

static const uint64_t sha2_512_h0[8] = {
	0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL, 0x3C6EF372FE94F82BULL,
	0xA54FF53A5F1D36F1ULL, 0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179LL
};

//	=== incremental interface (internal here) ===

typedef struct {
	uint32_t s[8 + 24];
	size_t i, len;
} sha256_t;

typedef struct {
	uint64_t s[8 + 24];
	size_t i, len;
} sha512_t;

typedef sha256_t sha224_t;
typedef sha512_t sha384_t;

//	shaNNN_init(ctx): Initialize context for hashing.
static inline void sha256_init_h0(sha256_t *sha, const uint32_t h0[8]);
#define sha256_init(sha) sha256_init_h0(sha, sha2_256_h0)
#define sha224_init(sha) sha256_init_h0(sha, sha2_224_h0)
static inline void sha512_init_h0(sha512_t *sha, const uint64_t h0[8]);
#define sha512_init(sha) sha512_init_h0(sha, sha2_512_h0)
#define sha384_init(sha) sha512_init_h0(sha, sha2_384_h0)

//	shaNNN_update(ctx, m, mlen): Include "m" of "mlen" bytes in hash.
static inline void sha256_update(sha256_t *sha, const uint8_t *m, size_t mlen);
#define sha224_update(sha, m, mlen) sha256_update(sha, m, mlen)
static inline void sha512_update(sha512_t *sha, const uint8_t *m, size_t mlen);
#define sha384_update(sha, m, mlen) sha512_update(sha, m, mlen)

//	shaNNN_final(ctx, h): Finalize hash to "h", and clear the state.
static inline void sha256_final_len(sha256_t *sha, uint8_t *h, size_t hlen);
#define sha256_final(sha, h) sha256_final_len(sha, h, 32)
#define sha224_final(sha, h) sha256_final_len(sha, h, 28)
static inline void sha512_final_len(sha512_t *sha, uint8_t *h, size_t hlen);
#define sha512_final(sha, h) sha512_final_len(sha, h, 64)
#define sha384_final(sha, h) sha512_final_len(sha, h, 48)


//	SHA2-256 initialize

void sha256_init_h0(sha256_t *sha, const uint32_t h0[8])
{
	size_t i;

	for (i = 0; i < 8; i++)	 //	 set H0 (IV)
		sha->s[i] = h0[i];
	sha->i = 0;
	sha->len = 0;
}

//	SHA2-256 process input

void sha256_update(sha256_t *sha, const uint8_t *m, size_t mlen)
{
	size_t l;
	uint8_t *mp = (uint8_t *)&sha->s[8];

	sha->len += mlen;
	l = 64 - sha->i;

	if (mlen < l) {
		memcpy(mp + sha->i, m, mlen);
		sha->i += mlen;
		return;
	}
	if (sha->i > 0) {
		memcpy(mp + sha->i, m, l);
		sha256_compress(sha->s);
		mlen -= l;
		m += l;
		sha->i = 0;
	}
	while (mlen >= 64) {
		memcpy(mp, m, 64);
		sha256_compress(sha->s);
		mlen -= 64;
		m += 64;
	}
	memcpy(mp, m, mlen);
	sha->i = mlen;
}

void sha256_final_len(sha256_t *sha, uint8_t *h, size_t hlen)
{
	uint8_t *mp = (uint8_t *)&sha->s[8];
	uint64_t x;
	size_t i;

	i = sha->i;	 // last data block
	mp[i++] = 0x80;
	if (i > 56) {
		memset(mp + i, 0x00, 64 - i);
		sha256_compress(sha->s);
		i = 0;
	}
	memset(mp + i, 0x00, 64 - i);  //	clear rest

	x = ((uint64_t)sha->len) << 3;	//	process length
	i = 64;
	while (x > 0) {
		mp[--i] = x & 0xFF;
		x >>= 8;
	}
	sha256_compress(sha->s);

	for (i = 0; i < hlen; i += 4)  //  store big endian output
		put32u_be(&h[i], sha->s[i / 4]);

	memset(sha, 0x00, sizeof(sha256_t));  //	clear it
}

//	SHA-224/256 public single-call interfaces

void sha2_224(uint8_t *h, const void *m, size_t mlen)
{
	sha256_t sha;

	sha224_init(&sha);
	sha224_update(&sha, m, mlen);
	sha224_final(&sha, h);
}

void sha2_256(uint8_t *h, const void *m, size_t mlen)
{
	sha256_t sha;

	sha256_init(&sha);
	sha256_update(&sha, m, mlen);
	sha256_final(&sha, h);
}

//	SHA-512 initialize

void sha512_init_h0(sha512_t *sha, const uint64_t h0[8])
{
	size_t i;

	for (i = 0; i < 8; i++)	 //	 set H0 (IV)
		sha->s[i] = h0[i];
	sha->i = 0;
	sha->len = 0;
}

//	take message input

void sha512_update(sha512_t *sha, const uint8_t *m, size_t mlen)
{
	size_t l;
	uint8_t *mp = (uint8_t *)&sha->s[8];

	sha->len += mlen;
	l = 128 - sha->i;

	if (mlen < l) {
		memcpy(mp + sha->i, m, mlen);
		sha->i += mlen;
		return;
	}
	if (sha->i > 0) {
		memcpy(mp + sha->i, m, l);
		sha512_compress(sha->s);
		mlen -= l;
		m += l;
		sha->i = 0;
	}
	while (mlen >= 128) {
		memcpy(mp, m, 128);
		sha512_compress(sha->s);
		mlen -= 128;
		m += 128;
	}
	memcpy(mp, m, mlen);
	sha->i = mlen;
}

void sha512_final_len(sha512_t *sha, uint8_t *h, size_t hlen)
{
	uint8_t *mp = (uint8_t *)&sha->s[8];
	uint64_t x;
	size_t i;

	i = sha->i;	 // last data block
	mp[i++] = 0x80;
	if (i > 112) {
		memset(mp + i, 0x00, 128 - i);
		sha512_compress(sha->s);
		i = 0;
	}
	memset(mp + i, 0x00, 128 - i);	//	clear rest

	x = ((uint64_t)sha->len) << 3;	//	process length
	i = 128;
	while (x > 0) {
		mp[--i] = x & 0xFF;
		x >>= 8;
	}
	sha512_compress(sha->s);

	for (i = 0; i < hlen; i += 8)  //  store big endian output
		put64u_be(&h[i], sha->s[i / 8]);

	memset(sha, 0x00, sizeof(sha512_t));  //	clear it
}

//	SHA-384/512 public single-call interfaces

void sha2_384(uint8_t *h, const void *m, size_t mlen)
{
	sha384_t sha;

	sha384_init(&sha);
	sha384_update(&sha, m, mlen);
	sha384_final(&sha, h);
}

void sha2_512(uint8_t *h, const void *m, size_t mlen)
{
	sha512_t sha;

	sha512_init(&sha);
	sha512_update(&sha, m, mlen);
	sha512_final(&sha, h);
}
