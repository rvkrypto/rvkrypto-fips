//	gcm_api.c
//	2020-03-21	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	A basic (very limited!) AES-GCM interface for testing purposes.

#include <string.h>

#include "riscv_crypto.h"
#include "test_rvkat.h"
#include "rv_endian.h"
#include "aes/aes_api.h"
#include "gcm_api.h"
#include "gcm_gfmul.h"

static void ghash_rev_undef(gf128_t *x)
{
	(void) x;
	rvkat_info("undefined pointer: ghash_rev_undef()");
}

static void ghash_mul_undef(gf128_t *x, const gf128_t *y, const gf128_t *z)
{
	(void) x;
	(void) y;
	(void) z;
	rvkat_info("undefined pointer: ghash_mul_undef()");
}

//	function pointers are here

void (*ghash_rev)(gf128_t *) = ghash_rev_undef;
void (*ghash_mul)(gf128_t *, const gf128_t *, const gf128_t *) =
	ghash_mul_undef;


//	the same "body" for encryption/decryption and various key lengths

static void aes_gcm_body(uint8_t * dst, uint8_t tag[16],
						 const uint8_t * src, size_t len,
						 const uint8_t iv[12], const uint32_t rk[],
						 void (*enc_ecb)(uint8_t * ct, const uint8_t * pt,
							const uint32_t * rk), int enc_flag)
{
	size_t i, ctr;
	gf128_t b, c, z, h, t, p;

	h.d[0] = 0;								//	h = AES_k(0)
	h.d[1] = 0;
	enc_ecb(h.b, h.b, rk);
	ghash_rev(&h);

	ctr = 0;								//	counter value
	memcpy(p.b, iv, 12);					//	J0
	p.w[3] = __builtin_bswap32(++ctr);		//	big-endian counter
	enc_ecb(t.b, p.b, rk);					//	first AES_k(IV | 1) for tag

	z.d[0] = 0;								//	initialize GHASH result
	z.d[1] = 0;

	if (enc_flag) {							//	== encrypt / generate tag ==

		i = len;
		while (i >= 16) {					//	full block
			p.w[3] = __builtin_bswap32(++ctr);
			enc_ecb(c.b, p.b, rk);
			memcpy(b.b, src, 16);			//	load plaintext
			c.d[0] ^= b.d[0];
			c.d[1] ^= b.d[1];
			memcpy(dst, c.b, 16);			//	store ciphertext
			ghash_mul(&z, &c, &h);			//	GHASH the block
			src += 16;
			dst += 16;
			i -= 16;
		}

		if (i > 0) {						//	partial block
			p.w[3] = __builtin_bswap32(++ctr);
			enc_ecb(c.b, p.b, rk);
			memcpy(b.b, src, i);			//	load plaintext
			c.d[0] ^= b.d[0];
			c.d[1] ^= b.d[1];
			memcpy(dst, c.b, i);
			memset(&c.b[i], 0, 16 - i);		//	zero pad input
			ghash_mul(&z, &c, &h);			//	GHASH last block
		}

	} else {								//	== decrypt / verify tag ==

		i = len;
		while (i >= 16) {					//	full block
			p.w[3] = __builtin_bswap32(++ctr);
			enc_ecb(b.b, p.b, rk);
			memcpy(c.b, src, 16);			//	load ciphertext
			b.d[0] ^= c.d[0];
			b.d[1] ^= c.d[1];
			memcpy(dst, b.b, 16);			//	store plaintext
			ghash_mul(&z, &c, &h);			//	GHASH the block
			src += 16;
			dst += 16;
			i -= 16;
		}

		if (i > 0) {						//	partial block
			p.w[3] = __builtin_bswap32(++ctr);
			enc_ecb(b.b, p.b, rk);
			memcpy(c.b, src, i);
			b.d[0] ^= c.d[0];
			b.d[1] ^= c.d[1];
			memcpy(dst, b.b, i);
			memset(&c.b[i], 0, 16 - i);		//	zero pad input
			ghash_mul(&z, &c, &h);			//	GHASH last block
		}
	}

	c.d[0] = 0;								//	pad with bit length
	c.w[2] = __builtin_bswap32(len >> 29);			//	"bswap"
	c.w[3] = __builtin_bswap32(len << 3);
	ghash_mul(&z, &c, &h);					//	last GHASH block
	ghash_rev(&z);							//	flip result bits
	t.d[0] = t.d[0] ^ z.d[0];				//	XOR with AES_k(IV | 1)
	t.d[1] = t.d[1] ^ z.d[1];
	memcpy(tag, t.b, 16);					//	write tag
}

//	verify it

static int aes_gcm_vfy(uint8_t * m,
					   const uint8_t * c, size_t clen,
					   const uint8_t iv[12], const uint32_t rk[],
					   void (*enc_ecb)(uint8_t * ct, const uint8_t * pt,
									   const uint32_t * rk))
{
	size_t i;
	uint8_t tag[16], x;

	if (clen < 16)
		return -1;

	aes_gcm_body(m, tag, c, clen - 16, iv, rk, enc_ecb, 0);
	x = 0;
	for (i = 0; i < 16; i++) {
		x |= tag[i] ^ c[clen - 16 + i];
	}

	return x == 0 ? 0 : 1;
}

//	AES128-GCM

void aes128_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES128_RK_WORDS];

	aes128_enc_key(rk, key);
	aes_gcm_body(c, c + mlen, m, mlen, iv, rk, aes128_enc_ecb, 1);
}

int aes128_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES128_RK_WORDS];

	aes128_enc_key(rk, key);
	return aes_gcm_vfy(m, c, clen, iv, rk, aes128_enc_ecb);
}


//	AES192-GCM

void aes192_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES192_RK_WORDS];

	aes192_enc_key(rk, key);
	aes_gcm_body(c, c + mlen, m, mlen, iv, rk, aes192_enc_ecb, 1);
}

int aes192_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES192_RK_WORDS];

	aes192_enc_key(rk, key);
	return aes_gcm_vfy(m, c, clen, iv, rk, aes192_enc_ecb);
}

//	AES256-GCM

void aes256_enc_gcm(uint8_t * c, const uint8_t * m, size_t mlen,
					const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES256_RK_WORDS];

	aes256_enc_key(rk, key);
	aes_gcm_body(c, c + mlen, m, mlen, iv, rk, aes256_enc_ecb, 1);
}

int aes256_dec_vfy_gcm(uint8_t * m, const uint8_t * c, size_t clen,
					   const uint8_t * key, const uint8_t iv[12])
{
	uint32_t rk[AES256_RK_WORDS];

	aes256_enc_key(rk, key);
	return aes_gcm_vfy(m, c, clen, iv, rk, aes256_enc_ecb);
}
