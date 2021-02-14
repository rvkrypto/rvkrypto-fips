//	sha3_api.c
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 202: SHA-3 hash and SHAKE eXtensible Output Functions (XOF)
//	Hash padding mode code for testing permutation implementations.

#include "sha3_api.h"
#include "test_rvkat.h"

//	These functions have not been optimized for performance -- they are
//	here just to facilitate testing of the permutation code implementations.

//	externally visible pointer to the permutation implementation

static void sha3_f1600_undef(void *s)
{
	(void) s;
	
	rvkat_info("undefined pointer: sha3_f1600_undef()");
}

void (*sha3_keccakp)(void *) = sha3_f1600_undef;

//	initialize the context for SHA3

void sha3_init(sha3_ctx_t * c, int mdlen)
{
	int i;

	for (i = 0; i < 25; i++)
		c->st.d[i] = 0;
	c->mdlen = mdlen;
	c->rsiz = 200 - 2 * mdlen;
	c->pt = 0;
}

//	update state with more data

void sha3_update(sha3_ctx_t * c, const void *data, size_t len)
{
	size_t i;
	int j;

	j = c->pt;
	for (i = 0; i < len; i++) {
		c->st.b[j++] ^= ((const uint8_t *) data)[i];
		if (j >= c->rsiz) {
			sha3_keccakp(c->st.d);
			j = 0;
		}
	}
	c->pt = j;
}

//	finalize and output a hash

void sha3_final(uint8_t * md, sha3_ctx_t * c)
{
	int i;

	c->st.b[c->pt] ^= 0x06;
	c->st.b[c->rsiz - 1] ^= 0x80;
	sha3_keccakp(c->st.d);

	for (i = 0; i < c->mdlen; i++) {
		md[i] = c->st.b[i];
	}
}

//	compute a SHA-3 hash "md" of "mdlen" bytes from data in "in"

void *sha3(uint8_t * md, int mdlen, const void *in, size_t inlen)
{
	sha3_ctx_t sha3;

	sha3_init(&sha3, mdlen);
	sha3_update(&sha3, in, inlen);
	sha3_final(md, &sha3);

	return md;
}

//	SHAKE128 and SHAKE256 extensible-output functionality

//	add padding (call once after calls to shake_update() are done

void shake_xof(sha3_ctx_t * c)
{
	c->st.b[c->pt] ^= 0x1F;
	c->st.b[c->rsiz - 1] ^= 0x80;
	sha3_keccakp(c->st.d);
	c->pt = 0;
}

//	squeeze output

void shake_out(uint8_t * out, size_t len, sha3_ctx_t * c)
{
	size_t i;
	int j;

	j = c->pt;
	for (i = 0; i < len; i++) {
		if (j >= c->rsiz) {
			sha3_keccakp(c->st.d);
			j = 0;
		}
		out[i] = c->st.b[j++];
	}
	c->pt = j;
}
