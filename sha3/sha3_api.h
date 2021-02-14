//	sha3_api.h
//	2020-03-02	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	FIPS 202: SHA-3 hash and SHAKE eXtensible Output Functions (XOF)

#ifndef _SHA3_API_H_
#define _SHA3_API_H_

#include <stddef.h>
#include <stdint.h>

//	compute a SHA-3 hash "md" of "mdlen" bytes from data in "in"
void *sha3(uint8_t * md, int mdlen, const void *in, size_t inlen);

typedef struct {							//	state context
	union {									//	aligned:
		uint8_t b[200];						//	8-bit bytes
		uint64_t d[25];						//	64-bit words
	} st;
	int pt, rsiz, mdlen;					//	(don't overflow)
} sha3_ctx_t;

//	function pointer to the permutation
extern void (*sha3_keccakp)(void *);

//	which is set to point to an external function, one of:
void sha3_f1600_rvb32(void *);				//	sha3_f1600_rvb32.c
void sha3_f1600_rvb64(void *);				//	sha3_f1600_rvb64.c
//void ref_keccakp(void *);					//	ref_keccakp.c ("reference")

//	incremental interfece
void sha3_init(sha3_ctx_t * c, int mdlen);	//	mdlen = hash output in bytes
void sha3_update(sha3_ctx_t * c, const void *data, size_t len);
void sha3_final(uint8_t * md, sha3_ctx_t * c);	// digest goes to md

//	SHAKE128 and SHAKE256 extensible-output functions
#define shake128_init(c) sha3_init(c, 16)
#define shake256_init(c) sha3_init(c, 32)
#define shake_update sha3_update

//	add padding (call once after calls to shake_update() are done
void shake_xof(sha3_ctx_t * c);

//	squeeze output (can call repeat)
void shake_out(uint8_t * out, size_t len, sha3_ctx_t * c);

#endif	//	_SHA3_API_H_
