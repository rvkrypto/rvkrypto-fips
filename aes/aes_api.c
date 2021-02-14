//	aes_api.c
//	2020-04-23	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	AES 128/192/256 block encryption and decryption

#include "aes_api.h"
#include "aes_rvk32.h"
#include "test_rvkat.h"

//	defaults

static void aes_key_undef(uint32_t * rk, const uint8_t * key)
{
	(void) rk;
	(void) key;

	rvkat_info("undefined pointer: aes_key_undef()");
}

static void aes_ciph_undef(uint8_t * d, const uint8_t * s, const uint32_t * rk)
{
	(void) d;
	(void) s;
	(void) rk;

	rvkat_info("undefined pointer: aes_ciph_undef()");
}

//	== Externally visible pointers ==

//	Set encryption key

void (*aes128_enc_key)(uint32_t rk[AES128_RK_WORDS],
					   const uint8_t key[16]) = aes_key_undef;

void (*aes192_enc_key)(uint32_t rk[AES192_RK_WORDS],
					   const uint8_t key[24]) = aes_key_undef;

void (*aes256_enc_key)(uint32_t rk[AES256_RK_WORDS],
					   const uint8_t key[32]) = aes_key_undef;

//	Encrypt a block


void (*aes128_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[AES128_RK_WORDS]) = aes_ciph_undef;

void (*aes192_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[AES192_RK_WORDS]) = aes_ciph_undef;

void (*aes256_enc_ecb)(uint8_t ct[16], const uint8_t pt[16],
					   const uint32_t rk[AES256_RK_WORDS]) = aes_ciph_undef;

//	Set decryption key

void (*aes128_dec_key)(uint32_t rk[AES128_RK_WORDS],
					   const uint8_t key[16]) = aes_key_undef;
void (*aes192_dec_key)(uint32_t rk[AES192_RK_WORDS],
					   const uint8_t key[24]) = aes_key_undef;
void (*aes256_dec_key)(uint32_t rk[AES256_RK_WORDS],
					   const uint8_t key[32]) = aes_key_undef;

//	Decrypt a block

void (*aes128_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[AES128_RK_WORDS]) = aes_ciph_undef;

void (*aes192_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[AES192_RK_WORDS]) = aes_ciph_undef;

void (*aes256_dec_ecb)(uint8_t pt[16], const uint8_t ct[16],
					   const uint32_t rk[AES256_RK_WORDS]) = aes_ciph_undef;
