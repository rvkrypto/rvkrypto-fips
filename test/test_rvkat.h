//	test_rvkat.h
//	2020-03-07	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	functions to facilitate simple algorithm self tests

//	RVK_ALGTEST_VERBOSE_SIO will use stdio for output, replace
//	with what is suitable for your target.

#ifndef _TEST_RVKAT_H_
#define _TEST_RVKAT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>

//	=== TESTING === used in tests

//	read a hex string of "maxbytes", return byte length
size_t rvkat_gethex(uint8_t *buf, size_t maxbytes, const char *str);

//	check "data" of "len" bytes against a hexadecimal test vector "ref"
int rvkat_chkhex(const char *lab, const void *data, size_t len, const char *ref);

//	boolean return value check (integer -- print decimal)
int rvkat_chkret(const char *lab, int want, int have);

//	32-bit return value check (print hex)
int rvkat_chku32(const char *lab, uint32_t want, uint32_t have);

//	64-bit return value check (print hex)
int rvkat_chku64(const char *lab, uint64_t want, uint64_t have);

//	=== DEBUG ==  available for information / debug purposes only

//	print information
void rvkat_info(const char *info);

//	print hexadecimal "data", length "len", with label "lab"
void rvkat_hexout(const char *lab, const void *data, size_t len);

//	print a space ' ' and hexademical unsigned without a label
void rvkat_hexu32(uint32_t x);
void rvkat_hexu64(uint64_t x);

#ifdef __cplusplus
}
#endif

#endif	//	 _TEST_RVKAT_H_
