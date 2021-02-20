//	test_rvkat.h
//	2020-03-07	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	functions to facilitate simple algorithm self tests

//	RVK_ALGTEST_VERBOSE_SIO will use stdio for output, replace
//	with what is suitable for your target.

#ifndef _TEST_RVKAT_H_
#define _TEST_RVKAT_H_

#include <stdint.h>
#include <stddef.h>

//	print information
void rvkat_info(const char *info);

//	print hexadecimal "data", length "len", with label "lab"
void rvkat_hexout(const char *lab, const void *data, size_t len);

//	read a hex string of "maxbytes", return byte length
size_t rvkat_gethex(uint8_t *buf, size_t maxbytes, const char *str);

//	check "data" of "len" bytes against a hexadecimal test vector "ref"
int rvkat_chkhex(const char *lab, const void *data, size_t len, const char *ref);

//	boolean return value check
int rvkat_chkret(const char *lab, int want, int have);

#endif	//	 _TEST_RVKAT_H_
