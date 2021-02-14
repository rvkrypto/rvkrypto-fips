//	test_rvkat.c
//	2020-03-07	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	=== functions to facilitate simple startup tests

//	RVK_ALGTEST_VERBOSE_STDIO will use stdio for output, replace
//	with what is suitable for your target.

#include "rvkintrin.h"
#include "test_rvkat.h"

#ifdef RVK_ALGTEST_VERBOSE_STDIO
#include <stdio.h>
#endif

//	print hexadecimal "data", length "len", with label "lab"

void rvkat_hexout(const char *lab, const void *data, size_t len)
{
#ifdef RVK_ALGTEST_VERBOSE_STDIO
	size_t i;
	uint8_t x;

	printf("[TEST] %s ", lab);
	const char hex[] = "0123456789ABCDEF";

	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		putchar(hex[(x >> 4) & 0xF]);
		putchar(hex[x & 0xF]);
	}

	putchar('\n');
#else
	(void) lab;								//	suppress warning
	(void) data;
	(void) len;
#endif
}

//	print information

void rvkat_info(const char *info)
{
#ifdef RVK_ALGTEST_VERBOSE_STDIO
	printf("[INFO] %s\n", info);
#else
	(void) info;
#endif
}

//	(internal) single hex digit

static int rvkat_hexoutdigit(char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	return -1;
}

//	read a hex string of "maxbytes", return byte length

size_t rvkat_gethex(uint8_t * buf, size_t maxbytes, const char *str)
{
	size_t i;
	int h, l;

	for (i = 0; i < maxbytes; i++) {
		h = rvkat_hexoutdigit(str[2 * i]);
		if (h < 0)
			return i;
		l = rvkat_hexoutdigit(str[2 * i + 1]);
		if (l < 0)
			return i;
		buf[i] = (h << 4) + l;
	}

	return i;
}

//	check "data" of "len" bytes against a hexadecimal test vector "ref"

int rvkat_chkhex(const char *lab, const void *data, size_t len, const char *ref)
{
	size_t i;
	uint8_t x;
	int fail = 0;

	//	check equivalence
	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		if (rvkat_hexoutdigit(ref[2 * i]) != ((x >> 4) & 0xF) ||
			rvkat_hexoutdigit(ref[2 * i + 1]) != (x & 0x0F)) {
			fail = 1;
			break;
		}
	}

	if (i == len && rvkat_hexoutdigit(ref[2 * len]) >= 0) {
		fail = 1;
	}

#ifdef RVK_ALGTEST_VERBOSE_STDIO
	printf("[%s] %s %s\n", fail ? "FAIL" : "PASS", lab, ref);
#endif

	if (fail) {
		rvkat_hexout(lab, data, len);
	}

	return fail;
}

//	boolean return value check

int rvkat_chkret(const char *lab, int want, int have)
{
#ifdef RVK_ALGTEST_VERBOSE_STDIO
	printf("[%s] %s | WANT= %d	HAVE= %d\n",
		   want != have ? "FAIL" : "PASS", lab, want, have);
#else
	(void) lab;
#endif
	return want != have ? 1 : 0;
}
