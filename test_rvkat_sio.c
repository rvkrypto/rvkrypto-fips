//	test_rvkat_sio.c
//	2021-02-18	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== functions to facilitate simple startup tests

#include "rvkintrin.h"
#include "test_rvkat.h"

//	RVK_ALGTEST_VERBOSE_SIO will use generic sio for output, replace
//	with what is suitable for your target.

#if 1
//	fancy standard library
#include <stdio.h>
#define sio_putc(c) fputc(c, stdout)
#define sio_puts(s)	fputs(s, stdout)
#define	sio_put_dec(x) fprintf(stdout, "%d", (int) (x))
#else
//	my bare metal code
#include "sio_generic.h"
#endif

//	print hexadecimal "data", length "len", with label "lab"

void rvkat_hexout(const char *lab, const void *data, size_t len)
{
#ifdef RVK_ALGTEST_VERBOSE_SIO
	const char hex[] = "0123456789ABCDEF";
	size_t i;
	uint8_t x;
	
	sio_puts("[TEST] ");
	sio_puts(lab);
	sio_putc(' ');
	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		sio_putc(hex[(x >> 4) & 0xF]);
		sio_putc(hex[x & 0xF]);
	}
	sio_putc('\n');
#else
	(void) lab;								//	suppress warning
	(void) data;
	(void) len;
#endif
}

//	print information

void rvkat_info(const char *info)
{
#ifdef RVK_ALGTEST_VERBOSE_SIO
	sio_puts("[INFO] ");
	sio_puts(info);
	sio_putc('\n');
#else
	(void) info;
#endif
}

//	(internal) single hex digit

static int rvkat_hexdigit(char ch)
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
		h = rvkat_hexdigit(str[2 * i]);
		if (h < 0)
			return i;
		l = rvkat_hexdigit(str[2 * i + 1]);
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
		if (rvkat_hexdigit(ref[2 * i]) != ((x >> 4) & 0xF) ||
			rvkat_hexdigit(ref[2 * i + 1]) != (x & 0x0F)) {
			fail = 1;
			break;
		}
	}

#ifdef RVK_ALGTEST_VERBOSE_SIO
	if (fail) {
		sio_puts("[FAIL]");
	} else {
		sio_puts("[PASS]");	
	}
	sio_putc(' ');
	sio_puts(lab);
	sio_putc(' ');
	sio_puts(ref);
	sio_putc('\n');
#endif

	if (fail) {
		rvkat_hexout(lab, data, len);
	}

	return fail;
}

//	boolean return value check

int rvkat_chkret(const char *lab, int want, int have)
{
#ifdef RVK_ALGTEST_VERBOSE_SIO
	if (want != have) {
		sio_puts("[FAIL]");
	} else {
		sio_puts("[PASS]");	
	}
	sio_putc(' ');
	sio_puts(lab);
	sio_puts(" | WANT= ");
	sio_put_dec(want);
	sio_puts("  HAVE= ");
	sio_put_dec(have);
	sio_putc('\n');	
#else
	(void) lab;
#endif
	return want != have ? 1 : 0;
}
