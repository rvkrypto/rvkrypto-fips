//	test_rvkat_sio.c
//	2021-02-18	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2021, PQShield Ltd. All rights reserved.

//	=== functions to facilitate simple startup tests

#include "rvkintrin.h"
#include "test_rvkat.h"

#ifdef RVK_ALGTEST_VERBOSE_SIO

//	=== verbose versions

//	(internal) fail or pass

static void rvkat_failpass(int fail)
{
	if (fail) {
		sio_puts("[FAIL] ");
	} else {
		sio_puts("[PASS] ");
	}
}

//	(internal) a single hex digit

static inline void rvkat_out_hexdigit(unsigned x)
{
	x &= 0xF;
	if (x < 10) {
		sio_putc('0' + x);
	} else {
		sio_putc('A' - 10 + x);
	}
}
//	print a space ' ' and hexademical unsigned long without a label

void rvkat_hexu32(uint32_t x)
{
	int i;

	sio_putc(' ');
	for (i = 28; i >= 0; i -= 4) {
		rvkat_out_hexdigit((unsigned) (x >> i));
	}
}

void rvkat_hexu64(uint64_t x)
{
	int i;

	sio_putc(' ');
	for (i = 60; i >= 0; i -= 4) {
		rvkat_out_hexdigit((unsigned) (x >> i));
	}
}

//	just the hex string

static void rvkat_hexdata(const void *data, size_t len)
{

	size_t i;
	uint8_t x;

	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		rvkat_out_hexdigit(x >> 4);
		rvkat_out_hexdigit(x);
	}
}

//	boolean return value check (print decimal)

int rvkat_chkret(const char *lab, int want, int have)
{
	int fail = (want == have) ? 0 : 1;

	rvkat_failpass(fail);
	sio_puts(lab);
	sio_puts(" | WANT= ");
	sio_put_dec(want);
	sio_puts("	HAVE= ");
	sio_put_dec(have);
	sio_putc('\n');
	return fail;
}

//	boolean long return value check (print hex)

int rvkat_chku32(const char *lab, uint32_t want, uint32_t have)
{
	int fail = (want == have) ? 0 : 1;

	rvkat_failpass(fail);
	sio_puts(lab);
	sio_puts(" | WANT=");
	rvkat_hexu32(want);
	sio_puts("	HAVE=");
	rvkat_hexu32(have);
	sio_putc('\n');

	return fail;
}

int rvkat_chku64(const char *lab, uint64_t want, uint64_t have)
{
	int fail = (want == have) ? 0 : 1;

	rvkat_failpass(fail);
	sio_puts(lab);
	sio_puts(" | WANT=");
	rvkat_hexu64(want);
	sio_puts("	HAVE=");
	rvkat_hexu64(have);
	sio_putc('\n');

	return fail;
}

//	print hexadecimal "data", length "len", with label "lab"

void rvkat_hexout(const char *lab, const void *data, size_t len)
{
	sio_puts("[TEST] ");
	sio_puts(lab);
	sio_putc(' ');
	rvkat_hexdata(data, len);
	sio_putc('\n');
}

//	print information

void rvkat_info(const char *info)
{
	sio_puts("[INFO] ");
	sio_puts(info);
	sio_putc('\n');
}

#else	//	RVK_ALGTEST_VERBOSE_SIO

//	(silent) boolean return value checks

int rvkat_chkret(const char *lab, int want, int have)
{
	(void) lab;
	return want != have ? 1 : 0;
}

int rvkat_chku32(const char *lab, uint32_t want, uint32_t have)
{
	(void) lab;
	return want != have ? 1 : 0;
}

int rvkat_chku64(const char *lab, uint64_t want, uint64_t have)
{
	(void) lab;
	return want != have ? 1 : 0;
}

//	(silent) inert stubs for information output

void rvkat_hexu32(uint32_t x)
{
	(void) x;
}

void rvkat_hexu64(uint64_t x)
{
	(void) x;
}

void rvkat_hexout(const char *lab, const void *data, size_t len)
{
	(void) lab;
	(void) data;
	(void) len;
}

void rvkat_info(const char *info)
{
	(void) info;
}

#endif

//	(internal) parse single hex digit

static int rvkat_parse_digit(char ch)
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
		h = rvkat_parse_digit(str[2 * i]);
		if (h < 0)
			return i;
		l = rvkat_parse_digit(str[2 * i + 1]);
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

#ifndef RVK_ALGTEST_VERBOSE_SIO
	(void) lab;
#endif

	//	check equivalence
	for (i = 0; i < len; i++) {
		x = ((const uint8_t *) data)[i];
		if (rvkat_parse_digit(ref[2 * i]) != ((x >> 4) & 0xF) ||
			rvkat_parse_digit(ref[2 * i + 1]) != (x & 0x0F)) {
			fail = 1;
			break;
		}
	}

#ifdef RVK_ALGTEST_VERBOSE_SIO
	rvkat_failpass(fail);
	sio_puts(lab);
	sio_putc(' ');
	rvkat_hexdata(data, len);
	sio_putc('\n');

	if (fail) {
		sio_puts("[WANT] ");
		sio_puts(lab);
		sio_putc(' ');
		sio_puts(ref);
		sio_putc('\n');
	}
#endif

	return fail;
}

