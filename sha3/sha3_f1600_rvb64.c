//	sha3_f1600_rvb64.c
//	2020-03-05	Markku-Juhani O. Saarinen <mjos@pqshield.com>
//	Copyright (c) 2020, PQShield Ltd. All rights reserved.

//	===	FIPS 202 Keccak permutation implementation for a 64-bit target.

#include "rvkintrin.h"

#ifdef RVKINTRIN_RV64

//	Keccak-p[1600,24](S) = Keccak-f1600(S)

void sha3_f1600_rvb64(void *s)
{
	//	round constants
	const uint64_t rc[24] = {
		0x0000000000000001LLU, 0x0000000000008082LLU, 0x800000000000808ALLU,
		0x8000000080008000LLU, 0x000000000000808BLLU, 0x0000000080000001LLU,
		0x8000000080008081LLU, 0x8000000000008009LLU, 0x000000000000008ALLU,
		0x0000000000000088LLU, 0x0000000080008009LLU, 0x000000008000000ALLU,
		0x000000008000808BLLU, 0x800000000000008BLLU, 0x8000000000008089LLU,
		0x8000000000008003LLU, 0x8000000000008002LLU, 0x8000000000000080LLU,
		0x000000000000800ALLU, 0x800000008000000ALLU, 0x8000000080008081LLU,
		0x8000000000008080LLU, 0x0000000080000001LLU, 0x8000000080008008LL
	};

	int i;
	uint64_t t, u, v, w;
	uint64_t sa, sb, sc, sd, se, sf, sg, sh, si, sj, sk, sl, sm,
		sn, so, sp, sq, sr, ss, st, su, sv, sw, sx, sy;

	//	load state, little endian, aligned

	uint64_t *vs = (uint64_t *) s;

	sa = vs[0];
	sb = vs[1];
	sc = vs[2];
	sd = vs[3];
	se = vs[4];
	sf = vs[5];
	sg = vs[6];
	sh = vs[7];
	si = vs[8];
	sj = vs[9];
	sk = vs[10];
	sl = vs[11];
	sm = vs[12];
	sn = vs[13];
	so = vs[14];
	sp = vs[15];
	sq = vs[16];
	sr = vs[17];
	ss = vs[18];
	st = vs[19];
	su = vs[20];
	sv = vs[21];
	sw = vs[22];
	sx = vs[23];
	sy = vs[24];

	//	iteration

	for (i = 0; i < 24; i++) {

		//	Theta

		u = sa ^ sf ^ sk ^ sp ^ su;
		v = sb ^ sg ^ sl ^ sq ^ sv;
		w = se ^ sj ^ so ^ st ^ sy;
		t = w ^ _rv64_ror(v, 63);
		sa = sa ^ t;
		sf = sf ^ t;
		sk = sk ^ t;
		sp = sp ^ t;
		su = su ^ t;

		t = sd ^ si ^ sn ^ ss ^ sx;
		v = v ^ _rv64_ror(t, 63);
		t = t ^ _rv64_ror(u, 63);
		se = se ^ t;
		sj = sj ^ t;
		so = so ^ t;
		st = st ^ t;
		sy = sy ^ t;

		t = sc ^ sh ^ sm ^ sr ^ sw;
		u = u ^ _rv64_ror(t, 63);
		t = t ^ _rv64_ror(w, 63);
		sc = sc ^ v;
		sh = sh ^ v;
		sm = sm ^ v;
		sr = sr ^ v;
		sw = sw ^ v;

		sb = sb ^ u;
		sg = sg ^ u;
		sl = sl ^ u;
		sq = sq ^ u;
		sv = sv ^ u;

		sd = sd ^ t;
		si = si ^ t;
		sn = sn ^ t;
		ss = ss ^ t;
		sx = sx ^ t;

		//	Rho Pi

		t = _rv64_ror(sb, 63);
		sb = _rv64_ror(sg, 20);
		sg = _rv64_ror(sj, 44);
		sj = _rv64_ror(sw, 3);
		sw = _rv64_ror(so, 25);
		so = _rv64_ror(su, 46);
		su = _rv64_ror(sc, 2);
		sc = _rv64_ror(sm, 21);
		sm = _rv64_ror(sn, 39);
		sn = _rv64_ror(st, 56);
		st = _rv64_ror(sx, 8);
		sx = _rv64_ror(sp, 23);
		sp = _rv64_ror(se, 37);
		se = _rv64_ror(sy, 50);
		sy = _rv64_ror(sv, 62);
		sv = _rv64_ror(si, 9);
		si = _rv64_ror(sq, 19);
		sq = _rv64_ror(sf, 28);
		sf = _rv64_ror(sd, 36);
		sd = _rv64_ror(ss, 43);
		ss = _rv64_ror(sr, 49);
		sr = _rv64_ror(sl, 54);
		sl = _rv64_ror(sh, 58);
		sh = _rv64_ror(sk, 61);
		sk = t;

		//	Chi

		t = _rv_andn(se, sd);
		se = se ^ _rv_andn(sb, sa);
		sb = sb ^ _rv_andn(sd, sc);
		sd = sd ^ _rv_andn(sa, se);
		sa = sa ^ _rv_andn(sc, sb);
		sc = sc ^ t;

		t = _rv_andn(sj, si);
		sj = sj ^ _rv_andn(sg, sf);
		sg = sg ^ _rv_andn(si, sh);
		si = si ^ _rv_andn(sf, sj);
		sf = sf ^ _rv_andn(sh, sg);
		sh = sh ^ t;

		t = _rv_andn(so, sn);
		so = so ^ _rv_andn(sl, sk);
		sl = sl ^ _rv_andn(sn, sm);
		sn = sn ^ _rv_andn(sk, so);
		sk = sk ^ _rv_andn(sm, sl);
		sm = sm ^ t;

		t = _rv_andn(st, ss);
		st = st ^ _rv_andn(sq, sp);
		sq = sq ^ _rv_andn(ss, sr);
		ss = ss ^ _rv_andn(sp, st);
		sp = sp ^ _rv_andn(sr, sq);
		sr = sr ^ t;

		t = _rv_andn(sy, sx);
		sy = sy ^ _rv_andn(sv, su);
		sv = sv ^ _rv_andn(sx, sw);
		sx = sx ^ _rv_andn(su, sy);
		su = su ^ _rv_andn(sw, sv);
		sw = sw ^ t;

		//	Iota

		sa = sa ^ rc[i];
	}

	//	store state

	vs[0] = sa;
	vs[1] = sb;
	vs[2] = sc;
	vs[3] = sd;
	vs[4] = se;
	vs[5] = sf;
	vs[6] = sg;
	vs[7] = sh;
	vs[8] = si;
	vs[9] = sj;
	vs[10] = sk;
	vs[11] = sl;
	vs[12] = sm;
	vs[13] = sn;
	vs[14] = so;
	vs[15] = sp;
	vs[16] = sq;
	vs[17] = sr;
	vs[18] = ss;
	vs[19] = st;
	vs[20] = su;
	vs[21] = sv;
	vs[22] = sw;
	vs[23] = sx;
	vs[24] = sy;
}

#endif
