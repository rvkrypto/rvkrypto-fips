##	Proposed Scalar Krypto Intrinsics

The proposed Scalar Krypto intrinsics are in [rvkintrin.h](rvkintrin.h).
This proposal complements and is mostly compatible with the Bitmanip
intrinsics of [rvintrin.h](https://github.com/riscv/riscv-bitmanip/blob/master/cproofs/rvintrin.h).
As with that Bitmanip file, the header provides both inline assembler hooks 
and "intrinsics emulation" in a consistent way.

The prefixes and data types are:

* `_rv_*(...)`: RV32/64 intrinsics that operate on the `long` data type.
* `_rv32_*(...)`:  RV32/64 intrinsics that operate on the `int32_t` data type.
* `_rv64_*(...)`:V64-only intrinsics that operate on the `int64_t` data type.

For testing purposes, the header emits inline assembly or emulation code.
Note that this currently only supports scalar krypto. Vector krypto
(which has more dependencies with the vector extension rather than bitmanip)
will use [vector intrisics](https://github.com/riscv/rvv-intrinsic-doc).

When compiled with `RVINTRIN_EMULATE`, the intrinsics will work on 
RV32I/RV64I (or arm/aarch64, i386/amd64) as if it had Bitmanip and Krypto
support -- but much more slowly, and without the constant-time security 
feature of Krypto. For AES and SM4 support, you'll need to link with 
[rvk_emu.c](rvk_emu.c) that provides 8-bit S-Boxes. 

Notes about compilers:

*	Compilers must never emit emulation code for machine intrinsics;
	compilation must fail unless appropriate architecture is specified.
*	Instructions should be mapped into architectural bultins in "real"
	compiler implementations (instead of inline assembler as is done here).
	The inline assembler solution used here should be seen as temporary.
*	The built-in architecture intrinsics are currently expected to be with 
	`__builtin_riscv_*` prefix, while these (shorter) `_rv_*`, `_rv32_*`, 
	`_rv64_*` will remain available via `rvintrin.h` and `rvkintrin.h`
	header mappings. If you don't want short-form intrinsics cluttering 
	your namespace, just don't include these headers.
*	Applications using the `rvintrin.h` and `rvkintrin.h` headers can remain
	unchanged. These intrinsics serve a similar programming convenience
	purpose as the Intel "short" intrinsics
	https://software.intel.com/sites/landingpage/IntrinsicsGuide/# do for that
	ISA. Otherwise programmers would no doubt shorten the `__builtin_riscv_*`
	prefix in various ways themselves. As an example, the Intel intrinsic 
	is `_mm_aesenc_si128()` 
	while the GCC intrinsic is `__builtin_ia32_aesenc128()`.	
*	The headers themselves will switch from inline assembler to
	architectural builtins once those are available. We of course hope that
	the bult-in naming will match between LLVM and GCC.

```C
//	===	Zbkb:	Bitmanipulation instructions for Cryptography
int32_t _rv32_ror(int32_t rs1, int32_t rs2);
int32_t _rv32_rol(int32_t rs1, int32_t rs2);
int32_t _rv32_ror(int32_t rs1, int32_t rs2);
int32_t _rv32_rol(int32_t rs1, int32_t rs2);
int64_t _rv64_ror(int64_t rs1, int64_t rs2);
int64_t _rv64_rol(int64_t rs1, int64_t rs2);
long _rv_andn(long rs1, long rs2);
long _rv_orn (long rs1, long rs2);
long _rv_xnor(long rs1, long rs2);
int32_t _rv32_pack(int32_t rs1, int32_t rs2);
int32_t _rv32_packh(int32_t rs1, int32_t rs2);
int64_t _rv64_pack(int64_t rs1, int64_t rs2);
int64_t _rv64_packh(int64_t rs1, int64_t rs2);
int32_t _rv32_pack(int32_t rs1, int32_t rs2);
int32_t _rv32_brev8(int32_t rs1);
int32_t _rv32_rev8(int32_t rs1);
int64_t _rv64_brev8(int64_t rs1);
int64_t _rv64_rev8(int64_t rs1);
int32_t _rv32_zip(int32_t rs1);
int32_t _rv32_unzip(int32_t rs1);

//	===	Zbkc:	Carry-less multiply instructions
int32_t _rv32_clmul(int32_t rs1, int32_t rs2);
int32_t _rv32_clmulh(int32_t rs1, int32_t rs2);
int64_t _rv64_clmul(int64_t rs1, int64_t rs2);
int64_t _rv64_clmulh(int64_t rs1, int64_t rs2);

//	===	Zbkx:	Crossbar permutation instructions
int32_t _rv32_xperm8(int32_t rs1, int32_t rs2);
int32_t _rv32_xperm4(int32_t rs1, int32_t rs2);
int64_t _rv64_xperm8(int64_t rs1, int64_t rs2);
int64_t _rv64_xperm4(int64_t rs1, int64_t rs2);

//	===	Zknd:	NIST Suite: AES Decryption
int32_t _rv32_aes32dsi(int32_t rs1, int32_t rs2, int bs);
int32_t _rv32_aes32dsmi(int32_t rs1, int32_t rs2, int bs);
int64_t _rv64_aes64ds(int64_t rs1, int64_t rs2);
int64_t _rv64_aes64dsm(int64_t rs1, int64_t rs2);
int64_t _rv64_aes64im(int64_t rs1);
int64_t _rv64_aes64ks1i(int64_t rs1, int rnum);
int64_t _rv64_aes64ks2(int64_t rs1, int64_t rs2);

//	===	Zkne:	NIST Suite: AES Encryption
int32_t _rv32_aes32esi(int32_t rs1, int32_t rs2, int bs);
int32_t _rv32_aes32esmi(int32_t rs1, int32_t rs2, int bs);
int64_t _rv64_aes64es(int64_t rs1, int64_t rs2);
int64_t _rv64_aes64esm(int64_t rs1, int64_t rs2);

//	===	Zknh:	NIST Suite: Hash Function Instructions
long _rv_sha256sig0(long rs1);
long _rv_sha256sig1(long rs1);
long _rv_sha256sum0(long rs1);
long _rv_sha256sum1(long rs1);
int32_t _rv32_sha512sig0h(int32_t rs1, int32_t rs2);
int32_t _rv32_sha512sig0l(int32_t rs1, int32_t rs2);
int32_t _rv32_sha512sig1h(int32_t rs1, int32_t rs2);
int32_t _rv32_sha512sig1l(int32_t rs1, int32_t rs2);
int32_t _rv32_sha512sum0r(int32_t rs1, int32_t rs2);
int32_t _rv32_sha512sum1r(int32_t rs1, int32_t rs2);
int64_t _rv64_sha512sig0(int64_t rs1);
int64_t _rv64_sha512sig1(int64_t rs1);
int64_t _rv64_sha512sum0(int64_t rs1);
int64_t _rv64_sha512sum1(int64_t rs1);

//	===	Zksed:	ShangMi Suite: SM4 Block Cipher Instructions
long _rv_sm4ks(int32_t rs1, int32_t rs2, int bs);
long _rv_sm4ed(int32_t rs1, int32_t rs2, int bs);

//	===	Zksh:	ShangMi Suite: SM3 Hash Function Instructions
long _rv_sm3p0(long rs1);
long _rv_sm3p1(long rs1);
```
