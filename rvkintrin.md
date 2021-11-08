##  Proposed Scalar Krypto Builtins and Intrinsics

**2021-11-05**  Markku-Juhani O. Saarinen <mjos@pqshield.com>

_( Released under BSD 2-Clause and FSF copyright transfer. )_

Notes:

*   The built-in architecture intrinsics are currently expected to be with
    `__builtin_riscv*` prefix.
*   The "W" instruction versions are sign-extended (as is the convention
    in RISC-V) and hence prototyping them as unsigned may cause extra
    code to be generated.
*   The [rvkintrin.h](rvkintrin.h) header (discussed below) serves a similar
    programming convenience purpose as the Intel "short" intrinsics
    https://software.intel.com/sites/landingpage/IntrinsicsGuide/# do for that
    ISA. ( Otherwise programmers would no doubt shorten the `__builtin_riscv*`
    prefix in various ways themselves. )
*   The `__builtin` versions are not yet universally available in
    compilers and hence a mapping to inline assembler via
    [rvkintrin.h](rvkintrin.h) is currently required.

### Architecture extension test macros

For post-ratification Scalar Cryptography v1.0, the Arch Version is `1000000`
(one million).

| Name          | Value        | When defined                                                 |
| ------------- | ------------ | ------------------------------------------------------------ |
| __riscv_zk    | Arch Version | `Zbkb` `Zbkc` `Zbkx` `Zkne` `Zknd` `Zknh` are all available. |
| __riscv_zkn   | Arch Version | `Zbkb` `Zbkc` `Zbkx` `Zkne` `Zknd` `Zknh` are all available. |
| __riscv_zks   | Arch Version | `Zbkb` `Zbkc` `Zbkx` `Zksed` `Zksh` are all available.       |
| __riscv_zbkb  | Arch Version | `Zbkb` extension is available.                               |
| __riscv_zbkc  | Arch Version | `Zbkc` extension is available.                               |
| __riscv_zbkx  | Arch Version | `Zbkx` extension is available.                               |
| __riscv_zknd  | Arch Version | `Zknd` extension is available.                               |
| __riscv_zkne  | Arch Version | `Zkne` extension is available.                               |
| __riscv_zknh  | Arch Version | `Zknh` extension is available.                               |
| __riscv_zksed | Arch Version | `Zksed` extension is available.                              |
| __riscv_zksh  | Arch Version | `Zbsh` extension is available.                               |

The extensions `Zkt` or `Zkr` do not introduce builtins and do not have
architecture extension test macros.

However, **all** of the scalar cryptography intrinsics below must offer the
same data-independent latency guarantees as the `Zkt` extension. The user
must be able to trust that the compiler can't use table lookups, conditional
branching, etc when transforming these crypto builtins into code.


### Zbkb (Zk, Zkn, Zks):    Bitmanipulation instructions for Cryptography

```C
//  Zk, Zkn, Zks, Zbkb on RV32
int32_t __builtin_riscv_ror_32(int32_t rs1, int32_t rs2);       //  ROR or RORI
int32_t __builtin_riscv_rol_32(int32_t rs1, int32_t rs2);       //  ROL or RORI
```

```C
//  Zk, Zkn, Zks, Zbkb on RV64
int32_t __builtin_riscv_ror_32(int32_t rs1, int32_t rs2);       //  RORW or RORIW
int32_t __builtin_riscv_rol_32(int32_t rs1, int32_t rs2);       //  ROLW or RORIW
int64_t __builtin_riscv_ror_64(int64_t rs1, int64_t rs2);       //  ROR or RORI
int64_t __builtin_riscv_rol_64(int64_t rs1, int64_t rs2);       //  ROL or RORI
```

```C
//  Zk, Zkn, Zks, Zbkb on RV32,RV64
long __builtin_riscv_andn(long rs1, long rs2);                  //  ANDN
long __builtin_riscv_orn(long rs1, long rs2);                   //  ORN
long __builtin_riscv_xnor(long rs1, long rs2);                  //  XNOR
```

```C
//  Zk, Zkn, Zks, Zbkb on RV32
int32_t __builtin_riscv_pack_32(int32_t rs1, int32_t rs2);      //  PACK
int32_t __builtin_riscv_packh_32(int32_t rs1, int32_t rs2);     //  PACKH
```

```C
//  Zk, Zkn, Zks, Zbkb on RV64
int64_t __builtin_riscv_pack_64(int64_t rs1, int64_t rs2);      //  PACK
int64_t __builtin_riscv_packh_64(int64_t rs1, int64_t rs2);     //  PACKH
int32_t __builtin_riscv_pack_32(int32_t rs1, int32_t rs2);      //  PACKW
```

```C
//  Zk, Zkn, Zks, Zbkb on RV32
int32_t __builtin_riscv_brev8_32(int32_t rs1);                  //  BREV8 (GREVI)
int32_t __builtin_riscv_rev8_32(int32_t rs1);                   //  REV8 (GREVI)
```

```C
//  Zk, Zkn, Zks, Zbkb on RV64
int64_t __builtin_riscv_brev8_64(int64_t rs1);                  //  BREV8 (GREVI)
int64_t __builtin_riscv_rev8_64(int64_t rs1);                   //  REV8 (GREVI)
```

```C
//  Zk, Zkn, Zks, Zbkb on RV32
int32_t __builtin_riscv_zip_32(int32_t rs1);                    //  ZIP (SHFLI)
int32_t __builtin_riscv_unzip_32(int32_t rs1);                  //  UNZIP (UNSHFLI)
```

```C
//  Zk, Zkn, Zks, Zbkb implementation of a generic builtin on RV32
uint32_t __builtin_bswap32(uint32_t x);                         //  REV8 (GREVI)
```

```C
//  Zk, Zkn, Zks, Zbkb implementation of generic builtins on RV64
uint64_t __builtin_bswap64(uint64_t x);                         //  REV8 (GREVI)
uint32_t __builtin_bswap32(uint32_t x);                         //  REV8 + SRAI
```

### Zbkc (Zk, Zkn, Zks):    Carry-less multiply instructions

```C
//  Zk, Zkn, Zks, Zbkc on RV32
int32_t __builtin_riscv_clmul_32(int32_t rs1, int32_t rs2);     //  CLMUL
int32_t __builtin_riscv_clmulh_32(int32_t rs1, int32_t rs2);    //  CLMULH
```

```C
//  Zk, Zkn, Zks, Zbkc on RV64
int64_t __builtin_riscv_clmul_64(int64_t rs1, int64_t rs2);     //  CLMUL
int64_t __builtin_riscv_clmulh_64(int64_t rs1, int64_t rs2);    //  CLMULH
```

### Zbkx (Zk, Zkn, Zks):    Crossbar permutation instructions

```C
//  Zk, Zkn, Zks, Zbkx on RV32
int32_t __builtin_riscv_xperm4_32(int32_t rs1, int32_t rs2);    //  XPERM4
int32_t __builtin_riscv_xperm8_32(int32_t rs1, int32_t rs2);    //  XPERM8
```

```C
//  Zk, Zkn, Zks, Zbkx on RV64
int64_t __builtin_riscv_xperm4_64(int64_t rs1, int64_t rs2);    //  XPERM4
int64_t __builtin_riscv_xperm8_64(int64_t rs1, int64_t rs2);    //  XPERM8
```

### Zknd (Zk, Zkn):     NIST Suite: AES Decryption

```C
//  Zk, Zkn, Zknd on RV32
int32_t __builtin_riscv_aes32dsi(int32_t rs1, int32_t rs2, int bs);     //  AES32DSI
int32_t __builtin_riscv_aes32dsmi(int32_t rs1, int32_t rs2, int bs);    //  AES32DSMI
```

```C
//  Zk, Zkn, Zknd on RV64
int64_t __builtin_riscv_aes64ds(int64_t rs1, int64_t rs2);      //  AES64DS
int64_t __builtin_riscv_aes64dsm(int64_t rs1, int64_t rs2);     //  AES64DSM
int64_t __builtin_riscv_aes64im(int64_t rs1);                   //  AES64IM
```

### Zkne (Zk, Zkn):     NIST Suite: AES Encryption

```C
//  Zk, Zkn, Zkne on RV32
int32_t __builtin_riscv_aes32esi(int32_t rs1, int32_t rs2, int bs);     //  AES32ESI
int32_t __builtin_riscv_aes32esmi(int32_t rs1, int32_t rs2, int bs);    //  AES32ESMI
```

```C
//  Zk, Zkn, Zkne or RV64
int64_t __builtin_riscv_aes64es(int64_t rs1, int64_t rs2);      //  AES64ES
int64_t __builtin_riscv_aes64esm(int64_t rs1, int64_t rs2);     //  AES64ESM
```

### Zknd and Zkne (Zk, Zkn):     NIST Suite: AES Key Schedule (Encrypt & Decrypt)

```C
//  Zk, Zkn, Zkne, Zknd on RV64
int64_t __builtin_riscv_aes64ks1i(int64_t rs1, int rnum);       //  AES64KS1I
int64_t __builtin_riscv_aes64ks2(int64_t rs1, int64_t rs2);     //  AES64KS2
```

### Zknh (Zk, Zkn): NIST Suite: Hash Function Instructions

```C
//  Zk, Zkn, Zknh on RV32, RV64
long __builtin_riscv_sha256sig0(long rs1);                      //  SHA256SIG0
long __builtin_riscv_sha256sig1(long rs1);                      //  SHA256SIG1
long __builtin_riscv_sha256sum0(long rs1);                      //  SHA256SUM0
long __builtin_riscv_sha256sum1(long rs1);                      //  SHA256SUM1
```

```C
//  Zk, Zkn, Zknh on RV32
int32_t __builtin_riscv_sha512sig0h(int32_t rs1, int32_t rs2);  //  SHA512SIG0H
int32_t __builtin_riscv_sha512sig0l(int32_t rs1, int32_t rs2);  //  SHA512SIG0L
int32_t __builtin_riscv_sha512sig1h(int32_t rs1, int32_t rs2);  //  SHA512SIG1H
int32_t __builtin_riscv_sha512sig1l(int32_t rs1, int32_t rs2);  //  SHA512SIG1L
int32_t __builtin_riscv_sha512sum0r(int32_t rs1, int32_t rs2);  //  SHA512SUM0R
int32_t __builtin_riscv_sha512sum1r(int32_t rs1, int32_t rs2);  //  SHA512SUM1R
```

```C
//  Zk, Zkn, Zknh on RV64
int64_t __builtin_riscv_sha512sig0(int64_t rs1);                //  SHA512SIG0
int64_t __builtin_riscv_sha512sig1(int64_t rs1);                //  SHA512SIG1
int64_t __builtin_riscv_sha512sum0(int64_t rs1);                //  SHA512SUM0
int64_t __builtin_riscv_sha512sum1(int64_t rs1);                //  SHA512SUM1
```

### Zksed  (Zks):   ShangMi Suite: SM4 Block Cipher Instructions

```C
//  Zks, Zksed on RV32, RV64
long __builtin_riscv_sm4ks(int32_t rs1, int32_t rs2, int bs);   //  SM4KS
long __builtin_riscv_sm4ed(int32_t rs1, int32_t rs2, int bs);   //  SM4ED
```

### Zksh  (Zks):    ShangMi Suite: SM3 Hash Function Instructions

```C
//  Zks, Zksh on RV32, RV64
long __builtin_riscv_sm3p0(long rs1);                           //  SM3P0
long __builtin_riscv_sm3p1(long rs1);                           //  SM3P1
```

##  Notes on `rvkintrin.h`

The (shorter) `_rv_*`, `_rv32_*`, `_rv64_*` forms will remain available via
[rvkintrin.h](rvkintrin.h) header mappings. If you don't want short-form
intrinsics cluttering  your namespace, just don't include this header.
That header complements and is mostly compatible with the bitmanip intrinsics
of [rvintrin.h](https://github.com/riscv/riscv-bitmanip/blob/master/cproofs/rvintrin.h).
As with that Bitmanip file, the header provides both inline assembler hooks
and "intrinsics emulation" in a consistent way.

The prefixes and data types are:

* `_rv_*(...)`: RV32/64 intrinsics that operate on the `long` data type.
* `_rv32_*(...)`:V64-only intrinsics that operate on the `int32_t` data type.
* `_rv64_*(...)`:V64-only intrinsics that operate on the `int64_t` data type.
* `__builtin_riscv_*(...)`:  the RV32/64 builtin intrinsics (above).

For testing purposes, the header emits inline assembly or emulation code.
Note that this currently only supports scalar krypto. Vector krypto
(which has more dependencies with the vector extension rather than bitmanip)
will use [vector intrisics](https://github.com/riscv/rvv-intrinsic-doc).

When compiled with `RVKINTRIN_EMULATE`, the shoft-form intrinsics will work on
RV32I/RV64I (or arm/aarch64, i386/amd64) as if it had Bitmanip and Krypto
support -- but much more slowly, and without the constant-time security
feature of Krypto. For AES and SM4 support, you'll need to link with
[rvk_emu.c](rvk_emu.c) that provides 8-bit S-Boxes.

*   The headers themselves will switch from inline assembler to
    architectural builtins once those are available. We of course hope that
    the bult-in naming will match between LLVM and GCC.
*   Compilers must never emit emulation code for machine intrinsics;
    compilation must fail unless appropriate architecture is specified.
*   Instructions should be mapped into architectural bultins in "real"
    compiler implementations (instead of inline assembler as is done here).
    The inline assembler solution used here should be seen as temporary.

