#	rvkrypto-fips

FIPS and higher-level algorithm tests for RISC-V Crypto Extension

2021-02-14	Markku-Juhani O. Saarinen <mjos@pqshield.com>

*Information and recommendations here are unofficial and under discussion in
the [CETG](https://wiki.riscv.org/display/TECH/Cryptographic+Extensions+TG).*

This repo currently provides 
[RISC-V Cryptographic Extensions](https://github.com/riscv/riscv-crypto)
implementations of AES-128/192/256, GCM, SHA2-256/384, SHA3, SM3, SM4 
algorithms for RV32-K and RV64-K scalar targets. Together with primary 
test vectors in `test_*.c`, the implementations allow bare metal 
architectural self-testing of the scalar crypto extension, which is the
first part of the Krypto extension reaching "stable" status.

After intrinsics are agreed and initial testing succeeds, we can start
pushing RV Krypto optimizations into 
[FIPS 140-3 OpenSSL](https://www.openssl.org/docs/OpenSSL300Design.html)
and other open source middleware.

Please consider the 
[RISC-V Crypto repo](https://github.com/riscv/riscv-crypto) as the official
reference. There are very similar implementations in that repo, as these
particular instruction extensions were designed to be used in algorithms
in very specific ways.


**NOTE.** 

I'm expanding this repo to cover more test vectors and other
[FIPS 140-3](https://csrc.nist.gov/projects/fips-140-3-transition-effort)
algorithm validation information. I am not an accredited testing laboratory,
nor is RISC-V International, so all information herein should be seen just 
as a well-intentioned sharing of breadcrumbs of information and experiments
without any warranty whatsoever. However, this repo is a freely 
[licensed](LICENSE) contribution to RISC-V work by a member.

*Cheers, - markku*


##	Proposed Krypto Intrinsics

The proposed Krypto intrinsics are in [rvkintrin.h](rvkintrin.h).
This proposal complements and is compatible with the Bitmanip intrinsics of
[rvintrin.h](https://github.com/riscv/riscv-bitmanip/blob/master/cproofs/rvintrin.h).
As with that Bitmanip file, the header provides both inline assembler hooks 
and "intrinsics emulation" in a consistent way.

The prefixes and data types are:

* `_rv_*(...)`: RV32/64 intrinsics that operate on the `long` data type.
* `_rv32_*(...)`:  RV32/64 intrinsics that operate on the `int32_t` data type.
* `_rv64_*(...)`:V64-only intrinsics that operate on the `int64_t` data type.

Note that this currently only supports scalar krypto. Vector krypto
(which has more dependencies with the vector extension rather than bitmanip)
will use [vector intrisics](https://github.com/riscv/rvv-intrinsic-doc).

When compiled with `RVINTRIN_EMULATE`, the intrinsics will work on 
RV32I/RV64I (or arm/aarch64, i386/amd64) as if it had Bitmanip and Krypto
support -- but much more slowly, and without the constant-time security 
feature of Krypto. For AES and SM4 support, you'll need to link with 
[rvk_emu.c](rvk_emu.c) that provides 8-bit S-Boxes. For emulation of 
Zkr entropy sources, you'll need to provide
`_rv_pollentropy()` and `_rv_getnoise()` yourself; the emulation mode 
provides just function prototypes for these.

Notes about compilers:

*	Compilers must never emit emulation code for machine intrinsics;
	compilation must fail unless appropriate architecture is specified.
*	Actual CMVP testing is of course with native instructions only.
	CAVP tests must fail if emulation is used as they contain table
	lookups and conditionals (forbidden in constant-time code).
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
	the bult-in namic will match between LLVM and GCC.


##	Compiling

You can use `make -f rv32.mk` or `make -f rv64.mk` to compile and
execute the tests on spike (add `xtest` to build the binary only).
The goal is that these will run nicely without `RVINTRIN_EMULATE` 
being defined in `Makefile`.

You can also compile the tests natively on a non-RV host with simple `make`:
```
$ make
gcc -Wall -O2 -I.  -DRVINTRIN_EMULATE=1 -DRVK_ALGTEST_VERBOSE_SIO=1 -c rvk_emu.c -o rvk_emu.o
gcc -Wall -O2 -I.  -DRVINTRIN_EMULATE=1 -DRVK_ALGTEST_VERBOSE_SIO=1 -c test_aes.c -o test_aes.o
(..)
```
Note that even in this case the implementations depend on the `xlen` of the
compiler (aarch64 will emulate RV64K while 32-bit arm will emulate RV32K !). 
To execute, just run `xtest`:
```
$ ./xtest 
[INFO] === AES64 ===
[PASS] AES-128 Enc 69C4E0D86A7B0430D8CDB78070B4C55A
[PASS] AES-128 Dec 00112233445566778899AABBCCDDEEFF
(...)
[PASS] SM4 Encrypt 94CFE3F59E8507FEC41DBE738CCD53E1
[PASS] SM4 Decrypt A27EE076E48E6F389710EC7B5E8A3BE5
[INFO] RVKAT self-test finished: PASS (no errors)
```

##	Background for RISC-V FIPS 140-3

RISC-V encourages the use of standardized cryptography.
Through vendor compliance with cryptographic implementation standards,
such as 
[FIPS 140-3](https://csrc.nist.gov/projects/fips-140-3-transition-effort)
and [Common Criteria](https://www.commoncriteriaportal.org/) Protection
Profiles, users can manage risks and choose appropriate 
[RISC-V](https://riscv.org/) processor products for security applications.

The FIPS 140-3 validation program
[CMVP](https://csrc.nist.gov/projects/cryptographic-module-validation-program)
and its 
[automated](https://csrc.nist.gov/Projects/Automated-Cryptographic-Validation-Testing)
[ACVP](https://github.com/usnistgov/ACVP) 
mechanism offer a route to perform cost-effective base-level algorithm
validation for the FIPS-defined cryptographic algorithms, such as
AES ([FIPS 197](https://doi.org/10.6028/NIST.FIPS.197)),
SHA-2 ([FIPS 180-3](https://doi.org/10.6028/NIST.FIPS.180-4)), 
SHA-3 ([FIPS 202](https://doi.org/10.6028/NIST.FIPS.202)),
and their modes. 

FIPS is a requirement in some industries and for US Federal IT sales.
FIPS algorithm testing (ACVP) satisfies a functional requirement that is a
part of more stringent protection profiles of dedicated security products.


##	Certification and Self-Certification

Algorithm testing is just a part of a wider cryptographic module
testing process that leads to FIPS or CC certification. 

The certified module ("IUT") can be the RISC-V processor or coprocessor
itself, but more often is some derived device or product. Appropriate
standards-aware engineering, self-certification, and evidence of FIPS
compliance help a RISC-V vendor "sell" their IP to a security vendor
wishing to build a cryptographic module. 

The actual post-engineering validation process additionally involves
an accredited testing lab and a national certification body -- 
NIST (USA) CCCS (Canada) for most typical FIPS certification,
NIAP for National Security Systems, BSI in Germany, ANSSI in France, etc.


##	Side-Channels and Entropy Sources for Cryptographic Use

*I'm going to provide random number material here, so this is just a caveat.*

While basic algorithm testing can be largely automated, vendors
are very likely to need cryptographic security specialists when:
* Designing entropy sources or 
* Designing implementations for side-channel (non-invasive) security.

Entropy sources are easy to get wrong as the product will 
"work" regardless of the quality of cryptographic keys. 
Automated testing alone is not sufficient to satisfy 
[SP 800-90B](https://doi.org/10.6028/NIST.SP.800-90B) or
[AIS-31 PTG.2](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Zertifizierung/Interpretationen/AIS_31_Functionality_classes_for_random_number_generators_e.pdf)
requirements. These certification processes require additional
evidence about matters such as noise source entropy estimation, 
appropriateness of conditioning components, and health testing.

Side-channel claims must also be independently verified.
In a Common Criteria setting, this is often done by evaluating
[attack potential in a laboratory setting](https://www.sogis.eu/documents/cc/domains/sc/JIL-Application-of-Attack-Potential-to-Smartcards-v3-1.pdf)
against a specific protection profile (PP).

We urge vendors to make the **ZKr** (`pollentropy` and `getnoise`)
extension available only if they are confident that the entropy source
and its interfaces are actually compliant with either SP 800-90B or 
AIS-31 PTG.2. We also urge care when making side-channel security claims,
as such claims will put "non-invasive in the testing scope" (in crypto
module jargon) and greatly increase the risk of failing validation.

