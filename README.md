#	rvkrypto-fips

**NOTE: THIS REPO IS NOT MAINTAINED -- OLD DEVELOPMENT VERSION OF INTRINSICS**

Algorithm tests for RISC-V Crypto Extension.

2021-02-14	Markku-Juhani O. Saarinen <mjos@pqshield.com>

2021-11-04	Updated to post-arch review 1.0rc5.

2022-02-03  Removed most intrinsics for Zbkb.

*Information and recommendations here are unofficial and under discussion in
the [CETG](https://wiki.riscv.org/display/TECH/Cryptographic+Extensions+TG).*

This repo currently provides 
[RISC-V Cryptographic Extensions](https://github.com/riscv/riscv-crypto)
implementations of AES-128/192/256, GCM, SHA2-256/384, SHA3, SM3, SM4, 
PRESENT algorithms for RV32-K and RV64-K scalar targets. Together with primary 
test vectors in `test/test_*.c`, the implementations allow bare metal 
architectural self-testing of the scalar crypto extension, which is the
first part of the Krypto extension reaching "stable" status.

After intrinsics are agreed and initial testing succeeds, we can start
pushing RV Krypto optimizations into 
[FIPS 140-3 OpenSSL](https://www.openssl.org/docs/OpenSSL300Design.html)
and other open source middleware.

**NOTE.** 

I'm expanding this repo to cover more test vectors and other
[FIPS 140-3](https://csrc.nist.gov/projects/fips-140-3-transition-effort)
algorithm validation information. I am not an accredited testing laboratory,
nor is RISC-V International, so all information herein should be seen just 
as a well-intentioned sharing of breadcrumbs of information and experiments
without any warranty whatsoever. However, this repo is a freely 
[licensed](LICENSE) contribution to RISC-V work by a member.

*Cheers, - markku*


##	(Cross) Compiling 

If you have a RISC-V compiler and spike emulator with 1.0 Scalar Crypto
Extension, try:
```
make -f rv32.mk
``` 
or
```
make -f rv64.mk
``` 
for 32-bit and 64-bit RISC-V ISAs, respectively. This will create the
`xtest` test binary and execute it on spike. Add `xtest` as the target
to build the test binary only.

Currently the makefile uses inline assembler mappings.


##	Proposed Krypto Intrinsics

Please see [riscv_crypto.md](riscv_crypto.md) for information about the proposed
compiler builtins and intrinsics in [riscv_crypto.h](riscv_crypto.h).

You may enable inline assembler with flag `RVKINTRIN_ASSEMBLER` --
then the intrinsics are defined using [rvk_asm_intrin.h](rvk_asm_intrin.h).

##	Intrinsics emulation on other ISA

You can also compile the tests natively on a non-RV host with simple `make`
if you uncomment the line in Makefile:
```
CFLAGS	+=	-DRVKINTRIN_EMULATE=1 -DRVKINTRIN_RV32 -DRVKINTRIN_RV64
```
This uses emulation header in [rvk_emu_intrin.h](rvk_emu_intrin.h), which
in turn requires helper tables in [rvk_emu_intrin.c](rvk_emu_intrin.c).

To execute, just run `xtest`:
```
$ ./xtest 
[INFO] === AES32 ===
[PASS] AES-128 Enc 69C4E0D86A7B0430D8CDB78070B4C55A
[PASS] AES-128 Dec 00112233445566778899AABBCCDDEEFF
(...)
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

While basic algorithm testing can be largely automated, vendors
are very likely to need cryptographic security specialists when:
* Designing entropy sources for the Zkr, which is CSR part of Scalar Crypto or 
* Designing implementations for side-channel (non-invasive) security.

(This repo does not contain material related to entropy sources yet.)

Entropy sources are easy to get wrong as the product will 
"work" regardless of the quality of cryptographic keys. 
Automated testing alone is not sufficient to satisfy 
[SP 800-90B](https://doi.org/10.6028/NIST.SP.800-90B) or
[AIS-31 PTG.2](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Zertifizierung/Interpretationen/AIS_31_Functionality_classes_for_random_number_generators_e.pdf)
requirements. These certification processes require additional
evidence about matters such as noise source entropy justification, 
appropriateness of conditioning components, and health testing.

Side-channel claims must also be independently verified.
In a Common Criteria setting, this is often done by evaluating
[attack potential in a laboratory setting](https://www.sogis.eu/documents/cc/domains/sc/JIL-Application-of-Attack-Potential-to-Smartcards-v3-1.pdf)
against a specific protection profile (PP).

