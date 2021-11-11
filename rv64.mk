#	rv64.mk
#	2021-02-14	Markku-Juhani O. Saarinen <mjos@pqshield.com>
#   Copyright (c) 2021, PQShield Ltd.  All rights reserved.

#	===	Cross-compile for RV64 target, run with spike emulator.

#	(lacking K flag here)
CFLAGS	+=	-march=rv64imafdc -mabi=lp64d -DRVKINTRIN_ASSEMBLER

#	toolchain
XCHAIN	=	$(RISCV)/bin/riscv64-unknown-elf-

#	spike and proxy kernel
SPIKE	=	$(RISCV)/bin/spike
PK64	=	$(RISCV)/riscv64-unknown-elf/bin/pk

#	default target
all:	spike64

#	include main makefile
include	Makefile

#	execution target
spike64:	$(XBIN)
	$(SPIKE) --isa=rv64imac_zkn_zks_zkr $(PK64) ./$(XBIN)

