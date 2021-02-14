#	rv32.mk
#	2021-02-14	Markku-Juhani O. Saarinen <mjos@pqshield.com>
#   Copyright (c) 2021, PQShield Ltd.  All rights reserved.

#	===	Cross-compile for RV32 target, run with spike emulator.

#	(lacking K flag)
ARCH_32	=	rv32imac
ABI_32	=	ilp32
CFLAGS	+=	-march=$(ARCH_32) -mabi=$(ABI_32)

#	toolchain
XCHAIN	=	$(RISCV)/bin/riscv64-unknown-elf-

#	spike and proxy kernel
SPIKE	=	$(RISCV)/bin/spike
PK32	=	$(RISCV)/riscv32-unknown-elf/bin/pk

#	default target
all:	spike32

#	include main makefile
include	Makefile

#	execution target
spike32:	$(XBIN)
	$(SPIKE) --isa=$(ARCH_32) $(PK32) ./$(XBIN)

