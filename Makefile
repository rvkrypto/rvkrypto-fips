#	Makefile
#	2021-02-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
#   Copyright (c) 2021, PQShield Ltd.  All rights reserved.

#	export all variables to sub-makefiles
export				

#	some cross-compilers
#XCHAIN	=	riscv64-unknown-elf-
#XCHAIN	=	arm-linux-gnueabi-
#XCHAIN	=	aarch64-linux-gnu-
#XCHAIN	=	i686-linux-gnu-

XBIN	=	xtest
CSRC	=	$(wildcard *.c */*.c)
OBJS	=	$(CSRC:.c=.o)
XCC		?=	$(XCHAIN)gcc

CFLAGS	+=	-Wall -Wextra -O2 -I. 

#	intrinsics emulation; the testing goal is that this can be OFF
CFLAGS	+=	-DRVINTRIN_EMULATE=1

#	note that the final program return value is the output without this
CFLAGS	+=	-DRVK_ALGTEST_VERBOSE_STDIO=1
#LDFLAGS	+=	-static		#	easier for cross compilers

$(XBIN): $(OBJS)
	$(XCC) $(LDFLAGS) $(CFLAGS) -o $(XBIN) $(OBJS) $(LDLIBS)

%.o:	%.[cS]
	$(XCC) $(CFLAGS) -c $^ -o $@

run:	$(XBIN)
	./$(XBIN)
	@echo $(XBIN) "finished."
#	"finished" will not print on failure ( no RVK_ALGTEST_VERBOSE_STDIO )

clean:
	rm -rf $(OBJS) $(XBIN) *~

