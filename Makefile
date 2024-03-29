#	Makefile
#	2021-02-10	Markku-Juhani O. Saarinen <mjos@pqshield.com>
#   Copyright (c) 2021, PQShield Ltd.  All rights reserved.

#	export all variables to sub-makefiles
export

XBIN	=	xtest
CSRC	=	$(wildcard *.c */*.c)
SSRC	=	$(wildcard *.S)
OBJS	=	$(CSRC:.c=.o) $(SSRC:.S=.o)
XCC		?=	$(XCHAIN)gcc
XOBJD	?=	$(XCHAIN)objdump

CFLAGS	+=	-Wall -Wextra -O2 -g

#	intrinsics emulation (you can enable both at the same time)
#CFLAGS	+=	-DRVKINTRIN_EMULATE=1 -DRVKINTRIN_RV32 -DRVKINTRIN_RV64

#	note that the final program return value is the output without this
CFLAGS	+=	-I. -Itest -DRVK_ALGTEST_VERBOSE_SIO=1

$(XBIN): $(OBJS)
	$(XCC) $(LDFLAGS) $(CFLAGS) -o $(XBIN) $(OBJS) $(LDLIBS)

$(XBIN).dis: $(XBIN)
	$(XOBJD) -d -S $^ > $@

%.o:	%.[cS]
	$(XCC) $(CFLAGS) -c $^ -o $@

run:	$(XBIN)
	./$(XBIN)
	@echo $(XBIN) "finished."
#	"finished" will not print on failure ( no RVK_ALGTEST_VERBOSE_SIO )

clean:
	rm -rf $(OBJS) $(XBIN) $(XBIN).dis *~

