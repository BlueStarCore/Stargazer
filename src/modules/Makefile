# SPDX-License-Identifier: GPL-2.0-only
# Stargazer NGFW - Kernel modules build

obj-m += pkt_forward.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules KBUILD_MODPOST_WARN=1

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true
	rm -f *.o *.ko *.mod *.mod.c modules.order Module.symvers
	rm -rf .tmp_versions .*.cmd .cache.mk
