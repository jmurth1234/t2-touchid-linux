obj-m += t2_sep_transport.o

KDIR ?= /lib/modules/$(shell uname -r)/build

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) modules
	$(CC) -O2 -Wall -Wextra -Werror -o t2-aks-tool t2-aks-tool.c

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) t2-aks-tool
