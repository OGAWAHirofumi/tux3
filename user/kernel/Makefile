ifeq ($(KERNELRELEASE),)
LINUX = /lib/modules/`uname -r`/build/

all:
	make -C $(LINUX) M=`pwd` CONFIG_TUX3=m modules
clean:
	make -C $(LINUX) M=`pwd` CONFIG_TUX3=m clean
else
obj-$(CONFIG_TUX3) += tux3.o
tux3-objs += balloc.o btree.o dir.o dleaf.o filemap.o iattr.o \
	ileaf.o namei.o inode.o super.o xattr.o log.o commit.o utility.o
EXTRA_CFLAGS += -Werror -std=gnu99 -Wno-declaration-after-statement
endif
