ifeq ($(KERNELRELEASE),)
LINUX = /lib/modules/`uname -r`/build/

all:
	make -C $(LINUX) M=`pwd` CONFIG_TUX3=m modules
clean:
	make -C $(LINUX) M=`pwd` CONFIG_TUX3=m clean
else
obj-$(CONFIG_TUX3) += tux3.o
tux3-objs += balloc.o btree.o dir.o dleaf.o dleaf2.o filemap.o iattr.o ileaf.o \
	inode.o namei.o orphan.o xattr.o super.o log.o commit.o replay.o \
	utility.o
EXTRA_CFLAGS += -Werror -std=gnu99 -Wno-declaration-after-statement
EXTRA_CFLAGS += -DATOMIC=1
endif
