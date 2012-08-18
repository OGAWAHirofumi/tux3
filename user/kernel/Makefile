ifeq ($(KERNELRELEASE),)
LINUX = /lib/modules/`uname -r`/build/

all:
	make -C $(LINUX) M=`pwd` CONFIG_TUX3=m modules
clean:
	make -C $(LINUX) M=`pwd` CONFIG_TUX3=m clean
else
obj-$(CONFIG_TUX3) += tux3.o
tux3-objs += balloc.o btree.o buffer.o commit.o dir.o dleaf.o dleaf2.o \
	filemap.o iattr.o ileaf.o inode.o log.o namei.o orphan.o replay.o \
	super.o utility.o writeback.o xattr.o
EXTRA_CFLAGS += -Werror -std=gnu99 -Wno-declaration-after-statement
EXTRA_CFLAGS += -DATOMIC=1
endif
