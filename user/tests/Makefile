VG	= valgrind --error-exitcode=200 --leak-check=full

# test rules
.NOTPARALLEL: tests
# The "tests" run in order, otherwise those will output the result mixed.

all: test_balloc test_btree test_buffer test_commit test_dir test_dleaf \
	test_dleaf2 test_filemap test_iattr test_ileaf test_inode test_log \
	test_xattr

clean:
	rm -f foodev

test_balloc: balloc
	$(VG) ./balloc

test_btree: btree
	$(VG) ./btree foodev

test_buffer: buffer
	$(VG) ./buffer

test_commit: commit
	$(VG) ./commit foodev

test_dir: dir
	$(VG) ./dir

test_dleaf: dleaf
	$(VG) ./dleaf

test_dleaf2: dleaf2
	$(VG) ./dleaf2

test_filemap: filemap
	$(VG) ./filemap foodev

test_iattr: iattr
	$(VG) ./iattr

test_ileaf: ileaf
	$(VG) ./ileaf

test_inode: inode
	$(VG) ./inode foodev

test_log: log
	$(VG) ./log

test_xattr: xattr
	$(VG) ./xattr foodev
