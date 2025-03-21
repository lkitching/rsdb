all: target/debug/reg_write target/debug/reg_read target/debug/hello_rsdb

target/debug/reg_write : src/support/reg_write.s
	gcc -pie src/support/reg_write.s -o target/debug/reg_write

target/debug/reg_read: src/support/reg_read.s
	gcc -pie src/support/reg_read.s -o target/debug/reg_read

target/debug/hello_rsdb: src/support/hello_rsdb.c
	gcc -g -O0 -pie src/support/hello_rsdb.c -o target/debug/hello_rsdb

clean :
	rm target/debug/reg_write
	rm target/debug/reg_read
	rm target/debug/hello_rsdb
