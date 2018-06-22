obj-m += hooker.o
hooker-objs := main.o hooks.o

all:
	make -C /lib/modules/`uname -r`/build M=`pwd` modules
	gcc -o user user.c
clean:
	make -C /lib/modules/`uname -r`/build M=`pwd` clean
	rm user
