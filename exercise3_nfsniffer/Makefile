obj-m += nfsniff.o
#obj-m += hello.o
#obj-m += send_pass.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
