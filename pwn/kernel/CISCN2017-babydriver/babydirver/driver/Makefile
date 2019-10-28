ifneq ($(KERNELRELEASE),)

    obj-m := hello.o

else
    CURRENT_PATH :=$(shell pwd)
    LINUX_KERNEL_PATH := /lib/modules/$(shell uname -r)/build

default:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) modules

clean:
	make -C $(LINUX_KERNEL_PATH) M=$(CURRENT_PATH) clean 
endif
