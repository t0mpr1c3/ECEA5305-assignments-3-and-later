# See example Makefile from scull project
# Comment/uncomment the following line to disable/enable debugging
DEBUG = y

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSCULL_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

EXTRA_CFLAGS += $(DEBFLAGS)

.PHONY: default modules clean

default: modules

ifneq ($(KERNELRELEASE),)
  $(info "Makefile call from kernel build")
  obj-m      := aesdchar.o
  aesdchar-y := aesd-circular-buffer.o main.o

else
  $(info "Makefile call from module build")
  KERNELDIR ?= /lib/modules/$(shell uname -r)/build
  PWD       := $(shell pwd)

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
