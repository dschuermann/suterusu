obj-m += suterusu.o

default:
	@echo "To build Suterusu, type:"
	@echo "  make TARGET KDIR=/path/to/kernel"
	@echo
	@echo "To cross-compile, type:"
	@echo "  make TARGET CROSS_COMPILE=arm-linux-androideabi- KDIR=/path/to/kernel"
	@echo
	@echo "To clean the build dir, type:"
	@echo "  make clean KDIR=/path/to/kernel"
	@echo
	@echo "Supported targets:"
	@echo "linux-x86	Linux, x86"
	@echo "android-arm	Android Linux, ARM"
	@echo

linux-x86:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) ARCH=x86 EXTRA_CFLAGS=-D_CONFIG_X86_ -C $(KDIR) M=$(PWD) modules

android-arm:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) ARCH=arm EXTRA_CFLAGS="-D_CONFIG_ARM_ -fno-pic" -C $(KDIR) M=$(PWD) modules

clean:
ifndef KDIR
	@echo "Must provide KDIR!"
	@exit 1
endif
	$(MAKE) -C $(KDIR) M=$(PWD) clean
