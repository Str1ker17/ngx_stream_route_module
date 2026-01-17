.PHONY: configure all binary modules clean

BUILDDIR ?= objs-module

all: binary modules

configure: $(BUILDDIR)/Makefile

objs-module/Makefile:
	mkdir -p $(BUILDDIR)
	cd nginx && ./auto/configure --with-stream --with-debug --add-dynamic-module=$(PWD) --builddir=$(PWD)/$(BUILDDIR)

binary: configure
	make -C nginx -f $(PWD)/$(BUILDDIR)/Makefile binary

modules: configure
	make -C nginx -f $(PWD)/$(BUILDDIR)/Makefile modules

clean:
	rm -rf objs-module
