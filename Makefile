.PHONY: configure all binary modules clean test

BUILDDIR ?= objs-module
CFLAGS ?= -O0 -ggdb2
LDFLAGS ?=

MAKE := make --no-print-directory --no-builtin-rules --no-builtin-variables

all: binary modules test

configure: $(BUILDDIR)/Makefile Makefile

objs-module/Makefile:
	mkdir -p $(BUILDDIR)
	cd nginx && ./auto/configure --with-http_v2_module --with-stream --with-debug --with-cc-opt="$(CFLAGS)" --with-ld-opt="$(LDFLAGS)" --add-dynamic-module=$(PWD) --builddir=$(PWD)/$(BUILDDIR)

binary: configure
	$(MAKE) -C nginx -f $(PWD)/$(BUILDDIR)/Makefile binary

modules: configure
	$(MAKE) -C nginx -f $(PWD)/$(BUILDDIR)/Makefile modules

clean:
	$(MAKE) -C tests clean
	rm -rf objs-module

test:
	$(MAKE) -C tests
