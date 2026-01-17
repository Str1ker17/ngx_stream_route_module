.PHONY: run clean

run: test_first_line_parse
	./test_first_line_parse

test_first_line_parse: test_first_line_parse.c Makefile ../objs-module/addon/stream_route/ngx_stream_route_module.o
	cc -O0 -g -o test_first_line_parse test_first_line_parse.c \
        ../objs-module/addon/stream_route/ngx_stream_route_module.o \
        ../objs-module/src/core/ngx_string.o \
    -Wl,--unresolved-symbols=ignore-all

clean:
	rm -f test_first_line_parse
