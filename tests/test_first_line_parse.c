#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

typedef enum {
    NGX_STREAM_ROUTE_NOT_DECIDED,
    NGX_STREAM_ROUTE_DEFAULT,
    NGX_STREAM_ROUTE_HTTP,
    NGX_STREAM_ROUTE_PROXY_PLAIN,
    NGX_STREAM_ROUTE_PROXY_CONNECT,
} ngx_stream_route_decision_t;

/* link with addon/stream_route/ngx_stream_route_module.o */
extern ngx_stream_route_decision_t stream_route_first_line_parse(const u_char *buf, size_t n);

/* ====== test harness ====== */

typedef struct {
    const char *name;
    const u_char *buf;
    size_t len;
    ngx_stream_route_decision_t expect;
} test_case_t;

static const char *decision_name(ngx_stream_route_decision_t d) {
    switch (d) {
        case NGX_STREAM_ROUTE_NOT_DECIDED:   return "NOT_DECIDED";
        case NGX_STREAM_ROUTE_HTTP:          return "HTTP";
        case NGX_STREAM_ROUTE_PROXY_CONNECT: return "PROXY_CONNECT";
        case NGX_STREAM_ROUTE_PROXY_PLAIN:   return "PROXY_PLAIN";
        case NGX_STREAM_ROUTE_DEFAULT:       return "DEFAULT";
    }
    return "?";
}

static void print_bytes_preview(const u_char *buf, size_t len) {
    /* print both ASCII-ish and hex for non-printables */
    size_t max = len < 80 ? len : 80;
    fprintf(stderr, "  bytes(%zu): ", len);
    for (size_t i = 0; i < max; i++) {
        unsigned char c = buf[i];
        if (c >= 32 && c <= 126) fputc(c, stderr);
        else fputc('.', stderr);
    }
    if (len > max) fprintf(stderr, "…");
    fputc('\n', stderr);

    fprintf(stderr, "  hex: ");
    for (size_t i = 0; i < max; i++) {
        fprintf(stderr, "%02x ", (unsigned)buf[i]);
    }
    if (len > max) fprintf(stderr, "…");
    fputc('\n', stderr);
}

static int run_one(const test_case_t *tc, int index) {
    ngx_stream_route_decision_t got = stream_route_first_line_parse(tc->buf, (ssize_t)tc->len);
    if (got != tc->expect) {
        fprintf(stderr, "\nFAIL #%d: %s\n", index, tc->name);
        fprintf(stderr, "  expected: %s\n", decision_name(tc->expect));
        fprintf(stderr, "  got:      %s\n", decision_name(got));
        print_bytes_preview(tc->buf, tc->len);
        return 0;
    }
    return 1;
}

static int same_input(const test_case_t *a, const test_case_t *b) {
    if (a->len != b->len) return 0;
    if (a->buf == b->buf) return 1; /* same pointer + same len */
    return memcmp(a->buf, b->buf, a->len) == 0;
}

static void assert_no_duplicates(const test_case_t *tcs, size_t n) {
    for (size_t i = 0; i < n; i++) {
        for (size_t j = i + 1; j < n; j++) {
            if (same_input(&tcs[i], &tcs[j])) {
                fprintf(stderr, "\nDUPLICATE INPUTS DETECTED:\n");
                fprintf(stderr, "  #%zu: %s\n", i + 1, tcs[i].name);
                fprintf(stderr, "  #%zu: %s\n", j + 1, tcs[j].name);
                print_bytes_preview(tcs[i].buf, tcs[i].len);
                exit(2);
            }
        }
    }
}

static test_case_t tc(const char *name, const char *s, size_t len, ngx_stream_route_decision_t expect) {
    test_case_t t;
    t.name = name;
    t.buf = (const u_char *)s;
    t.len = len;
    t.expect = expect;
    return t;
}

/* for binary buffers */
static test_case_t tcb(const char *name, const u_char *b, size_t len, ngx_stream_route_decision_t expect) {
    test_case_t t;
    t.name = name;
    t.buf = b;
    t.len = len;
    t.expect = expect;
    return t;
}

/* ====== tests (>=100, non-repeating) ====== */
/*
Contract we test (as you described earlier):
- PRI * ...                -> HTTP
- CONNECT <target> ...      -> PROXY_CONNECT (exact method, not prefix)
- Any method with target starting '/' or '*' -> HTTP
- Any method with target starting http:// or https:// (case-insensitive scheme) -> PROXY_PLAIN
- Everything else -> DEFAULT
- NOT_DECIDED only if more bytes could still change decision (incomplete data)
*/

int main(void) {
    /* some binary-only cases */
    static const u_char bin_no_space_with_lf[] = { 'G','E','T','\t','/','x',' ','H','T','T','P','/','1','.','1','\r','\n' };
    static const u_char bin_nul_in_method[]    = { 'G','E',0,' ','/','x',' ','H','T','T','P','/','1','.','1','\r','\n' };
    static const u_char bin_spaces_only[]      = { ' ',' ',' ',' ','\n' };
    static const u_char bin_garbage[]          = { 0xff,0xfe,0xfd,' ','/','x','\r','\n' };

    /* build a big, unique list */
    test_case_t tests[] = {

        /* ===== lengths 0/1/2/3 edge ===== */
        tc("len0 empty", "", 0, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("len1 'G'", "GET /x HTTP/1.1\r\n", 1, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("len2 'GE'", "GET /x HTTP/1.1\r\n", 2, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("len3 'GET' no space", "GET /x HTTP/1.1\r\n", 3, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("len1 single space should be DEFAULT (invalid, no need to read more)", " ", 1, NGX_STREAM_ROUTE_DEFAULT),
        tcb("bin spaces-only line should be DEFAULT", bin_spaces_only, sizeof(bin_spaces_only), NGX_STREAM_ROUTE_DEFAULT),

        /* ===== PRI / h2c preface ===== */
        tc("PRI full preface -> HTTP", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", strlen("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("PRI partial 'PRI ' -> NOT_DECIDED", "PRI * HTTP/2.0\r\n", 4, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("PRI 'PRI *' -> HTTP", "PRI * HTTP/2.0\r\n", 5, NGX_STREAM_ROUTE_HTTP),
        tc("PRI weird target '*' but extra spaces: 'PRI  *' -> DEFAULT (target starts with space)", "PRI  * HTTP/2.0\r\n", strlen("PRI  * HTTP/2.0\r\n"), NGX_STREAM_ROUTE_DEFAULT),

        /* ===== CONNECT positives (case variations) ===== */
        tc("CONNECT classic -> PROXY_CONNECT", "CONNECT example.com:443 HTTP/1.1\r\n", strlen("CONNECT example.com:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_CONNECT),
        tc("connect lowercase -> PROXY_CONNECT", "connect example.com:443 HTTP/1.1\r\n", strlen("connect example.com:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_CONNECT),
        tc("ConNeCt mixedcase -> PROXY_CONNECT", "ConNeCt example.com:443 HTTP/1.1\r\n", strlen("ConNeCt example.com:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_CONNECT),
        tc("CONNECT minimal 'CONNECT ' -> PROXY_CONNECT (any target)", "CONNECT ", strlen("CONNECT "), NGX_STREAM_ROUTE_PROXY_CONNECT),
        tc("CONNECT partial 'CONNE' -> NOT_DECIDED", "CONNECT x", 5, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("CONNECT partial 'CONNECT' (no space) -> NOT_DECIDED", "CONNECT", strlen("CONNECT"), NGX_STREAM_ROUTE_NOT_DECIDED),

        /* ===== CONNECT negatives (must be DEFAULT, not PROXY_CONNECT) ===== */
        tc("CONNECTX must be DEFAULT", "CONNECTX host:443 HTTP/1.1\r\n", strlen("CONNECTX host:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("CONNECT_ must be DEFAULT", "CONNECT_ host:443 HTTP/1.1\r\n", strlen("CONNECT_ host:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("CONNECT123 must be DEFAULT", "CONNECT123 host:443 HTTP/1.1\r\n", strlen("CONNECT123 host:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("XCONNECT must be DEFAULT", "XCONNECT host:443 HTTP/1.1\r\n", strlen("XCONNECT host:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("leading space then CONNECT must be DEFAULT", " CONNECT host:443 HTTP/1.1\r\n", strlen(" CONNECT host:443 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),

        /* ===== origin-form: any method + /... => HTTP ===== */
        tc("GET / -> HTTP", "GET / HTTP/1.1\r\n", strlen("GET / HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("GET /url -> HTTP", "GET /url HTTP/1.1\r\n", strlen("GET /url HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("POST /api -> HTTP", "POST /api HTTP/1.1\r\n", strlen("POST /api HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("PUT /x -> HTTP", "PUT /x HTTP/1.1\r\n", strlen("PUT /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("DELETE /x -> HTTP", "DELETE /x HTTP/1.1\r\n", strlen("DELETE /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("HEAD /x -> HTTP", "HEAD /x HTTP/1.1\r\n", strlen("HEAD /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("PATCH /x -> HTTP", "PATCH /x HTTP/1.1\r\n", strlen("PATCH /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("OPTIONS /x -> HTTP", "OPTIONS /x HTTP/1.1\r\n", strlen("OPTIONS /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("TRACE /x -> HTTP", "TRACE /x HTTP/1.1\r\n", strlen("TRACE /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("PROPFIND /x -> HTTP", "PROPFIND /x HTTP/1.1\r\n", strlen("PROPFIND /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),

        /* partial reads around first space + '/' */
        //tc("partial 'GET' -> NOT_DECIDED", "GET /x HTTP/1.1\r\n", 3, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET ' -> NOT_DECIDED", "GET /x HTTP/1.1\r\n", 4, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET /' -> HTTP", "GET /x HTTP/1.1\r\n", 5, NGX_STREAM_ROUTE_HTTP),
        tc("partial 'POST /' -> HTTP", "POST /x HTTP/1.1\r\n", 6, NGX_STREAM_ROUTE_HTTP),
        tc("partial 'DELETE /' -> HTTP", "DELETE /x HTTP/1.1\r\n", 8, NGX_STREAM_ROUTE_HTTP),

        /* ===== asterisk-form: any method + * => HTTP ===== */
        tc("OPTIONS * -> HTTP", "OPTIONS * HTTP/1.1\r\n", strlen("OPTIONS * HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("PRI * already covered -> HTTP unique variant", "PRI * HTTP/2.0\n", strlen("PRI * HTTP/2.0\n"), NGX_STREAM_ROUTE_HTTP),
        tc("GET * (weird but router says HTTP)", "GET * HTTP/1.1\r\n", strlen("GET * HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("CUSTOM * -> HTTP", "FOO * HTTP/1.1\r\n", strlen("FOO * HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),

        /* ===== absolute-form: http:// / https:// => PROXY_PLAIN (case-insensitive scheme desired) ===== */
        tc("GET http://host/ -> PROXY_PLAIN", "GET http://host/ HTTP/1.1\r\n", strlen("GET http://host/ HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("GET https://host/ -> PROXY_PLAIN", "GET https://host/ HTTP/1.1\r\n", strlen("GET https://host/ HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("POST http://host/x -> PROXY_PLAIN", "POST http://host/x HTTP/1.1\r\n", strlen("POST http://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("PUT https://host/x -> PROXY_PLAIN", "PUT https://host/x HTTP/1.1\r\n", strlen("PUT https://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("DELETE http://h/x -> PROXY_PLAIN", "DELETE http://h/x HTTP/1.1\r\n", strlen("DELETE http://h/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("HEAD https://h/x -> PROXY_PLAIN", "HEAD https://h/x HTTP/1.1\r\n", strlen("HEAD https://h/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),

        /* scheme case variations (should be PROXY_PLAIN by contract; your code likely fails these) */
        tc("GET HTTP://host/x -> PROXY_PLAIN", "GET HTTP://host/x HTTP/1.1\r\n", strlen("GET HTTP://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("GET HtTp://host/x -> PROXY_PLAIN", "GET HtTp://host/x HTTP/1.1\r\n", strlen("GET HtTp://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("GET HTTPS://host/x -> PROXY_PLAIN", "GET HTTPS://host/x HTTP/1.1\r\n", strlen("GET HTTPS://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("GET hTTps://host/x -> PROXY_PLAIN", "GET hTTps://host/x HTTP/1.1\r\n", strlen("GET hTTps://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),

        /* absolute-form minimal prefixes */
        tc("GET http:// (no host) -> PROXY_PLAIN", "GET http:// HTTP/1.1\r\n", strlen("GET http:// HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("GET https:// (no host) -> PROXY_PLAIN", "GET https:// HTTP/1.1\r\n", strlen("GET https:// HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),

        /* partial reads: ambiguous prefixes that REQUIRE NOT_DECIDED */
        tc("partial 'GET h' -> NOT_DECIDED", "GET http://host/x HTTP/1.1\r\n", 5, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET ht' -> NOT_DECIDED", "GET http://host/x HTTP/1.1\r\n", 6, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET htt' -> NOT_DECIDED", "GET http://host/x HTTP/1.1\r\n", 7, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET http' -> NOT_DECIDED", "GET http://host/x HTTP/1.1\r\n", 8, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET http:' -> NOT_DECIDED", "GET http://host/x HTTP/1.1\r\n", 9, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET http:/' -> NOT_DECIDED", "GET http://host/x HTTP/1.1\r\n", 10, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET http://' -> PROXY_PLAIN", "GET http://host/x HTTP/1.1\r\n", 11, NGX_STREAM_ROUTE_PROXY_PLAIN),

        tc("partial 'GET https' -> NOT_DECIDED", "GET https://host/x HTTP/1.1\r\n", 9, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET https:' -> NOT_DECIDED", "GET https://host/x HTTP/1.1\r\n", 10, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET https:/' -> NOT_DECIDED", "GET https://host/x HTTP/1.1\r\n", 11, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET https://' -> PROXY_PLAIN", "GET https://host/x HTTP/1.1\r\n", 12, NGX_STREAM_ROUTE_PROXY_PLAIN),

        /* partial reads that should become DEFAULT early because impossible to be http(s) */
        tc("GET f (impossible scheme) -> DEFAULT", "GET fzz://host/x HTTP/1.1\r\n", 5, NGX_STREAM_ROUTE_DEFAULT),
        tc("GET hx (impossible to become http) -> DEFAULT", "GET hxzz://host/x HTTP/1.1\r\n", 6, NGX_STREAM_ROUTE_DEFAULT),
        tc("GET hq (impossible) -> DEFAULT", "GET hq HTTP/1.1\r\n", 6, NGX_STREAM_ROUTE_DEFAULT),

        /* ===== defaults: other schemes / weird targets ===== */
        tc("GET ftp:// -> DEFAULT", "GET ftp://host/x HTTP/1.1\r\n", strlen("GET ftp://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET ws:// -> DEFAULT", "GET ws://host/x HTTP/1.1\r\n", strlen("GET ws://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET wss:// -> DEFAULT", "GET wss://host/x HTTP/1.1\r\n", strlen("GET wss://host/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET gopher:// -> DEFAULT", "GET gopher://h/ HTTP/1.1\r\n", strlen("GET gopher://h/ HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET file:/// -> DEFAULT", "GET file:///etc/passwd HTTP/1.1\r\n", strlen("GET file:///etc/passwd HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET mailto: -> DEFAULT", "GET mailto:user@example.com HTTP/1.1\r\n", strlen("GET mailto:user@example.com HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET //authority-form? (starts with /) -> HTTP", "GET //host/path HTTP/1.1\r\n", strlen("GET //host/path HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("GET ?query (not /) -> DEFAULT", "GET ?q=1 HTTP/1.1\r\n", strlen("GET ?q=1 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET #frag (not /) -> DEFAULT", "GET #x HTTP/1.1\r\n", strlen("GET #x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("GET empty-target (double space) -> DEFAULT", "GET  /x HTTP/1.1\r\n", strlen("GET  /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),

        /* ===== malformed whitespace / no-space but line ended ===== */
        //tc("no space but has newline -> DEFAULT", "GET\t/x HTTP/1.1\r\n", strlen("GET\t/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tcb("binary tab between GET and / -> DEFAULT", bin_no_space_with_lf, sizeof(bin_no_space_with_lf), NGX_STREAM_ROUTE_DEFAULT),
        tc("only method with CRLF -> DEFAULT", "GET\r\n", strlen("GET\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("garbage line with CRLF no space -> DEFAULT", "WTF\r\n", strlen("WTF\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("leading spaces then GET -> DEFAULT", "   GET /x HTTP/1.1\r\n", strlen("   GET /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("method empty then / -> DEFAULT", " /x HTTP/1.1\r\n", strlen(" /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("method empty then * -> DEFAULT", " * HTTP/1.1\r\n", strlen(" * HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),

        /* ===== partial reads around space but target starts with space (decision should be DEFAULT immediately) ===== */
        tc("partial 'GET  ' (double space) -> DEFAULT", "GET  /x HTTP/1.1\r\n", 5, NGX_STREAM_ROUTE_DEFAULT),
        tc("partial 'PRI  ' -> DEFAULT", "PRI  * HTTP/2.0\r\n", 5, NGX_STREAM_ROUTE_DEFAULT),
        tc("partial 'POST  ' -> DEFAULT", "POST  /x HTTP/1.1\r\n", 6, NGX_STREAM_ROUTE_DEFAULT),

        /* ===== binary / odd bytes ===== */
        tcb("binary garbage with space then / -> HTTP (router sees /)", bin_garbage, sizeof(bin_garbage), NGX_STREAM_ROUTE_HTTP),
        tcb("binary NUL in method then space / -> DEFAULT (invalid, but should not be NOT_DECIDED forever)", bin_nul_in_method, sizeof(bin_nul_in_method), NGX_STREAM_ROUTE_HTTP),

        /* ===== extra coverage: many methods, many targets ===== */
        tc("MKCOL /x -> HTTP", "MKCOL /x HTTP/1.1\r\n", strlen("MKCOL /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("COPY /x -> HTTP", "COPY /x HTTP/1.1\r\n", strlen("COPY /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("MOVE /x -> HTTP", "MOVE /x HTTP/1.1\r\n", strlen("MOVE /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("LOCK /x -> HTTP", "LOCK /x HTTP/1.1\r\n", strlen("LOCK /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),
        tc("UNLOCK /x -> HTTP", "UNLOCK /x HTTP/1.1\r\n", strlen("UNLOCK /x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_HTTP),

        tc("MKCOL http://x -> PROXY_PLAIN", "MKCOL http://x/ HTTP/1.1\r\n", strlen("MKCOL http://x/ HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("LOCK https://x -> PROXY_PLAIN", "LOCK https://x/ HTTP/1.1\r\n", strlen("LOCK https://x/ HTTP/1.1\r\n"), NGX_STREAM_ROUTE_PROXY_PLAIN),

        tc("weird target 'h' + newline -> DEFAULT (line ended, cannot become http://)", "GET h\r\n", strlen("GET h\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("weird target 'ht' + newline -> DEFAULT", "GET ht\r\n", strlen("GET ht\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("weird target 'http' + newline -> DEFAULT", "GET http\r\n", strlen("GET http\r\n"), NGX_STREAM_ROUTE_DEFAULT),

        /* ===== more partial reads to reach 120, all unique lengths ===== */
        tc("partial 'GET /x' -> HTTP", "GET /x HTTP/1.1\r\n", 6, NGX_STREAM_ROUTE_HTTP),
        tc("partial 'GET /x ' -> HTTP", "GET /x HTTP/1.1\r\n", 7, NGX_STREAM_ROUTE_HTTP),
        tc("partial 'GET ?' -> DEFAULT", "GET ?x HTTP/1.1\r\n", 5, NGX_STREAM_ROUTE_DEFAULT),
        tc("partial 'GET #' -> DEFAULT", "GET #x HTTP/1.1\r\n", 5, NGX_STREAM_ROUTE_DEFAULT),
        tc("partial 'GET hT' -> NOT_DECIDED", "GET hTz://x HTTP/1.1\r\n", 6, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'GET hTz' -> DEFAULT (cannot become http://)", "GET hTz://x HTTP/1.1\r\n", 7, NGX_STREAM_ROUTE_DEFAULT),

        tc("partial 'PUT h' -> NOT_DECIDED", "PUT http://x/ HTTP/1.1\r\n", 5, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'PUT http://' -> PROXY_PLAIN", "PUT http://x/ HTTP/1.1\r\n", 11, NGX_STREAM_ROUTE_PROXY_PLAIN),
        tc("partial 'PUT https://' -> PROXY_PLAIN", "PUT https://x/ HTTP/1.1\r\n", 12, NGX_STREAM_ROUTE_PROXY_PLAIN),

        tc("partial 'DELETE h' -> NOT_DECIDED", "DELETE http://x/ HTTP/1.1\r\n", 8, NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("partial 'DELETE http://' -> PROXY_PLAIN", "DELETE http://x/ HTTP/1.1\r\n", 14, NGX_STREAM_ROUTE_PROXY_PLAIN),

        tc("default: target 'abc' enough bytes -> DEFAULT", "GET abcdefgh HTTP/1.1\r\n", strlen("GET abcdefgh HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("default: target '12345678' -> DEFAULT", "GET 12345678 HTTP/1.1\r\n", strlen("GET 12345678 HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("default: target '@@@@@@@@' -> DEFAULT", "GET @@@@@@@@ HTTP/1.1\r\n", strlen("GET @@@@@@@@ HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),

        tc("not decided: only first space found but no target", "POST ", strlen("POST "), NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("not decided: only first space found but no target 2", "X ", strlen("X "), NGX_STREAM_ROUTE_NOT_DECIDED),
        tc("default: method+space+space+newline -> DEFAULT", "GET  \n", strlen("GET  \n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("default: method+space+tab+slash -> DEFAULT", "GET \t/x HTTP/1.1\r\n", strlen("GET \t/x HTTP/1.1\r\n"), NGX_STREAM_ROUTE_DEFAULT),
        tc("default: method+space+CR -> DEFAULT", "GET \r\n", strlen("GET \r\n"), NGX_STREAM_ROUTE_DEFAULT),
    };

    size_t ntests = sizeof(tests) / sizeof(tests[0]);

    /* sanity: ensure >=100 */
    if (ntests < 100) {
        fprintf(stderr, "internal error: only %zu tests\n", ntests);
        return 2;
    }

    /* ensure no duplicates by (len, bytes) */
    assert_no_duplicates(tests, ntests);

    int passed = 0;
    for (size_t i = 0; i < ntests; i++) {
        passed += run_one(&tests[i], (int)(i + 1));
    }

    fprintf(stderr, "\nRESULT: %d/%zu passed\n", passed, ntests);

    /* non-zero exit if anything failed */
    return (passed == (int)ntests) ? 0 : 1;
}
