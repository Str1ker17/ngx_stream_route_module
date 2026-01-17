/*
 * nginx stream preread router (MSG_PEEK)
 *
 * Directives:
 *   stream_route_proxy_connect <addr:port>;  # CONNECT host:port
 *   stream_route_proxy_plain   <addr:port>;  # GET http(s)://host/path...
 *   stream_route_default       <addr:port>;  # GET /path...
 *                                            # PRI * HTTP/2...
 *
 * Variable:
 *   $stream_route
 */

/* ReSharper disable CppClangTidyClangDiagnosticExtraSemiStmt */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <errno.h>
#include <sys/socket.h>

#define STREAM_ROUTE_DEFAULT "127.0.0.1:80"
#define STREAM_ROUTE_PEEK_MAX 16

typedef enum {
    NGX_STREAM_ROUTE_NOT_DECIDED,
    NGX_STREAM_ROUTE_DEFAULT,
    NGX_STREAM_ROUTE_HTTP,
    NGX_STREAM_ROUTE_PROXY_PLAIN,
    NGX_STREAM_ROUTE_PROXY_CONNECT,
} ngx_stream_route_decision_t;

typedef struct {
    ngx_str_t route_proxy_connect;
    ngx_str_t route_proxy_plain;
    ngx_str_t route_http;
    ngx_str_t route_default;
} ngx_stream_route_srv_conf_t;

typedef struct {
    u_char line_buf[STREAM_ROUTE_PEEK_MAX];
    ngx_str_t line;
    ngx_str_t *stream_route;
    ngx_stream_route_decision_t decision;
} ngx_stream_route_ctx_t;

extern ngx_module_t ngx_stream_route_module;

static ngx_int_t
ngx_stream_route_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data) {
    ngx_stream_route_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_module);
    if (ctx == NULL || ctx->decision == NGX_STREAM_ROUTE_NOT_DECIDED) {
        /* variable should be used after preread */
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    v->len = (unsigned)ctx->stream_route->len;
    v->data = ctx->stream_route->data;

    return NGX_OK;
}

ngx_stream_route_decision_t stream_route_first_line_parse(const u_char *buf, size_t n) {
    const u_char *end = buf + n;
    u_char *method = (u_char *)buf;
    u_char *target = ngx_strlchr((u_char *)buf, (u_char *)end, ' ');
    if (target == NULL) {
        if ((ngx_strlchr((u_char *)buf, (u_char *)end, '\n') != NULL) ||
            (ngx_strlchr((u_char *)buf, (u_char *)end, '\r') != NULL)) {
            return NGX_STREAM_ROUTE_DEFAULT;
        }
        return NGX_STREAM_ROUTE_NOT_DECIDED;
    }
    if (target == method) { /* empty method, not HTTP */
        return NGX_STREAM_ROUTE_DEFAULT;
    }
    if (target - method == 7 && ngx_strncasecmp(method, (u_char *)"CONNECT", 7) == 0) {
        return NGX_STREAM_ROUTE_PROXY_CONNECT;
    }
    n -= (target - method);
    if (n <= 1) {
        return NGX_STREAM_ROUTE_NOT_DECIDED;
    }
    ++target;
    --n;
    if (target[0] == '/' || target[0] == '*') {
        return NGX_STREAM_ROUTE_HTTP;
    }
    if (ngx_strncasecmp(target, (u_char *)"http://", ngx_min(n, 7)) == 0) {
        return n >= 7 ? NGX_STREAM_ROUTE_PROXY_PLAIN : NGX_STREAM_ROUTE_NOT_DECIDED;
    }
    if (ngx_strncasecmp(target, (u_char *)"https://", ngx_min(n, 8)) == 0) {
        return n >= 8 ? NGX_STREAM_ROUTE_PROXY_PLAIN : NGX_STREAM_ROUTE_NOT_DECIDED;
    }

    return NGX_STREAM_ROUTE_DEFAULT;
}

static ngx_int_t ngx_stream_route_preread(ngx_stream_session_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_stream_route_srv_conf_t *scf = ngx_stream_get_module_srv_conf(s, ngx_stream_route_module);
    ngx_stream_route_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_module);

    if (ctx != NULL && ctx->decision != NGX_STREAM_ROUTE_NOT_DECIDED) {
        return NGX_OK;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->line.data = ctx->line_buf;
        ngx_stream_set_ctx(s, ctx, ngx_stream_route_module);
    }

    ssize_t n = recv(c->fd, ctx->line_buf, sizeof(ctx->line_buf), MSG_PEEK);
    if (n == 0) { /* EOF, nothing to route */
        return NGX_OK;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return NGX_AGAIN;
        }
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "recv(c->fd, ..., MSK_PEEK) = %z", n);
        return NGX_ERROR;
    }

    ctx->line.len = n;
    ctx->decision = stream_route_first_line_parse(ctx->line.data, ctx->line.len);
    ngx_log_debug2(
        NGX_LOG_DEBUG_STREAM, c->log, 0, "request line=%V decision=%ud", &ctx->line, ctx->decision
    );

    switch (ctx->decision) {
        case NGX_STREAM_ROUTE_NOT_DECIDED:
            return NGX_AGAIN;
        case NGX_STREAM_ROUTE_PROXY_CONNECT:
            ctx->stream_route = &scf->route_proxy_connect;
            break;
        case NGX_STREAM_ROUTE_PROXY_PLAIN:
            ctx->stream_route = &scf->route_proxy_plain;
            break;
        case NGX_STREAM_ROUTE_HTTP:
            ctx->stream_route = &scf->route_http;
            break;
        case NGX_STREAM_ROUTE_DEFAULT:
            ctx->stream_route = &scf->route_default;
            break;
        default:
            ngx_log_error(NGX_LOG_ALERT, c->log, 0, "unknown decision %ud", ctx->decision);
            return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_stream_route_postconf(ngx_conf_t *cf) {
    ngx_stream_variable_t *stream_route_var;
    static ngx_str_t name = ngx_string("stream_route");

    stream_route_var =
        ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_NOCACHEABLE | NGX_STREAM_VAR_INDEXED);
    if (stream_route_var == NULL) {
        return NGX_ERROR;
    }

    stream_route_var->get_handler = ngx_stream_route_variable;
    stream_route_var->data = 0;

    ngx_stream_core_main_conf_t *cmcf;
    ngx_stream_handler_pt *h;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    h = (ngx_stream_handler_pt *)ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_route_preread;
    return NGX_OK;
}

static void *ngx_stream_route_create_srv_conf(ngx_conf_t *cf) {
    return ngx_pcalloc(cf->pool, sizeof(ngx_stream_route_srv_conf_t));
}

static char *ngx_stream_route_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_stream_route_srv_conf_t *prev = parent;
    ngx_stream_route_srv_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->route_default, prev->route_default, STREAM_ROUTE_DEFAULT);

    /* connect/plain can be empty => fallback to route_default */
    ngx_conf_merge_str_value(conf->route_proxy_connect, prev->route_proxy_connect, "");
    if (!conf->route_proxy_connect.len) conf->route_proxy_connect = conf->route_default;
    ngx_conf_merge_str_value(conf->route_proxy_plain, prev->route_proxy_plain, "");
    if (!conf->route_proxy_plain.len) conf->route_proxy_plain = conf->route_default;
    ngx_conf_merge_str_value(conf->route_http, prev->route_http, "");
    if (!conf->route_http.len) conf->route_http = conf->route_default;

    return NGX_CONF_OK;
}

static ngx_command_t ngx_stream_route_commands[] = {
    {ngx_string("stream_route_proxy_connect"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_route_srv_conf_t, route_proxy_connect),
     NULL},

    {ngx_string("stream_route_proxy_plain"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_route_srv_conf_t, route_proxy_plain),
     NULL},

    {ngx_string("stream_route_http"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_route_srv_conf_t, route_http),
     NULL},

    {ngx_string("stream_route_default"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_str_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_route_srv_conf_t, route_default),
     NULL},

    ngx_null_command
};

static ngx_stream_module_t ngx_stream_route_module_ctx = {
    NULL,                      /* preconfiguration */
    ngx_stream_route_postconf, /* postconfiguration */

    NULL, /* create main conf */
    NULL, /* init main conf */

    ngx_stream_route_create_srv_conf, /* create srv conf */
    ngx_stream_route_merge_srv_conf,  /* merge srv conf */
};

ngx_module_t ngx_stream_route_module = {
    NGX_MODULE_V1,
    &ngx_stream_route_module_ctx, /* module context */
    ngx_stream_route_commands,    /* module directives */
    NGX_STREAM_MODULE,            /* module type */
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};
