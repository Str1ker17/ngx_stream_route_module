/*
 * nginx stream preread router (MSG_PEEK)
 *
 * Directives:
 *   stream_route_enable <on|off>;
 *
 * Variables:
 *   $stream_route_type: string
 *
 *   Supported values:
 *     - 'http'             # GET /path
 *                          # POST /path
 *                          # PRI *
 *     - 'proxy_plain'      # GET http://host/path...
 *                          # POST https://host/path...
 *     - 'proxy_connect'    # CONNECT host:port
 *     - 'proxy_socks'      # [0x05, 0x00] for SOCKS5 or [0x04, 0x00] for SOCKS4
 *     - 'proxy_tls'        # [0x16] - TLS ClientHello

 *     - 'unknown'          # none of the above
 *
 *   $stream_route_is_proxy: bool
 */

/* ReSharper disable CppClangTidyClangDiagnosticExtraSemiStmt */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <errno.h>
#include <sys/socket.h>

/* The longest string we need to decide for sure is "DELETE https://" which is 15 chars long. */
#define NGX_STREAM_ROUTE_PEEK_MAX 16

typedef enum {
    NGX_STREAM_ROUTE_TYPE_NOT_DECIDED,
    NGX_STREAM_ROUTE_TYPE_UNKNOWN,
    NGX_STREAM_ROUTE_TYPE_HTTP, /* direct, should be handled as a usual http request */
    NGX_STREAM_ROUTE_TYPE_PROXY_PLAIN,
    NGX_STREAM_ROUTE_TYPE_PROXY_CONNECT,
    NGX_STREAM_ROUTE_TYPE_PROXY_SOCKS,
    NGX_STREAM_ROUTE_TYPE_PROXY_TLS, /* if for a reason you need TLS in TLS */
} ngx_stream_route_type_t;

static const ngx_stream_variable_value_t ngx_stream_route_type_str[] = {
    [NGX_STREAM_ROUTE_TYPE_NOT_DECIDED] = ngx_stream_variable("not_decided"),
    [NGX_STREAM_ROUTE_TYPE_UNKNOWN] = ngx_stream_variable("unknown"),
    [NGX_STREAM_ROUTE_TYPE_HTTP] = ngx_stream_variable("http"),
    [NGX_STREAM_ROUTE_TYPE_PROXY_PLAIN] = ngx_stream_variable("proxy_plain"),
    [NGX_STREAM_ROUTE_TYPE_PROXY_CONNECT] = ngx_stream_variable("proxy_connect"),
    [NGX_STREAM_ROUTE_TYPE_PROXY_SOCKS] = ngx_stream_variable("proxy_socks"),
    [NGX_STREAM_ROUTE_TYPE_PROXY_TLS] = ngx_stream_variable("proxy_tls"),
};

typedef enum {
    NGX_STREAM_ROUTE_VARIABLE_TYPE,
    NGX_STREAM_ROUTE_VARIABLE_PROXY, /* Quickly answer "is proxy?" */
} ngx_stream_route_variable_t;

static const ngx_str_t ngx_stream_route_variables[] = {
    [NGX_STREAM_ROUTE_VARIABLE_TYPE] = ngx_string("stream_route_type"),
    [NGX_STREAM_ROUTE_VARIABLE_PROXY] = ngx_string("stream_route_is_proxy"),
};

typedef struct {
    ngx_flag_t enabled;
} ngx_stream_route_srv_conf_t;

typedef struct {
    u_char line_buf[NGX_STREAM_ROUTE_PEEK_MAX];
    ngx_str_t line;
    ngx_stream_route_type_t decision;
} ngx_stream_route_ctx_t;

extern ngx_module_t ngx_stream_route_module;

static ngx_int_t
ngx_stream_route_variable(ngx_stream_session_t *s, ngx_stream_variable_value_t *v, uintptr_t data) {
    ngx_stream_route_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_module);
    if (ctx == NULL) {
        /* Variable should be used after preread. */
        v->not_found = 1;
        return NGX_OK;
    }

    switch ((ngx_stream_route_variable_t)data) {
        case NGX_STREAM_ROUTE_VARIABLE_TYPE:
            *v = ngx_stream_route_type_str[ctx->decision];
            break;
        case NGX_STREAM_ROUTE_VARIABLE_PROXY:
            v->len = 1;
            v->data = (u_char *)((ctx->decision == NGX_STREAM_ROUTE_TYPE_HTTP ||
                                  ctx->decision == NGX_STREAM_ROUTE_TYPE_UNKNOWN)
                                     ? "0"
                                     : "1");
            break;
        default:
            v->valid = 0;
            break;
    }

    return NGX_OK;
}

ngx_stream_route_type_t stream_route_first_line_parse(const u_char *buf, size_t n) {
    switch (buf[0]) {
        case 0x04:
        case 0x05:
            return NGX_STREAM_ROUTE_TYPE_PROXY_SOCKS;
        case 0x16:
            return NGX_STREAM_ROUTE_TYPE_PROXY_TLS;
    }
    const u_char *end = buf + n;
    u_char *method = (u_char *)buf;
    u_char *target = ngx_strlchr((u_char *)buf, (u_char *)end, ' ');
    if (target == NULL) {
        if ((ngx_strlchr((u_char *)buf, (u_char *)end, '\n') != NULL) ||
            (ngx_strlchr((u_char *)buf, (u_char *)end, '\r') != NULL)) {
            return NGX_STREAM_ROUTE_TYPE_UNKNOWN;
        }
        return NGX_STREAM_ROUTE_TYPE_NOT_DECIDED;
    }
    if (target == method) { /* empty method, not HTTP */
        return NGX_STREAM_ROUTE_TYPE_UNKNOWN;
    }
    if (target - method == 7 && ngx_strncasecmp(method, (u_char *)"CONNECT", 7) == 0) {
        return NGX_STREAM_ROUTE_TYPE_PROXY_CONNECT;
    }
    n -= (target - method);
    if (n <= 1) {
        return NGX_STREAM_ROUTE_TYPE_NOT_DECIDED;
    }
    ++target;
    --n;
    if (target[0] == '/' || target[0] == '*') {
        return NGX_STREAM_ROUTE_TYPE_HTTP;
    }
    if (ngx_strncasecmp(target, (u_char *)"http://", ngx_min(n, 7)) == 0) {
        return n >= 7 ? NGX_STREAM_ROUTE_TYPE_PROXY_PLAIN : NGX_STREAM_ROUTE_TYPE_NOT_DECIDED;
    }
    if (ngx_strncasecmp(target, (u_char *)"https://", ngx_min(n, 8)) == 0) {
        return n >= 8 ? NGX_STREAM_ROUTE_TYPE_PROXY_PLAIN : NGX_STREAM_ROUTE_TYPE_NOT_DECIDED;
    }

    return NGX_STREAM_ROUTE_TYPE_UNKNOWN;
}

static ngx_int_t ngx_stream_route_preread(ngx_stream_session_t *s) {
    ngx_connection_t *c = s->connection;
    ngx_stream_route_srv_conf_t *scf = ngx_stream_get_module_srv_conf(s, ngx_stream_route_module);
    ngx_stream_route_ctx_t *ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_module);

    if (!scf->enabled) {
        return NGX_OK;
    }

    if (ctx != NULL && ctx->decision != NGX_STREAM_ROUTE_TYPE_NOT_DECIDED) {
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

    ssize_t n = recv(c->fd, ctx->line_buf, sizeof(ctx->line_buf), MSG_PEEK | MSG_DONTWAIT);
    if (n == 0) { /* EOF, nothing to route. */
        return NGX_OK;
    }
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return NGX_AGAIN;
        }
        ngx_log_error(NGX_LOG_ERR, c->log, errno, "recv(c->fd, ..., MSG_PEEK) = %z", n);
        return NGX_ERROR;
    }

    ctx->line.len = n;
    ctx->decision = stream_route_first_line_parse(ctx->line.data, ctx->line.len);

    ngx_log_debug2(
        NGX_LOG_DEBUG_STREAM,
        c->log,
        0,
        "request line=%V decision=%v",
        &ctx->line,
        &ngx_stream_route_type_str[ctx->decision]
    );

    if (ctx->decision == NGX_STREAM_ROUTE_TYPE_NOT_DECIDED) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}

static ngx_int_t ngx_stream_route_postconf(ngx_conf_t *cf) {
    for (unsigned i = 0;
         i < sizeof(ngx_stream_route_variables) / sizeof(ngx_stream_route_variables[0]);
         ++i) {
        const ngx_str_t *stream_route_variable_name = &ngx_stream_route_variables[i];
        ngx_stream_variable_t *stream_route_variable = ngx_stream_add_variable(
            cf,
            (ngx_str_t *)stream_route_variable_name,
            NGX_STREAM_VAR_NOCACHEABLE | NGX_STREAM_VAR_INDEXED
        );
        if (stream_route_variable == NULL) {
            return NGX_ERROR;
        }

        stream_route_variable->get_handler = ngx_stream_route_variable;
        stream_route_variable->data = i;
    }

    ngx_stream_core_main_conf_t *cmcf =
        ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    ngx_stream_handler_pt *h =
        (ngx_stream_handler_pt *)ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_route_preread;
    return NGX_OK;
}

static void *ngx_stream_route_create_srv_conf(ngx_conf_t *cf) {
    ngx_stream_route_srv_conf_t *conf =  ngx_pcalloc(cf->pool, sizeof(ngx_stream_route_srv_conf_t));
    if (conf != NULL) {
        conf->enabled = NGX_CONF_UNSET;
    }
    return conf;
}

static char *ngx_stream_route_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_stream_route_srv_conf_t *prev = parent;
    ngx_stream_route_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enabled, prev->enabled, 0);
    return NGX_CONF_OK;
}

static ngx_command_t ngx_stream_route_commands[] = {
    {ngx_string("stream_route_enable"),
     NGX_STREAM_MAIN_CONF | NGX_STREAM_SRV_CONF | NGX_CONF_TAKE1,
     ngx_conf_set_flag_slot,
     NGX_STREAM_SRV_CONF_OFFSET,
     offsetof(ngx_stream_route_srv_conf_t, enabled),
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
