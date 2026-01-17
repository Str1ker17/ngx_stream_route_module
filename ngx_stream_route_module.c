/*
 * nginx 1.24.0 stream preread router (MSG_PEEK)
 *
 * Directives:
 *   route_traffic_proxy_connect  <addr:port>;  # CONNECT host:port
 *   route_traffic_proxy_plain    <addr:port>;  # absolute-form:  http(s)://...
 *   route_traffic_default        <addr:port>;  # origin-form:    /path
 *
 * Variable:
 *   $route_traffic
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <sys/socket.h>
#include <errno.h>

#define ROUTE_PEEK_MAX 4096

typedef struct {
    ngx_str_t  route_connect;
    ngx_str_t  route_plain;
    ngx_str_t  route_default;
} ngx_stream_route_srv_conf_t;

typedef struct {
    ngx_str_t  route;
    ngx_uint_t done;
} ngx_stream_route_ctx_t;

static ngx_int_t ngx_stream_route_preread(ngx_stream_session_t *s);
static ngx_int_t ngx_stream_route_variable(ngx_stream_session_t *s,
                                                   ngx_stream_variable_value_t *v,
                                                   uintptr_t data);

static void *ngx_stream_route_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_route_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_stream_route_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_stream_route_postconf(ngx_conf_t *cf);

static ngx_command_t ngx_stream_route_commands[] = {

    { ngx_string("route_traffic_proxy_connect"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_route_srv_conf_t, route_connect),
      NULL },

    { ngx_string("route_traffic_proxy_plain"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_route_srv_conf_t, route_plain),
      NULL },

    { ngx_string("route_traffic_default"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_route_srv_conf_t, route_default),
      NULL },

    ngx_null_command
};

static ngx_stream_module_t ngx_stream_route_module_ctx = {
    ngx_stream_route_preconf,     /* preconfiguration */
    ngx_stream_route_postconf,    /* postconfiguration */

    NULL,                                 /* create main conf */
    NULL,                                 /* init main conf */

    ngx_stream_route_create_srv_conf, /* create srv conf */
    ngx_stream_route_merge_srv_conf,  /* merge srv conf */
};

ngx_module_t ngx_stream_route_module = {
    NGX_MODULE_V1,
    &ngx_stream_route_module_ctx, /* module context */
    ngx_stream_route_commands,    /* module directives */
    NGX_STREAM_MODULE,                    /* module type */
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_int_t
ngx_stream_route_preconf(ngx_conf_t *cf)
{
    ngx_stream_variable_t *var;
    ngx_str_t name = ngx_string("route_traffic");

    var = ngx_stream_add_variable(cf, &name, NGX_STREAM_VAR_CHANGEABLE);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_stream_route_variable;
    var->data = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_stream_route_postconf(ngx_conf_t *cf)
{
    ngx_stream_core_main_conf_t *cmcf;
    ngx_stream_handler_pt       *h;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf == NULL) {
        return NGX_ERROR;
    }

    h = ngx_array_push(&cmcf->phases[NGX_STREAM_PREREAD_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_stream_route_preread;
    return NGX_OK;
}

static void *
ngx_stream_route_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_route_srv_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL) {
        return NULL;
    }

    /* all empty by default; merge will set defaults */
    conf->route_connect.len = 0;
    conf->route_connect.data = NULL;

    conf->route_plain.len = 0;
    conf->route_plain.data = NULL;

    conf->route_default.len = 0;
    conf->route_default.data = NULL;

    return conf;
}

static char *
ngx_stream_route_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_route_srv_conf_t *prev = parent;
    ngx_stream_route_srv_conf_t *conf = child;

    /* default backend if user didn't set it */
    ngx_conf_merge_str_value(conf->route_default, prev->route_default, "127.0.0.1:80");

    /* connect/plain can be empty => fallback to route_default */
    ngx_conf_merge_str_value(conf->route_connect, prev->route_connect, "");
    ngx_conf_merge_str_value(conf->route_plain,   prev->route_plain,   "");

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_stream_route_variable(ngx_stream_session_t *s,
                                  ngx_stream_variable_value_t *v,
                                  uintptr_t data)
{
    ngx_stream_route_ctx_t *ctx;
    (void) data;

    ctx = ngx_stream_get_module_ctx(s, ngx_stream_route_module);

    if (ctx == NULL || !ctx->done || ctx->route.len == 0 || ctx->route.data == NULL) {
        /* variable should be used after preread decided; if not yet, treat as not found */
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->len = ctx->route.len;
    v->data = ctx->route.data;

    return NGX_OK;
}

static ngx_inline ngx_int_t
route_parse_first_line(const u_char *buf, size_t n, ngx_str_t *method, ngx_str_t *target)
{
    size_t i;
    ssize_t lf = -1;

    for (i = 0; i < n; i++) {
        if (buf[i] == '\n') { lf = (ssize_t)i; break; }
    }
    if (lf < 0) {
        return NGX_AGAIN;
    }

    size_t line_end = (size_t) lf;
    if (line_end > 0 && buf[line_end - 1] == '\r') {
        line_end--;
    }
    if (line_end == 0) {
        return NGX_ERROR;
    }

    size_t sp1 = (size_t)-1, sp2 = (size_t)-1;
    for (i = 0; i < line_end; i++) {
        if (buf[i] == ' ') { sp1 = i; break; }
    }
    if (sp1 == (size_t)-1 || sp1 == 0) {
        return NGX_ERROR;
    }
    for (i = sp1 + 1; i < line_end; i++) {
        if (buf[i] == ' ') { sp2 = i; break; }
    }
    if (sp2 == (size_t)-1 || sp2 <= sp1 + 1) {
        return NGX_ERROR;
    }

    method->data = (u_char *) buf;
    method->len  = sp1;

    target->data = (u_char *) (buf + sp1 + 1);
    target->len  = sp2 - (sp1 + 1);

    return NGX_OK;
}

static ngx_int_t
ngx_stream_route_preread(ngx_stream_session_t *s)
{
    ngx_connection_t *c = s->connection;

    ngx_stream_route_ctx_t *ctx =
        ngx_stream_get_module_ctx(s, ngx_stream_route_module);

    if (ctx != NULL && ctx->done) {
        return NGX_OK;
    }

    if (ctx == NULL) {
        ctx = ngx_pcalloc(c->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ngx_stream_set_ctx(s, ctx, ngx_stream_route_module);
    }

    ngx_stream_route_srv_conf_t *scf =
        ngx_stream_get_module_srv_conf(s, ngx_stream_route_module);

    u_char buf[ROUTE_PEEK_MAX];

    ssize_t n = recv(c->fd, buf, sizeof(buf), MSG_PEEK);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return NGX_AGAIN;
        }
        return NGX_ERROR;
    }
    if (n == 0) {
        return NGX_OK;
    }

    ngx_str_t method = ngx_null_string;
    ngx_str_t target = ngx_null_string;

    ngx_int_t rc = route_parse_first_line(buf, (size_t)n, &method, &target);
    if (rc == NGX_AGAIN) {
        return NGX_AGAIN;
    }

    /* default if can't parse */
    if (rc != NGX_OK) {
        ctx->route = scf->route_default;
        ctx->done = 1;
        return NGX_OK;
    }

    /* CONNECT => route_connect (or fallback to default) */
    if (method.len == (sizeof("CONNECT") - 1)
        && ngx_strncasecmp(method.data, (u_char *)"CONNECT", method.len) == 0)
    {
        ctx->route = (scf->route_connect.len ? scf->route_connect : scf->route_default);
        ctx->done = 1;
        return NGX_OK;
    }

    /* absolute-form => route_plain (or fallback to default) */
    if (target.len >= (sizeof("http://") - 1)
        && ngx_strncasecmp(target.data, (u_char *)"http://", sizeof("http://") - 1) == 0)
    {
        ctx->route = (scf->route_plain.len ? scf->route_plain : scf->route_default);
        ctx->done = 1;
        return NGX_OK;
    }

    if (target.len >= (sizeof("https://") - 1)
        && ngx_strncasecmp(target.data, (u_char *)"https://", sizeof("https://") - 1) == 0)
    {
        ctx->route = (scf->route_plain.len ? scf->route_plain : scf->route_default);
        ctx->done = 1;
        return NGX_OK;
    }

    /* origin-form (/path) => default */
    ctx->route = scf->route_default;
    ctx->done = 1;
    return NGX_OK;
}
