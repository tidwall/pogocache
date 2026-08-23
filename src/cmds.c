// https://github.com/tidwall/pogocache
//
// Copyright 2025 Polypoint Labs, LLC. All rights reserved.
// This file is part of the Pogocache project.
// Use of this source code is governed by the MIT that can be found in
// the LICENSE file.
//
// For alternative licensing options or general questions, please contact
// us at licensing@polypointlabs.com.
//
// Unit cmd.c handles all incoming client commands.
#include <stdlib.h>
#include <stdatomic.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <stdarg.h>
#include "save.h"
#include "parse.h"
#include "util.h"
#include "sys.h"
#include "cmds.h"
#include "conn.h"
#include "xmalloc.h"
#include "pogocache.h"
#include "stats.h"
#include "monitor.h"
#include "tls.h"

// from main.c
extern const uint64_t seed;
extern const char *path;
extern const int verb;
extern const char *auth;
extern const bool useauth;
extern const char *persist;
extern const int nthreads;
extern const char *version;
extern const char *githash;
extern atomic_bool sweep;
extern atomic_bool lowmem;
extern const int nshards;
extern const int narenas;
extern const int64_t procstart;
extern const int maxconns;
extern atomic_bool monitoring;

extern struct pogocache *cache;

struct set_entry_context {
    bool written;
    struct conn *conn;
    const char *cmdname;
};

static bool set_entry(int shard, int64_t time, const void *key,
    size_t keylen, const void *val, size_t vallen, int64_t expires,
    uint32_t flags, uint64_t cas, void *udata)
{
    (void)shard, (void)time, (void)key, (void)keylen, (void)val, (void)vallen,
    (void)expires, (void)flags, (void)cas;
    struct set_entry_context *ctx = udata;
    if (conn_proto(ctx->conn) == PROTO_POSTGRES) {
        pg_write_row_desc(ctx->conn, (const char*[]){ "value" }, 1);
        pg_write_row_data(ctx->conn, (const char*[]){ val }, 
            (size_t[]){ vallen }, 1);
        pg_write_completef(ctx->conn, "%s 1", ctx->cmdname);
        pg_write_ready(ctx->conn, 'I');
    } else {
        conn_write_bulk(ctx->conn, val, vallen);
    }
    ctx->written = true;
    return true;
}

static void execSET(struct conn *conn, const char *cmdname, 
    int64_t now, const char *key,
    size_t keylen, const char *val, size_t vallen, int64_t expires, bool nx,
    bool xx, bool get, bool keepttl, uint32_t flags, uint64_t cas, bool withcas)
{
    stat_cmd_set_incr(conn);
    struct set_entry_context ctx = { .conn = conn, .cmdname = cmdname };
    struct pogocache_store_opts opts = {
        .time = now,
        .expires = expires,
        .cas = cas,
        .flags = flags,
        .keepttl = keepttl,
        .casop = withcas,
        .nx = nx,
        .xx = xx,
        .lowmem = atomic_load_explicit(&lowmem, __ATOMIC_ACQUIRE),
        .entry = get?set_entry:0,
        .udata = get?&ctx:0,
    };
    int status = pogocache_store(cache, key, keylen, val, vallen, &opts);
    if (status == POGOCACHE_NOMEM) {
        stat_store_no_memory_incr(conn);
        conn_write_error(conn, ERR_OUT_OF_MEMORY);
        return;
    }
    if (get) {
        if (!ctx.written) {
            if (conn_proto(conn) == PROTO_POSTGRES) {
                pg_write_row_desc(conn, (const char*[]){ "value" }, 1);
                pg_write_completef(conn, "%s 0", cmdname);
                pg_write_ready(conn, 'I');
            } else {
                conn_write_null(conn);
            }
        }
        return;
    }
    bool stored = status == POGOCACHE_INSERTED || status == POGOCACHE_REPLACED;
    switch (conn_proto(conn)) {
    case PROTO_MEMCACHE:
        if (!stored) {
            if (status == POGOCACHE_FOUND) {
                conn_write_raw(conn, "EXISTS\r\n", 8);
            } else {
                conn_write_raw(conn, "NOT_FOUND\r\n", 12);
            }
        } else {
            conn_write_raw(conn, "STORED\r\n", 8);
        }
        break;
    case PROTO_HTTP:
        if (!stored) {
            conn_write_http(conn, 404, "Not Found", "Not Found\r\n", -1);
        } else {
            conn_write_http(conn, 200, "OK", "Stored\r\n", -1);
        }
        break;
    case PROTO_POSTGRES:
        pg_write_completef(conn, "%s %d", cmdname, stored?1:0);
        pg_write_ready(conn, 'I');
        break;
    default:
        if (!stored) {
            conn_write_null(conn);
        } else {
            conn_write_string(conn, "OK");
        }
        break;
    }
}

static int64_t expiry_seconds_time(struct conn *conn, int64_t now, 
    int64_t expiry)
{
    if (conn_proto(conn) == PROTO_MEMCACHE && expiry > HOUR*24*30) {
        // Consider Unix time value rather than an offset from current time.
        int64_t unix_ = sys_unixnow();
        if (expiry > unix_) {
            expiry = expiry-sys_unixnow();
        } else {
            expiry = 0;
        }
    }
    return int64_add_clamp(now, expiry);
}

// SET key value [NX | XX] [GET] [EX seconds | PX milliseconds |
//   EXAT unix-time-seconds | PXAT unix-time-milliseconds | KEEPTTL] 
//   [FLAGS flags] [CAS cas] 
static void cmdSET(struct conn *conn, struct args *args) {
#ifdef CMDSETOK
    // For testing the theoretical top speed of a single SET command.
    // No data is stored.
    if (conn_proto(conn) == PROTO_MEMCACHE) {
        conn_write_raw(conn, "STORED\r\n", 8);
    } else {
        conn_write_string(conn, "OK");
    }
    return;
#endif
    // RESP command
    if (args->len < 3) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    const char *key = args->bufs[1].data;
    size_t keylen = args->bufs[1].len;
    const char *val = args->bufs[2].data;
    size_t vallen = args->bufs[2].len;
    int64_t expires = 0;
    int exkind = 0;
    bool nx = false;
    bool xx = false;
    bool get = false;
    bool keepttl = false;
    bool hasex = false;
    uint32_t flags = 0;
    uint64_t cas = 0;
    bool withcas = false;
    for (size_t i = 3; i < args->len; i++) {
        if (argeq(args, i, "ex")) {
            exkind = 1;
            goto parse_ex;
        } else if (argeq(args, i, "px")) {
            exkind = 2;
            goto parse_ex;
        } else if (argeq(args, i, "exat")) {
            exkind = 3;
            goto parse_ex;
        } else if (argeq(args, i, "pxat")) {
            exkind = 4;
        parse_ex:
            i++;
            if (i == args->len) {
                goto err_syntax;
            }
            bool ok = parse_i64(args->bufs[i].data, args->bufs[i].len, 
                &expires);
            if (!ok) {
                conn_write_error(conn, "ERR invalid expire time");
                return;
            }
            if (expires <= 0) {
                if (conn_proto(conn) == PROTO_MEMCACHE) {
                    // memcache allows for negative expiration
                    expires = expiry_seconds_time(conn, now, 0);
                    goto skip_exkind;
                } else {
                    conn_write_error(conn, "ERR invalid expire time");
                    return;
                }
            }
            switch (exkind) {
            case 1:
                expires = int64_mul_clamp(expires, SECOND);
                expires = expiry_seconds_time(conn, now, expires);
                break;
            case 2:
                expires = int64_mul_clamp(expires, MILLISECOND);
                expires = expiry_seconds_time(conn, now, expires);
                break;
            case 3:
                expires = int64_mul_clamp(expires, SECOND);
                break;
            case 4:
                expires = int64_mul_clamp(expires, MILLISECOND);
                break;
            }
        skip_exkind:
            hasex = true;
        } else if (argeq(args, i, "nx")) {
            nx = true;
        } else if (argeq(args, i, "xx")) {
            xx = true;
        } else if (argeq(args, i, "get")) {
            get = true;
        } else if (argeq(args, i, "keepttl")) {
            keepttl = true;
        } else if (argeq(args, i, "flags")) {
            i++;
            if (i == args->len) {
                goto err_syntax;
            }
            uint64_t x;
            if (!argu64(args, i, &x)) {
                goto err_syntax;
            }
            flags = x&UINT32_MAX;
        } else if (argeq(args, i, "cas")) {
            i++;
            if (i == args->len) {
                goto err_syntax;
            }
            if (!argu64(args, i, &cas)) {
                goto err_syntax;
            }
            withcas = true;
        } else {
            goto err_syntax;
        }
    }
    assert(expires >= 0);
    if (keepttl && hasex > 0){
        goto err_syntax;
    }
    if (xx && nx > 0){
        goto err_syntax;
    }
    execSET(conn, "SET", now, key, keylen, val, vallen, expires, nx, xx, get,
        keepttl, flags, cas, withcas);
    return;
err_syntax:
    conn_write_error(conn, ERR_SYNTAX_ERROR);
}

static void cmdSETEX(struct conn *conn, struct args *args) {
    if (args->len != 4) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    int64_t ex = 0;
    const char *key = args->bufs[1].data;
    size_t keylen = args->bufs[1].len;
    bool ok = parse_i64(args->bufs[2].data, args->bufs[2].len, &ex);
    if (!ok || ex <= 0) {
        conn_write_error(conn, "ERR invalid expire time");
        return;
    }
    ex = int64_mul_clamp(ex, SECOND);
    ex = int64_add_clamp(sys_now(), ex);
    const char *val = args->bufs[3].data;
    size_t vallen = args->bufs[3].len;
    execSET(conn, "SETEX", now, key, keylen, val, vallen, ex, 0, 0, 0, 0, 0, 0,
        0);
}

enum get_entry_kind {
    KIND_GET, KIND_MGET, KIND_MGETS, 
};

struct get_entry_context {
    struct conn *conn;
    enum get_entry_kind kind;
};

static void get_entry(int shard, int64_t time, const void *key, size_t keylen,
    const void *val, size_t vallen, int64_t expires, uint32_t flags,
    uint64_t cas, struct pogocache_update **update, void *udata)
{
    (void)shard, (void)time, (void)expires, (void)flags, (void)update;
    struct get_entry_context *ctx = udata;
    uint8_t buf[24];
    switch (conn_proto(ctx->conn)) {
    case PROTO_POSTGRES:;
        char flagsbuf[24];
        size_t flagsn = snprintf(flagsbuf, sizeof(flagsbuf), "%" PRIu32, flags);
        char casbuf[24];
        size_t casn = snprintf(casbuf, sizeof(casbuf), "%" PRIu64, cas);
        switch (ctx->kind) {
        case KIND_GET:
            pg_write_row_data(ctx->conn, (const char*[]){ val, }, 
                (size_t[]){ vallen }, 1);
            break;
        case KIND_MGET:
            pg_write_row_data(ctx->conn, (const char*[]){ key, val }, 
                (size_t[]){ keylen, vallen }, 2);
            break;
        case KIND_MGETS:
            pg_write_row_data(ctx->conn, 
                (const char*[]){ key, flagsbuf, casbuf, val }, 
                (size_t[]){ keylen, flagsn, casn, vallen }, 
                4);
            break;
        }
        break;
    case PROTO_MEMCACHE:
        conn_write_raw(ctx->conn, "VALUE ", 6);
        conn_write_raw(ctx->conn, key, keylen);
        size_t n = u64toa(flags, buf);
        conn_write_raw(ctx->conn, " ", 1);
        conn_write_raw(ctx->conn, buf, n);
        n = u64toa(vallen, buf);
        conn_write_raw(ctx->conn, " ", 1);
        conn_write_raw(ctx->conn, buf, n);
        if (ctx->kind == KIND_MGETS) {
            n = u64toa(cas, buf);
            conn_write_raw(ctx->conn, " ", 1);
            conn_write_raw(ctx->conn, buf, n);
        }
        conn_write_raw(ctx->conn, "\r\n", 2);
        conn_write_raw(ctx->conn, val, vallen);
        conn_write_raw(ctx->conn, "\r\n", 2);
        break;
    case PROTO_HTTP:
        conn_write_http(ctx->conn, 200, "OK", val, vallen);
        break;
    default:
        if (ctx->kind == KIND_MGETS) {
            conn_write_array(ctx->conn, 3);
            conn_write_uint(ctx->conn, flags);
            conn_write_uint(ctx->conn, cas);
        }
        conn_write_bulk(ctx->conn, val, vallen);
        break;
    }
}

// GET key
static void cmdGET(struct conn *conn, struct args *args) {
    stat_cmd_get_incr(conn);
#ifdef CMDGETNIL
    conn_write_null(conn);
    return;
#endif
#ifdef CMDSETOK
    conn_write_string(conn, "$1\r\nx\r\n");
    return;
#endif
    if (args->len != 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    const char *key = args->bufs[1].data;
    size_t keylen = args->bufs[1].len;
    struct get_entry_context ctx = { 
        .conn = conn
    };
    struct pogocache_load_opts opts = {
        .time = now,
        .entry = get_entry,
        .udata = &ctx,
    };
    int proto = conn_proto(conn);
    if (proto == PROTO_POSTGRES) {
        pg_write_row_desc(conn, (const char*[]){ "value" }, 1);
    }
    int status = pogocache_load(cache, key, keylen, &opts);
    if (status == POGOCACHE_NOTFOUND) {
        stat_get_misses_incr(conn);
        if (proto == PROTO_HTTP) {
            conn_write_http(conn, 404, "Not Found", "Not Found\r\n" , -1);
        } else if (proto == PROTO_POSTGRES) {
            pg_write_complete(conn, "GET 0");
        } else {
            conn_write_null(conn);
        }
    } else {
        stat_get_hits_incr(conn);
        if (proto == PROTO_POSTGRES) {
            pg_write_complete(conn, "GET 1");
        }
    }
    if (proto == PROTO_POSTGRES) {
        pg_write_ready(conn, 'I');
    }
}

// MGET(S) key [key...]
static void cmdMGET(struct conn *conn, struct args *args) {
    if (args->len < 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    struct get_entry_context ctx = { 
        .conn = conn,
        .kind = argeq(args, 0, "mgets") ? KIND_MGETS : KIND_MGET,
    };
    struct pogocache_load_opts opts = {
        .time = now,
        .entry = get_entry,
        .udata = &ctx,
    };
    int count = 0;
    int proto = conn_proto(conn);
    if (proto == PROTO_POSTGRES) {
        if (ctx.kind == KIND_MGETS) {
            const char *rows[] = {"key", "flags", "cas", "value"};
            pg_write_row_desc(conn, rows, 4);
        } else {
            const char *rows[] = {"key", "value"};
            pg_write_row_desc(conn, rows, 2);
        }
    } else if (proto == PROTO_RESP) {
        conn_write_array(conn, args->len-1);
    }
    for (size_t i = 1; i < args->len; i++) {
        stat_cmd_get_incr(conn);
        const char *key = args->bufs[i].data;
        size_t keylen = args->bufs[i].len;
        int status = pogocache_load(cache, key, keylen, &opts);
        if (status == POGOCACHE_NOTFOUND) {
            stat_get_misses_incr(conn);
            if (proto == PROTO_RESP) {
                conn_write_null(conn);
            }
        } else {
            count++;
            stat_get_hits_incr(conn);
        }
    }
    if (proto == PROTO_POSTGRES) {
        pg_write_completef(conn, "MGET %d", count);
        pg_write_ready(conn, 'I');
    } else if (proto == PROTO_MEMCACHE) {
        conn_write_raw_cstr(conn, "END\r\n");
    }
}

struct keys_ctx {
    int64_t now;
    struct buf buf;
    size_t count;
    char *pattern;
    size_t plen;
};

static void keys_ctx_free(struct keys_ctx *ctx) {
    xfree(ctx->pattern);
    buf_clear(&ctx->buf);
    xfree(ctx);
}

static int keys_entry(int shard, int64_t time, const void *key, size_t keylen,
        const void *value, size_t valuelen, int64_t expires, uint32_t flags,
        uint64_t cas, void *udata)
{
    (void)shard, (void)time, (void)value, (void)valuelen, (void)expires, 
    (void)flags, (void)cas;
    struct keys_ctx *ctx = udata;
    if ((ctx->plen == 1 && *ctx->pattern == '*') || 
        match(ctx->pattern, ctx->plen, key, keylen, 0))
    {
        buf_append_uvarint(&ctx->buf, keylen);
        buf_append(&ctx->buf, key, keylen);
        ctx->count++;
    }
    return POGOCACHE_ITER_CONTINUE;
}

static void bgkeys_work(void *udata) {
    struct keys_ctx *ctx = udata;
    struct pogocache_iter_opts opts = {
        .time = ctx->now,
        .entry = keys_entry,
        .udata = ctx,
    };
    pogocache_iter(cache, &opts);
}

static void bgkeys_done(struct conn *conn, void *udata) {
    struct keys_ctx *ctx = udata;
    int proto = conn_proto(conn);
    const char *p = ctx->buf.data;
    if (proto == PROTO_POSTGRES) {
        pg_write_row_desc(conn, (const char*[]){ "key" }, 1);
        for (size_t i = 0; i < ctx->count; i++) {
            uint64_t keylen;
            p += varint_read_u64(p, 10, &keylen);
            const char *key = p;
            p += keylen;
            pg_write_row_data(conn, (const char*[]){ key }, 
                (size_t[]){ keylen }, 1);
        }
        pg_write_completef(conn, "KEYS %zu", ctx->count);
        pg_write_ready(conn, 'I');
    } else {
        conn_write_array(conn, ctx->count);
        for (size_t i = 0; i < ctx->count; i++) {
            uint64_t keylen;
            p += varint_read_u64(p, 10, &keylen);
            const char *key = p;
            p += keylen;
            conn_write_bulk(conn, key, keylen);
        }
    }
    keys_ctx_free(ctx);
}

static void cmdKEYS(struct conn *conn, struct args *args) {
    if (args->len != 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    const char *pattern = args->bufs[1].data;
    size_t plen = args->bufs[1].len;
    struct keys_ctx *ctx = xmalloc(sizeof(struct keys_ctx));
    memset(ctx, 0, sizeof(struct keys_ctx));
    ctx->pattern = xmalloc(plen+1);
    memcpy(ctx->pattern, pattern, plen);
    ctx->pattern[plen] = '\0';
    ctx->plen = plen;
    ctx->now = now;
    if (!conn_bgwork(conn, bgkeys_work, bgkeys_done, ctx)) {
        conn_write_error(conn, "ERR failed to do work");
        keys_ctx_free(ctx);
    }
}

// SELECT 0
// This is an undocumented RESP only command that exists in order to provide
// compatibility for certain integrations that need it.
static void cmdSELECT(struct conn *conn, struct args *args) {
    if (conn_proto(conn) != PROTO_RESP) {
        char msg[64];
        snprintf(msg, 64, "ERR unknown command '%.*s'", 
            (int)args->bufs[0].len, args->bufs[0].data);
        conn_write_error(conn, msg);
        return;
    }
    if (args->len != 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t db = 0;
    bool ok = parse_i64(args->bufs[1].data, args->bufs[1].len, &db);
    const bool out_of_range = (ok && db > 0);
    ok = (ok && !out_of_range);
    if (!ok) {
        conn_write_error(conn, (out_of_range) ? ERR_INDEX_OUT_OF_RANGE : 
            ERR_INVALID_INTEGER);
        return;
    }
    conn_write_string(conn, "OK");
}

static void cmdDEL(struct conn *conn, struct args *args) {
    if (args->len < 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    struct pogocache_delete_opts opts = {
        .time = now,
    };
    int64_t deleted = 0;
    for (size_t i = 1; i < args->len; i++) {
        const char *key = args->bufs[i].data;
        size_t keylen = args->bufs[i].len;
        int status = pogocache_delete(cache, key, keylen, &opts);
        if (status == POGOCACHE_DELETED) {
            stat_delete_hits_incr(conn);
            deleted++;
        } else {
            stat_delete_misses_incr(conn);
        }
    }
    switch (conn_proto(conn)) {
    case PROTO_MEMCACHE:
        if (deleted == 0) {
            conn_write_raw_cstr(conn, "NOT_FOUND\r\n");
        } else {
            conn_write_raw_cstr(conn, "DELETED\r\n");
        }
        break;
    case PROTO_HTTP:
        if (deleted == 0) {
            conn_write_http(conn, 404, "Not Found", "Not Found\r\n", -1);
        } else {
            conn_write_http(conn, 200, "OK", "Deleted\r\n", -1);
        }
        break;
    case PROTO_POSTGRES:
        pg_write_completef(conn, "DEL %" PRIi64, deleted);
        pg_write_ready(conn, 'I');
        break;
    default:
        conn_write_int(conn, deleted);
    }
}

static void cmdDBSIZE(struct conn *conn, struct args *args) {
    if (args->len != 1) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    struct pogocache_count_opts opts = { .time = sys_now() };
    size_t count = pogocache_count(cache, &opts);
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_simple_row_i64_ready(conn, "count", count, "DBSIZE");
    } else {
        conn_write_int(conn, (int64_t)count);
    }
}

struct flushctx { 
    int64_t delay;
    bool fast;
    const char *cmdname;
    pthread_t th;
    int64_t time;
    int start;
    int count;
};

static void *thflush(void *arg) {
    struct flushctx *ctx = arg;
    struct pogocache_clear_opts opts = { .time = sys_now(), .oneshard = true };
    for (int i = 0; i < ctx->count; i++) {
        opts.oneshardidx = i+ctx->start;
        pogocache_clear(cache, &opts);
    }
    return 0;
}

static void flushfast(void) {
    int64_t now = sys_now();
    int nprocs = sys_nprocs();
    if (nprocs > nshards) {
        nprocs = nshards;
    }
    struct flushctx *ctxs = xmalloc(nprocs*sizeof(struct flushctx));
    memset(ctxs, 0, nprocs*sizeof(struct flushctx));
    int start = 0;
    for (int i = 0; i < nprocs; i++) {
        struct flushctx *ctx = &ctxs[i];
        ctx->start = start;
        ctx->count = nshards/nprocs;
        ctx->time = now;
        if (i == nprocs-1) {
            ctx->count = nshards-ctx->start;
        }
        if (pthread_create(&ctx->th, 0, thflush, ctx) == -1) {
            ctx->th = 0;
        }
        start += ctx->count;
    }
    for (int i = 0; i < nprocs; i++) {
        struct flushctx *ctx = &ctxs[i];
        if (ctx->th == 0) {
            thflush(ctx);
        }
    }
    for (int i = 0; i < nprocs; i++) {
        struct flushctx *ctx = &ctxs[i];
        if (ctx->th != 0) {
            pthread_join(ctx->th, 0);
        }
    }
    xfree(ctxs);
}

static void flush_work(void *udata) {
    struct flushctx *ctx = udata;
    int64_t start = sys_now();
    if (verb > 0) {
        printf(". flush started\n");
    }
    stat_cmd_flush_incr(0);
    if (ctx->fast) {
        flushfast();
    } else {
        struct pogocache_clear_opts opts = { 
            .time = start,
            .deferfree = true, // less thread blocking when defered
        };
        pogocache_clear(cache, &opts);
    }
    double elapsed = (sys_now()-start)/1e9;
    if (verb > 0) {
        printf(". flush finished in %.2fs\n", elapsed);
    }
}

static void flush_done(struct conn *conn, void *udata) {
    struct flushctx *ctx = udata;
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_completef(conn, "%s SYNC", ctx->cmdname);
        pg_write_ready(conn, 'I');
    } else if (conn_proto(conn) == PROTO_MEMCACHE) {
        conn_write_raw_cstr(conn, "OK\r\n");
    } else {
        conn_write_string(conn, "OK");
    }
    xfree(ctx);
}

static void *thflush0(void *arg) {
    struct flushctx *ctx = arg;
    if (ctx->delay > 0) {
        printf(". flush scheduled in %lld seconds\n", (long long)ctx->delay);
        sleep(ctx->delay);
    }
    flush_work(ctx);
    xfree(ctx);
    return 0;
}

// FLUSHALL [SYNC|ASYNC] [FAST] [DELAY <seconds>]
// FLUSHDB
// FLUSH
static void cmdFLUSHALL(struct conn *conn, struct args *args) {
    const char *cmdname = 
        args_eq(args, 0, "flush") ? "FLUSH" :
        args_eq(args, 0, "flushdb") ? "FLUSHDB" :
        "FLUSHALL";
    bool fast = false;
    bool async = false;
    int64_t delay = 0;
    for (size_t i = 1; i < args->len; i++) {
        if (argeq(args, i, "async")) {
            async = true;
        } else if (argeq(args, i, "sync")) {
            async = false;
        } else if (argeq(args, i, "fast")) {
            fast = true;
        } else if (argeq(args, i, "delay")) {
            i++;
            if (i == args->len) {
                conn_write_error(conn, ERR_SYNTAX_ERROR);
                return;
            }
            bool ok = parse_i64(args->bufs[i].data, args->bufs[i].len, &delay);
            if (!ok || delay < 0 || delay > 31536000) {
                conn_write_error(conn, "ERR invalid delay argument");
                return;
            }
            if (delay > 0) {
                async = true;
            } else {
                delay = 0;
            }
        } else {
            conn_write_error(conn, ERR_SYNTAX_ERROR);
            return;
        }
    }
    struct flushctx *ctx = xmalloc(sizeof(struct flushctx));
    memset(ctx, 0, sizeof(struct flushctx));
    ctx->cmdname = cmdname;
    ctx->fast = fast;
    ctx->delay = delay;
    if (async) {
        pthread_t th;
        int ret = pthread_create(&th, 0, thflush0, ctx);
        if (ret == -1) {
            xfree(ctx);
            conn_write_error(conn, "ERR failed to do work");
            return;
        }
        pthread_detach(th);
        if (conn_proto(conn) == PROTO_POSTGRES) {
            pg_write_completef(conn, "%s ASYNC", cmdname);
            pg_write_ready(conn, 'I');
        } else if (conn_proto(conn) == PROTO_MEMCACHE) {
            conn_write_raw_cstr(conn, "OK\r\n");
        } else {
            conn_write_string(conn, "OK");
        }
    } else {
        // Flush database is slow. cmdname is static and thread safe
        if (!conn_bgwork(conn, flush_work, flush_done, ctx)) {
            conn_write_error(conn, "ERR failed to do work");
            xfree(ctx);
        }
        return;
    }
    return;
}

struct bgsaveloadctx {
    bool ok;          // true = success, false = out of disk space
    bool fast;        // use all the proccesing power, otherwise one thread.
    char *path;       // path to file
    bool load;        // otherwise save
};

static void bgsaveloadwork(void *udata) {
    struct bgsaveloadctx *ctx = udata;
    int64_t start = sys_now();
    int status;
    if (ctx->load) {
        status = load(ctx->path, ctx->fast, 0);
    } else {
        status = save(ctx->path, ctx->fast);
    }
    printf(". %s finished %.3f secs\n", ctx->load?"load":"save", 
        (sys_now()-start)/1e9);
    ctx->ok = status == 0;
}

static void bgsaveloaddone(struct conn *conn, void *udata) {
    struct bgsaveloadctx *ctx = udata;
    if (ctx->ok) {
        if (conn_proto(conn) == PROTO_POSTGRES) {
            pg_write_completef(conn, "%s OK", ctx->load?"LOAD":"SAVE");
            pg_write_ready(conn, 'I');
        } else if (conn_proto(conn) == PROTO_MEMCACHE) {
            conn_write_raw_cstr(conn, "OK\r\n");
        } else {
            conn_write_string(conn, "OK");
        }
    } else {
        if (ctx->load) {
            conn_write_error(conn, "load failed");
        } else {
            conn_write_error(conn, "save failed");
        }
    }
    xfree(ctx->path);
    xfree(ctx);
}

// SAVE [TO <path>] [FAST]
// LOAD [FROM <path>] [FAST]
static void cmdSAVELOAD(struct conn *conn, struct args *args) {
    bool load = argeq(args, 0, "load");
    bool fast = false;
    const char *internal_path = persist;
    size_t plen = strlen(persist);
    for (size_t i = 1; i < args->len; i++) {
        if (argeq(args, i, "fast")) {
            fast = true;
        } else if ((load && argeq(args, i, "from")) || 
            (!load && argeq(args, i, "to")))
        {
            i++;
            if (i == args->len) {
                goto err_syntax;
            }
            internal_path = args->bufs[i].data;
            plen = args->bufs[i].len;
        } else {
            goto err_syntax;
        }
    }
    if (plen == 0) {
        conn_write_error(conn, "ERR path not provided");
        return;
    }
    struct bgsaveloadctx *ctx = xmalloc(sizeof(struct bgsaveloadctx));
    memset(ctx, 0, sizeof(struct bgsaveloadctx));
    ctx->fast = fast;
    ctx->path = xmalloc(plen+1);
    ctx->load = load;
    memcpy(ctx->path, internal_path, plen);
    ctx->path[plen] = '\0';
    if (!conn_bgwork(conn, bgsaveloadwork, bgsaveloaddone, ctx)) {
        conn_write_error(conn, "ERR failed to do work");
        xfree(ctx->path);
        xfree(ctx);
    }
    return;
err_syntax:
    conn_write_error(conn, ERR_SYNTAX_ERROR);
    return;
}

struct ttlctx {
    struct conn *conn;
    bool pttl;
};

static void ttl_entry(int shard, int64_t time, const void *key, size_t keylen,
    const void *val, size_t vallen, int64_t expires, uint32_t flags,
    uint64_t cas, struct pogocache_update **update, void *udata)
{
    (void)shard, (void)key, (void)keylen, (void)val, (void)vallen, (void)flags,
    (void)cas, (void)update;
    struct ttlctx *ctx = udata;
    int64_t ttl;
    if (expires > 0) {
        ttl = expires-time;
        if (ctx->pttl) {
            ttl /= MILLISECOND;
        } else {
            ttl /= SECOND;
        }
    } else {
        ttl = -1;
    }
    if (conn_proto(ctx->conn) == PROTO_POSTGRES) {
        char ttlstr[24];
        size_t n = i64toa(ttl, (uint8_t*)ttlstr);
        pg_write_row_data(ctx->conn, (const char*[]){ ttlstr }, 
            (size_t[]){ n }, 1);
    } else {
        conn_write_int(ctx->conn, ttl);
    }
}

static void cmdTTL(struct conn *conn, struct args *args) {
    if (args->len != 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    const char *key = args->bufs[1].data;
    size_t keylen = args->bufs[1].len;
    bool pttl = argeq(args, 0, "pttl");
    struct ttlctx ctx = { .conn = conn, .pttl = pttl };
    struct pogocache_load_opts opts = {
        .time = sys_now(),
        .entry = ttl_entry,
        .notouch = true,
        .udata = &ctx,
    };
    int proto = conn_proto(conn);
    if (proto == PROTO_POSTGRES) {
        pg_write_row_desc(conn, (const char*[]){ pttl?"pttl":"ttl" }, 1);
    }
    int status = pogocache_load(cache, key, keylen, &opts);
    if (status == POGOCACHE_NOTFOUND) {
        stat_get_misses_incr(conn);
        if (proto == PROTO_RESP) {
            conn_write_int(conn, -2);
        }
    } else {
        stat_get_hits_incr(conn);
    }
    if (proto == PROTO_POSTGRES) {
        pg_write_completef(conn, "%s %d", pttl?"PTTL":"TTL",
            status!=POGOCACHE_NOTFOUND);
        pg_write_ready(conn, 'I');
    }
}

static void expire_entry(int shard, int64_t time, const void *key,
    size_t keylen, const void *value, size_t valuelen, int64_t expires,
    uint32_t flags, uint64_t cas, struct pogocache_update **update, void *udata)
{
    (void)shard, (void)time, (void)key, (void)keylen, (void)expires, (void)cas;
    struct pogocache_update *ctx = udata;
    ctx->flags = flags;
    ctx->value = value;
    ctx->valuelen = valuelen;
    *update = ctx;
}

// EXPIRE key seconds
// returns 1 if success or 0 on failure. 
static void cmdEXPIRE(struct conn *conn, struct args *args) {
    if (args->len < 3) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    const char *key = args->bufs[1].data;
    size_t keylen = args->bufs[1].len;
    int64_t expires;
    if (!argi64(args, 2, &expires)) {
        conn_write_error(conn, ERR_INVALID_INTEGER);
        return;
    }
    expires = int64_mul_clamp(expires, POGOCACHE_SECOND);
    expires = int64_add_clamp(now, expires);
    struct pogocache_update ctx = { .expires = expires };
    struct pogocache_load_opts lopts = { 
        .time = now,
        .entry = expire_entry,
        .udata = &ctx,
    };
    int status = pogocache_load(cache, key, keylen, &lopts);
    int ret = status == POGOCACHE_FOUND;
    int proto = conn_proto(conn);
    switch (proto) {
    case PROTO_POSTGRES:
        pg_write_completef(conn, "EXPIRE %d", ret);
        pg_write_ready(conn, 'I');
        break;
    case PROTO_MEMCACHE:
        if (ret) {
            conn_write_raw_cstr(conn, "TOUCHED\r\n");
        } else {
            conn_write_raw_cstr(conn, "NOT_FOUND\r\n");
        }
        break;
    default:
        conn_write_int(conn, ret);
        break;
    }
}

// EXISTS key [key...]
// Checks if one or more keys exist in the cache.
// Return the number of keys that exist
static void cmdEXISTS(struct conn *conn, struct args *args) {
    if (args->len < 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    int64_t count = 0;
    struct pogocache_load_opts opts = {
        .time = now,
        .notouch = true,
    };
    for (size_t i = 1; i < args->len; i++) {
        const char *key = args->bufs[i].data;
        size_t keylen = args->bufs[i].len;
        int status = pogocache_load(cache, key, keylen, &opts);
        if (status == POGOCACHE_FOUND) {
            count++;
        }
    }
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_simple_row_i64_ready(conn, "exists", count, "EXISTS");
    } else {
        conn_write_int(conn, count);
    }
}

struct sweepctx {
    bool fast;
    pthread_t th;
    int64_t time;
    int start;
    int count;
    size_t swept;
    size_t kept;
};

static void *thsweep(void *arg) {
    struct sweepctx *ctx = arg;
    struct pogocache_sweep_opts opts = { .time = sys_now(), .oneshard = true };
    for (int i = 0; i < ctx->count; i++) {
        opts.oneshardidx = i+ctx->start;
        size_t swept, kept;
        pogocache_sweep(cache, &swept, &kept, &opts);
        ctx->swept += swept;
        ctx->kept += kept;
    }
    return 0;
}

static void sweepfast(size_t *swept, size_t *kept) {
    size_t sweptc = 0;
    size_t keptc = 0;
    int64_t now = sys_now();
    int nprocs = sys_nprocs();
    if (nprocs > nshards) {
        nprocs = nshards;
    }
    struct sweepctx *ctxs = xmalloc(nprocs*sizeof(struct sweepctx));
    memset(ctxs, 0, nprocs*sizeof(struct sweepctx));
    int start = 0;
    for (int i = 0; i < nprocs; i++) {
        struct sweepctx *ctx = &ctxs[i];
        ctx->fast = true;
        ctx->start = start;
        ctx->count = nshards/nprocs;
        ctx->time = now;
        if (i == nprocs-1) {
            ctx->count = nshards-ctx->start;
        }
        if (pthread_create(&ctx->th, 0, thsweep, ctx) == -1) {
            ctx->th = 0;
        }
        start += ctx->count;
    }
    for (int i = 0; i < nprocs; i++) {
        struct sweepctx *ctx = &ctxs[i];
        if (ctx->th == 0) {
            thsweep(ctx);
        }
    }
    for (int i = 0; i < nprocs; i++) {
        struct sweepctx *ctx = &ctxs[i];
        if (ctx->th != 0) {
            pthread_join(ctx->th, 0);
        }
        sweptc += ctx->swept;
        keptc += ctx->kept;
    }
    *swept = sweptc;
    *kept = keptc;
    xfree(ctxs);
}

static void sweep_work(void *udata) {
    struct sweepctx *ctx = udata;
    int64_t start = sys_now();
    size_t swept;
    size_t kept;
    if (verb > 0) {
        printf(". sweep started\n");
    }
    if (ctx->fast) {
        sweepfast(&swept, &kept);
    } else {
        struct pogocache_sweep_opts opts = { .time = start };
        pogocache_sweep(cache, &swept, &kept, &opts);
    }
    double elapsed = (sys_now()-start)/1e9;
    if (verb > 0) {
        printf(". sweep finished in %.2fs, (swept=%zu, kept=%zu) \n", elapsed, 
            swept, kept);
    }
}

static void sweep_done(struct conn *conn, void *udata) {
    struct sweepctx *ctx = udata;
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_completef(conn, "SWEEP SYNC");
        pg_write_ready(conn, 'I');
    } else {
        conn_write_string(conn, "OK");
    }
    xfree(ctx);
}

static void *thsweep0(void *arg) {
    struct sweepctx *ctx = arg;
    sweep_work(ctx);
    xfree(ctx);
    return 0;
}

// SWEEP [ASYNC] [FAST]
static void cmdSWEEP(struct conn *conn, struct args *args) {
    if (args->len > 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    bool fast = false;
    bool async = false;
    for (size_t i = 1; i < args->len; i++) {
        if (argeq(args, i, "async")) {
            async = true;
        } else if (argeq(args, i, "fast")) {
            fast = true;
        } else {
            conn_write_error(conn, ERR_SYNTAX_ERROR);
            return;
        }
    }
    struct sweepctx *ctx = xmalloc(sizeof(struct sweepctx));
    memset(ctx, 0, sizeof(struct sweepctx));
    ctx->fast = fast;
    if (async) {
        pthread_t th;
        int ret = pthread_create(&th, 0, thsweep0, ctx);
        if (ret == -1) {
            xfree(ctx);
            conn_write_error(conn, "ERR failed to do work");
            return;
        }
        pthread_detach(th);
        if (conn_proto(conn) == PROTO_POSTGRES) {
            pg_write_completef(conn, "SWEEP ASYNC");
            pg_write_ready(conn, 'I');
        } else {
            conn_write_string(conn, "OK");
        }
    } else {
        if (!conn_bgwork(conn, sweep_work, sweep_done, ctx)) {
            xfree(ctx);
            conn_write_error(conn, "ERR failed to do work");
        }
    }
}

static void purge_work(void *udata) {
    (void)udata;
    int64_t start = sys_now();
    printf(". purge started\n");
    xpurge();
    double elapsed = (sys_now()-start)/1e9;
    printf(". purge finished in %.2fs\n", elapsed);
}

static void purge_done(struct conn *conn, void *udata) {
    (void)udata;
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_completef(conn, "PURGE SYNC");
        pg_write_ready(conn, 'I');
    } else {
        conn_write_string(conn, "OK");
    }
}

static void *thpurge(void *arg) {
    (void)arg;
    purge_work(0);
    return 0;
}

// PURGE [ASYNC]
static void cmdPURGE(struct conn *conn, struct args *args) {
    if (args->len > 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    bool async = false;
    if (args->len == 2) {
        if (argeq(args, 1, "async")) {
            async = true;
        } else {
            conn_write_error(conn, ERR_SYNTAX_ERROR);
            return;
        }
    }
    if (async) {
        pthread_t th;
        int ret = pthread_create(&th, 0, thpurge, 0);
        if (ret == -1) {
            conn_write_error(conn, "ERR failed to do work");
            return;
        }
        pthread_detach(th);
        if (conn_proto(conn) == PROTO_POSTGRES) {
            pg_write_completef(conn, "PURGE ASYNC");
            pg_write_ready(conn, 'I');
        } else {
            conn_write_string(conn, "OK");
        }
    } else {
        if (!conn_bgwork(conn, purge_work, purge_done, 0)) {
            conn_write_error(conn, "ERR failed to do work");
        }
    }
}

struct populate_ctx {
    pthread_t th;
    size_t start;
    size_t count;
    char *prefix;
    size_t prefixlen;
    char *val;
    size_t vallen;
    bool randex;
    int randmin;
    int randmax;
};

static void *populate_entry(void *arg) {
    int64_t now = sys_now();
    struct populate_ctx *ctx = arg;
    char *key = xmalloc(ctx->prefixlen+32);
    memcpy(key, ctx->prefix, ctx->prefixlen);
    key[ctx->prefixlen++] = ':';
    for (size_t i = ctx->start; i < ctx->start+ctx->count; i++) {
        size_t n = i64toa(i, (uint8_t*)(key+ctx->prefixlen));
        size_t keylen = ctx->prefixlen+n;
        struct pogocache_store_opts opts = { 
            .time = now,
        };
        if (ctx->randex) {
            int ex = (rand()%(ctx->randmax-ctx->randmin))+ctx->randmin;
            opts.ttl = ex*POGOCACHE_SECOND;
        }
        pogocache_store(cache, key, keylen, ctx->val, ctx->vallen, &opts);
    }
    xfree(key);
    return 0;
}

// DEBUG POPULATE <count> <prefix> <size> [rand-ex-range]
// DEBUG POPULATE <count> <prefix> <size>
// DEBUG POPULATE 1000000 test 16
// DEBUG POPULATE 1000000 test 16 5-10
static void cmdDEBUG_populate(struct conn *conn, struct args *args) {
    if (args->len != 4 && args->len != 5) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t count;
    if (!argi64(args, 1, &count) || count < 0) {
        conn_write_error(conn, ERR_SYNTAX_ERROR);
        return;
    }
    size_t prefixlen = args->bufs[2].len;
    char *prefix = args->bufs[2].data;
    int64_t vallen;
    if (!argi64(args, 3, &vallen) || vallen < 0) {
        conn_write_error(conn, ERR_SYNTAX_ERROR);
        return;
    }
    bool randex = false;
    int randmin = 0;
    int randmax = 0;
    if (args->len == 5) {
        size_t exlen = args->bufs[4].len;
        char *aex = args->bufs[4].data;
        char *ex = xmalloc(exlen+1);
        memcpy(ex, aex, exlen);
        ex[exlen] = '\0';
        if (strchr(ex, '-')) {
            randmin = atoi(ex);
            randmax = atoi(strchr(ex, '-')+1);
            randex = true;
        }
        xfree(ex);
    }

    char *val = xmalloc(vallen);
    memset(val, 0, vallen);
    int nprocs = sys_nprocs();
    if (nprocs < 0) {
        nprocs = 1;
    }
    struct populate_ctx *ctxs = xmalloc(nprocs*sizeof(struct populate_ctx));
    memset(ctxs, 0, nprocs*sizeof(struct populate_ctx));
    size_t group = count/nprocs;
    size_t start = 0;
    for (int i = 0; i < nprocs; i++) {
        struct populate_ctx *ctx = &ctxs[i];
        ctx->start = start;
        if (i == nprocs-1) {
            ctx->count = count-start;
        } else {
            ctx->count = group;
        }
        ctx->prefix = prefix;
        ctx->prefixlen = prefixlen;
        ctx->val = val;
        ctx->vallen = vallen;
        ctx->randex = randex;
        ctx->randmin = randmin;
        ctx->randmax = randmax;
        if (pthread_create(&ctx->th, 0, populate_entry, ctx) == -1) {
            ctx->th = 0;
        }
        start += group;
    }
    for (int i = 0; i < nprocs; i++) {
        struct populate_ctx *ctx = &ctxs[i];
        if (ctx->th == 0) {
            populate_entry(ctx);
        }
    }
    for (int i = 0; i < nprocs; i++) {
        struct populate_ctx *ctx = &ctxs[i];
        if (ctx->th) {
            pthread_join(ctx->th, 0);
        }
    }
    xfree(ctxs);
    xfree(val);
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_completef(conn, "DEBUG POPULATE %" PRIi64, count);
        pg_write_ready(conn, 'I');
    } else {
        conn_write_string(conn, "OK");
    }
}

struct dbg_detach_ctx {
    int64_t now;
    int64_t then;
};

static void detach_work(void *udata) {
    struct dbg_detach_ctx *ctx = udata;
    ctx->then = sys_now();
    // printf(". ----- DELAY START\n");
    // sleep(1);
    // printf(". ----- DELAY END\n");
}

static void detach_done(struct conn *conn, void *udata) {
    struct dbg_detach_ctx *ctx = udata;
    char buf[128];
    snprintf(buf, sizeof(buf), "%" PRId64 ":%" PRId64, ctx->now, ctx->then);
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_simple_row_str_ready(conn, "detach", buf, "DEBUG DETACH");
    } else {
        conn_write_bulk_cstr(conn, buf);
    }
    xfree(ctx);
}

// DEBUG detach
static void cmdDEBUG_detach(struct conn *conn, struct args *args) {
    (void)args;
    struct dbg_detach_ctx *ctx = xmalloc(sizeof(struct dbg_detach_ctx));
    memset(ctx, 0,sizeof(struct dbg_detach_ctx));
    ctx->now = sys_now();
    if (!conn_bgwork(conn, detach_work, detach_done, ctx)) {
        conn_write_error(conn, "ERR failed to do work");
        xfree(ctx);
    }
}

// DEBUG subcommand (args...)
static void cmdDEBUG(struct conn *conn, struct args *args) {
    if (args->len <= 1) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    // args = args[1:]
    args = &(struct args){ .bufs = args->bufs+1, .len = args->len-1 };
    if (argeq(args, 0, "populate")) {
        cmdDEBUG_populate(conn, args);
    } else if (argeq(args, 0, "detach")) {
        cmdDEBUG_detach(conn, args);
    } else {
        conn_write_error(conn, "ERR unknown subcommand");
    }
}

static void cmdECHO(struct conn *conn, struct args *args) {
    if (args->len != 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_simple_row_data_ready(conn, "message", args->bufs[1].data, 
            args->bufs[1].len, "ECHO");
    } else {
        conn_write_bulk(conn, args->bufs[1].data, args->bufs[1].len);
    }
}

ssize_t parse_resp(const char *bytes, size_t len, struct args *args);
ssize_t parse_resp_telnet(const char *bytes, size_t len, struct args *args);

struct monitor_ctx {
    struct conn *conn;
};

static void monitor_work(void *udata) {
    struct monitor_ctx *ctx = udata;
    struct conn *conn = ctx->conn;
    char pkt[4096];
    conn_setnonblock(conn, false);
    monitor_start(conn);
    struct args args = { 0 };
    while (1) {
        ssize_t n = conn_read(conn, pkt, sizeof(pkt));
        if (n <= 0) {
            break;
        }
        args_clear(&args);
        ssize_t nn;
        if (pkt[0] == '*') {
            nn = parse_resp(pkt, n, &args);
        } else {
            nn = parse_resp_telnet(pkt, n, &args);
        }
        if (nn != n) {
            break;
        }
        if (args.len == 0) {
            continue;
        } else if (args_eq(&args, 0, "ping")) {
            conn_write(conn, "+PONG\r\n", 7);
        } else {
            break;
        }
    }
    args_free(&args);
    monitor_stop(conn);
    conn_setnonblock(conn, false);
}

static void monitor_done(struct conn *conn, void *udata) {
    struct dbg_detach_ctx *ctx = udata;
    xfree(ctx);
    conn_close(conn);
}


static void cmdMONITOR(struct conn *conn, struct args *args) {
    if (conn_proto(conn) != PROTO_RESP) {
        conn_write_error(conn, "unavailable");
        return;
    }
    if (args->len != 1) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    conn_write_string(conn, "OK");
    struct monitor_ctx *ctx = xmalloc(sizeof(struct monitor_ctx));
    memset(ctx, 0, sizeof(struct monitor_ctx));
    ctx->conn = conn;
    if (!conn_bgwork(conn, monitor_work, monitor_done, ctx)) {
        conn_write_error(conn, "ERR failed to do work");
        xfree(ctx);
    }

}

static void cmdPING(struct conn *conn, struct args *args) {
    if (args->len > 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    if (conn_proto(conn) == PROTO_POSTGRES) {
        if (args->len == 1) {
            pg_write_simple_row_str_ready(conn, "message", "PONG", "PING"); 
        } else {
            pg_write_simple_row_data_ready(conn, "message", args->bufs[1].data, 
                args->bufs[1].len, "PING");
        }
    } else {
        if (args->len == 1) {
            conn_write_string(conn, "PONG");
        } else {
            conn_write_bulk(conn, args->bufs[1].data, args->bufs[1].len);
        }
    }
}

static void cmdQUIT(struct conn *conn, struct args *args) {
    (void)args;
    if (conn_proto(conn) == PROTO_RESP) {
        conn_write_string(conn, "OK");
    }
    conn_close(conn);
}

// TOUCH key [key...]
static void cmdTOUCH(struct conn *conn, struct args *args) {
    if (args->len < 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int64_t now = sys_now();
    int64_t touched = 0;
    struct pogocache_load_opts opts = { 
        .time = now,
    };
    for (size_t i = 1; i < args->len; i++) {
        stat_cmd_touch_incr(conn);
        const char *key = args->bufs[i].data;
        size_t keylen = args->bufs[i].len;
        int status = pogocache_load(cache, key, keylen, &opts);
        if (status == POGOCACHE_FOUND) {
            stat_touch_hits_incr(conn);
            touched++;
        } else {
            stat_touch_misses_incr(conn);
        }
    }
    int proto = conn_proto(conn);
    if (proto == PROTO_POSTGRES) {
        pg_write_completef(conn, "TOUCH %" PRIi64, touched);
        pg_write_ready(conn, 'I');
    } else if (proto == PROTO_MEMCACHE) {
        if (touched > 0) {
            conn_write_raw_cstr(conn, "TOUCHED\r\n");
        } else {
            conn_write_raw_cstr(conn, "NOT_FOUND\r\n");
        }
    } else {
        conn_write_int(conn, touched);
    }
}

struct get64ctx {
    bool ok;
    bool isunsigned;
    union {
        int64_t ival;
        uint64_t uval;
    };
    int64_t expires;
    uint32_t flags;
    uint64_t cas;
};

union delta { 
    uint64_t u;
    int64_t i;
};

static void get64(int shard, int64_t time, const void *key,
    size_t keylen, const void *val, size_t vallen, int64_t expires,
    uint32_t flags, uint64_t cas, struct pogocache_update **update, void *udata)
{
    (void)shard, (void)time, (void)key, (void)keylen, (void)update;
    struct get64ctx *ctx = udata;
    ctx->flags = flags;
    ctx->expires = expires;
    ctx->cas = cas;
    if (ctx->isunsigned) {
        ctx->ok = parse_u64(val, vallen, &ctx->uval);
    } else {
        ctx->ok = parse_i64(val, vallen, &ctx->ival);
    }
}

static void execINCRDECR(struct conn *conn, const char *key, size_t keylen, 
    union delta delta, bool decr, bool isunsigned, const char *cmdname)
{
    bool hit = false;
    bool miss = false;
    int64_t now = sys_now();
    struct get64ctx ctx = { .isunsigned = isunsigned };
    struct pogocache *batch = pogocache_begin(cache);
    struct pogocache_load_opts gopts = {
        .time = now,
        .entry = get64,
        .udata = &ctx,
    };
    int status = pogocache_load(batch, key, keylen, &gopts);
    bool found = status == POGOCACHE_FOUND;
    if (found && !ctx.ok) {
        if (conn_proto(conn) == PROTO_MEMCACHE) {
            conn_write_raw_cstr(conn, "CLIENT_ERROR cannot increment or "
                "decrement non-numeric value\r\n");
            goto done;
        }
        goto fail_value_non_numeric;
    } else if (!found && conn_proto(conn) == PROTO_MEMCACHE) {
        miss = true;
        conn_write_raw_cstr(conn, "NOT_FOUND\r\n");
        goto done;
    }
    // add or subtract
    bool overflow;
    if (isunsigned) {
        if (decr) {
            overflow = __builtin_sub_overflow(ctx.uval, delta.u, &ctx.uval);
        } else {
            overflow = __builtin_add_overflow(ctx.uval, delta.u, &ctx.uval);
        }
    } else {
        if (decr) {
            overflow = __builtin_sub_overflow(ctx.ival, delta.i, &ctx.ival);
        } else {
            overflow = __builtin_add_overflow(ctx.ival, delta.i, &ctx.ival);
        }
    }
    if (overflow && conn_proto(conn) != PROTO_MEMCACHE) {
        goto fail_overflow;
    }
    // re-set the value
    char val[24];
    size_t vallen;
    if (isunsigned) {
        vallen = u64toa(ctx.uval, (uint8_t*)val);
    } else {
        vallen = i64toa(ctx.ival, (uint8_t*)val);
    }
    struct pogocache_store_opts sopts = {
        .time = now,
        .expires = ctx.expires, 
        .flags = ctx.flags, 
        .cas = ctx.cas,
        .udata = &ctx,
    };
    status = pogocache_store(batch, key, keylen, val, vallen, &sopts);
    if (status == POGOCACHE_NOMEM) {
        stat_store_no_memory_incr(conn);
        conn_write_error(conn, ERR_OUT_OF_MEMORY);
        goto done;
    }
    assert(status == POGOCACHE_INSERTED || status == POGOCACHE_REPLACED);
    int proto = conn_proto(conn);
    if (proto == PROTO_POSTGRES) {
        char buf1[24];
        if (isunsigned) {
            snprintf(buf1, sizeof(buf1), "%" PRIu64, ctx.uval);
        } else {
            snprintf(buf1, sizeof(buf1), "%" PRIi64, ctx.ival);
        }
        pg_write_simple_row_str_readyf(conn, "value", buf1, "%s", cmdname);
    } else {
        if (isunsigned) {
            conn_write_uint(conn, ctx.uval);
        } else {
            conn_write_int(conn, ctx.ival);
        }
        if (proto == PROTO_MEMCACHE) {
            conn_write_raw_cstr(conn, "\r\n");
        }
    }
    hit = true;
    goto done;
fail_value_non_numeric:
    conn_write_error(conn, ERR_INVALID_INTEGER);
    goto done;
fail_overflow:
    conn_write_error(conn, "ERR increment or decrement would overflow");
    goto done;
done:
    if (hit) {
        if (decr) {
            stat_decr_hits_incr(conn);
        } else {
            stat_incr_hits_incr(conn);
        }
    } else if (miss) {
        if (decr) {
            stat_decr_misses_incr(conn);
        } else {
            stat_incr_misses_incr(conn);
        }
    }
    pogocache_end(batch);
}

static void cmdINCRDECRBY(struct conn *conn, struct args *args, 
    bool decr, const char *cmdname)
{
    if (args->len != 3) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    bool isunsigned = tolower(args->bufs[0].data[0]) == 'u';
    size_t keylen;
    const char *key = args_at(args, 1, &keylen);
    union delta delta;
    bool ok;
    if (isunsigned) {
        ok = argu64(args, 2, &delta.u);
    } else {
        ok = argi64(args, 2, &delta.i);
    }
    if (!ok) {
        if (conn_proto(conn) == PROTO_MEMCACHE) {
            conn_write_raw_cstr(conn, "CLIENT_ERROR invalid numeric delta "
                "argument\r\n");
        } else {
            conn_write_error(conn, ERR_INVALID_INTEGER);
        }
        return;
    }
    execINCRDECR(conn, key, keylen, delta, decr, isunsigned, cmdname);
}

// DECRBY key num
static void cmdDECRBY(struct conn *conn, struct args *args) {
    cmdINCRDECRBY(conn, args, true, "DECRBY");
}

// INCRBY key num
static void cmdINCRBY(struct conn *conn, struct args *args) {
    cmdINCRDECRBY(conn, args, false, "INCRBY");
}

// DECR key
static void cmdDECR(struct conn *conn, struct args *args) {
    if (args->len != 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    bool isunsigned = tolower(args->bufs[0].data[0]) == 'u';
    size_t keylen;
    const char *key = args_at(args, 1, &keylen);
    union delta delta = { .i = 1 };
    execINCRDECR(conn, key, keylen, delta, true, isunsigned, "DECR");
}

// INCR key
static void cmdINCR(struct conn *conn, struct args *args) {
    if (args->len != 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    bool isunsigned = tolower(args->bufs[0].data[0]) == 'u';
    size_t keylen;
    const char *key = args_at(args, 1, &keylen);
    union delta delta = { .i = 1 };
    execINCRDECR(conn, key, keylen, delta, false, isunsigned, "INCR");
}

struct appendctx {
    bool prepend;
    uint32_t flags;
    int64_t expires;
    const char *val;
    size_t vallen;
    char *outval;
    size_t outvallen;
};

static void append_entry(int shard, int64_t time, const void *key,
    size_t keylen, const void *val, size_t vallen, int64_t expires, 
    uint32_t flags, uint64_t cas, struct pogocache_update **update, void *udata)
{
    (void)shard, (void)time, (void)key, (void)keylen, (void)update, (void)cas;
    struct appendctx *ctx = udata;
    ctx->expires = expires;
    ctx->flags = flags;
    ctx->outvallen = vallen+ctx->vallen;
    ctx->outval = xmalloc(ctx->outvallen);
    if (ctx->prepend) {
        memcpy(ctx->outval, ctx->val, ctx->vallen);
        memcpy(ctx->outval+ctx->vallen, val, vallen);
    } else {
        memcpy(ctx->outval, val, vallen);
        memcpy(ctx->outval+vallen, ctx->val, ctx->vallen);
    }
}

// APPEND <key> <value>
static void cmdAPPEND(struct conn *conn, struct args *args) {
    int64_t now = sys_now();
    if (args->len != 3) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    int proto = conn_proto(conn);
    bool prepend = argeq(args, 0, "prepend");
    size_t keylen;
    const char *key = args_at(args, 1, &keylen);
    size_t vallen;
    const char *val = args_at(args, 2, &vallen);
    struct appendctx ctx = { 
        .prepend = prepend,
        .val = val,
        .vallen = vallen,
    };
    size_t len;
    // Use a batch transaction for key isolation.
    struct pogocache *batch = pogocache_begin(cache);
    struct pogocache_load_opts lopts = { 
        .time = now,
        .entry = append_entry,
        .udata = &ctx,
    };
    int status = pogocache_load(batch, key, keylen, &lopts);
    if (status == POGOCACHE_NOTFOUND) {
        if (proto == PROTO_MEMCACHE) {
            conn_write_raw_cstr(conn, "NOT_STORED\r\n");
            goto done;
        }
        len = vallen;
        struct pogocache_store_opts sopts = {
            .time = now,
        };
        status = pogocache_store(batch, key, keylen, val, vallen, &sopts);
    } else {
        if (ctx.outvallen > MAXARGSZ) {
            // do not let values become larger than 500MB
            xfree(ctx.outval);
            conn_write_error(conn, "ERR value too large");
            goto done;
        }
        len = ctx.outvallen;
        struct pogocache_store_opts sopts = {
            .time = now,
            .expires = ctx.expires,
            .flags = ctx.flags,
        };
        status = pogocache_store(batch, key, keylen, ctx.outval, ctx.outvallen, 
            &sopts);
        xfree(ctx.outval);
    }
    if (status == POGOCACHE_NOMEM) {
        conn_write_error(conn, ERR_OUT_OF_MEMORY);
        goto done;
    }
    assert(status == POGOCACHE_INSERTED || status == POGOCACHE_REPLACED);
    if (proto == PROTO_POSTGRES) {
        pg_write_completef(conn, "%s %zu", prepend?"PREPEND":"APPEND", len);
        pg_write_ready(conn, 'I');
    } else if (proto == PROTO_MEMCACHE) {
        conn_write_raw_cstr(conn, "STORED\r\n");
    } else {
        conn_write_int(conn, len);
    }
done:
    pogocache_end(batch);
}

static void cmdPREPEND(struct conn *conn, struct args *args) {
    cmdAPPEND(conn, args);
}

static void cmdAUTH(struct conn *conn, struct args *args) {
    stat_auth_cmds_incr(0);
    if (!argeq(args, 0, "auth")) {
        stat_auth_errors_incr(0);
        goto noauth;
    }
    if (args->len == 3) {
        stat_auth_errors_incr(0);
        goto wrongpass;
    }
    if (args->len > 3) {
        stat_auth_errors_incr(0);
        conn_write_error(conn, ERR_SYNTAX_ERROR);
        return;
    }
    if (args->len == 1) {
        stat_auth_errors_incr(0);
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    if (args->bufs[1].len != strlen(auth) || 
        memcmp(auth, args->bufs[1].data, args->bufs[1].len) != 0)
    {
        stat_auth_errors_incr(0);
        goto wrongpass;
    }
    conn_setauth(conn, true);
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_complete(conn, "AUTH OK");
        pg_write_ready(conn, 'I');
    } else {
        conn_write_string(conn, "OK");
    }
    return;
noauth:
    if (conn_proto(conn) == PROTO_MEMCACHE) {
        conn_write_raw_cstr(conn, 
            "CLIENT_ERROR Authentication required\r\n");
    } else {
        conn_write_error(conn, "NOAUTH Authentication required.");
    }
    return;
wrongpass:
    conn_write_error(conn, 
        "WRONGPASS invalid username-password pair or user is disabled.");
}

struct stats {
    // use the args type as a list.
    struct args args;
};

static void stats_begin(struct stats *stats) {
    memset(stats, 0, sizeof(struct stats));
}

static void stats_end(struct stats *stats, struct conn *conn) {
    if (conn_proto(conn) == PROTO_POSTGRES) {
        pg_write_row_desc(conn, (const char*[]){ "stat", "value" }, 2);
        for (size_t i = 0; i < stats->args.len; i++) {
            char *stat = stats->args.bufs[i].data;
            char *key = stats->args.bufs[i].data;
            char *space = strchr(key, ' ');
            char *val = "";
            if (space) {
                *space = '\0';
                val = space+1;
            }
            pg_write_row_data(conn, (const char*[]){ stat, val }, 
                (size_t[]){ strlen(stat), strlen(val) }, 2);
        }
        pg_write_completef(conn, "STATS %zu", stats->args.len);
        pg_write_ready(conn, 'I');
    } else if (conn_proto(conn) == PROTO_MEMCACHE) {
        char line[512];
        for (size_t i = 0; i < stats->args.len; i++) {
            char *stat = stats->args.bufs[i].data;
            size_t n = snprintf(line, sizeof(line), "STAT %s\r\n", stat);
            conn_write_raw(conn, line, n);
        }
        conn_write_raw_cstr(conn, "END\r\n");
    } else {
        conn_write_array(conn, stats->args.len);
        for (size_t i = 0; i < stats->args.len; i++) {
            conn_write_array(conn, 2);
            char *key = stats->args.bufs[i].data;
            char *space = strchr(key, ' ');
            char *val = "";
            if (space) {
                *space = '\0';
                val = space+1;
            }
            conn_write_bulk_cstr(conn, key);
            conn_write_bulk_cstr(conn, val);
        }
    }
    args_free(&stats->args);
}

static void stats_printf(struct stats *stats, const char *format, ...) {
    // initializing list pointer
    char line[512];
    va_list ap;
    va_start(ap, format);
    size_t len = vsnprintf(line, sizeof(line)-1, format, ap);
    va_end(ap);
    args_append(&stats->args, line, len+1, false); // include null-terminator
}

static void stats(struct conn *conn) {
    struct stats stats;
    stats_begin(&stats);
    stats_printf(&stats, "pid %d", getpid());
    stats_printf(&stats, "uptime %.0f", (sys_now()-procstart)/1e9);
    stats_printf(&stats, "time %.0f", sys_unixnow()/1e9);
    stats_printf(&stats, "product %s", "pogocache");
    stats_printf(&stats, "version %s", version);
    stats_printf(&stats, "githash %s", githash);
    stats_printf(&stats, "pointer_size %zu", sizeof(uintptr_t)*8);
#ifdef __EMSCRIPTEN__
#else
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) == 0) {
        stats_printf(&stats, "rusage_user %ld.%06ld",
            usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        stats_printf(&stats, "rusage_system %ld.%06ld",
            usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
    }
#endif
    stats_printf(&stats, "max_connections %zu", maxconns);
    stats_printf(&stats, "curr_connections %zu", net_nconns());
    stats_printf(&stats, "total_connections %zu", net_tconns());
    stats_printf(&stats, "rejected_connections %zu", net_rconns());
    stats_printf(&stats, "cmd_get %" PRIu64, stat_cmd_get());
    stats_printf(&stats, "cmd_set %" PRIu64, stat_cmd_set());
    stats_printf(&stats, "cmd_flush %" PRIu64, stat_cmd_flush());
    stats_printf(&stats, "cmd_touch %" PRIu64, stat_cmd_touch());
    stats_printf(&stats, "get_hits %" PRIu64, stat_get_hits());
    stats_printf(&stats, "get_misses %" PRIu64, stat_get_misses());
    stats_printf(&stats, "delete_misses %" PRIu64, stat_delete_misses());
    stats_printf(&stats, "delete_hits %" PRIu64, stat_delete_hits());
    stats_printf(&stats, "incr_misses %" PRIu64, stat_incr_misses());
    stats_printf(&stats, "incr_hits %" PRIu64, stat_incr_hits());
    stats_printf(&stats, "decr_misses %" PRIu64, stat_decr_misses());
    stats_printf(&stats, "decr_hits %" PRIu64, stat_decr_hits());
    stats_printf(&stats, "touch_hits %" PRIu64, stat_touch_hits());
    stats_printf(&stats, "touch_misses %" PRIu64, stat_touch_misses());
    stats_printf(&stats, "store_too_large %" PRIu64, stat_store_too_large());
    stats_printf(&stats, "store_no_memory %" PRIu64, stat_store_no_memory());
    stats_printf(&stats, "auth_cmds %" PRIu64, stat_auth_cmds());
    stats_printf(&stats, "auth_errors %" PRIu64, stat_auth_errors());
    stats_printf(&stats, "threads %d", nthreads);
    struct sys_meminfo meminfo;
    sys_getmeminfo(&meminfo);
    stats_printf(&stats, "rss %zu", meminfo.rss);
    struct pogocache_size_opts sopts = { .entriesonly=true };
    stats_printf(&stats, "bytes %zu", pogocache_size(cache, &sopts));
    stats_printf(&stats, "curr_items %zu", pogocache_count(cache, 0));
    stats_printf(&stats, "total_items %" PRIu64, pogocache_total(cache, 0));
    stats_end(&stats, conn);
}

static void cmdSTATS(struct conn *conn, struct args *args) {
    if (args->len == 1) {
        stats(conn);
        return;
    }
    conn_write_error(conn, ERR_SYNTAX_ERROR);
    return;
}

static void cmdVERSION(struct conn *conn, struct args *args) {
    (void)args;
    int proto = conn_proto(conn);
    if (proto == PROTO_MEMCACHE) {
        conn_write_raw_cstr(conn, "VERSION ");
        conn_write_raw_cstr(conn, version);
        conn_write_raw_cstr(conn, "\r\n");
    } else if (proto == PROTO_POSTGRES) {
        pg_write_row_desc(conn, (const char*[]){ "version" }, 1);
            pg_write_row_data(conn, (const char*[]){ version },
                (size_t[]){ strlen(version) }, 1);
        pg_write_completef(conn, "VERSION 1");
        pg_write_ready(conn, 'I');
    } else {
        conn_write_string(conn, version);
    }
}

struct scan_ctx {
    char *pattern;
    size_t plen;
    int64_t now;
    size_t count;
    uint64_t cursor;
    struct pogocache_entry **entries;
    size_t len;
    size_t cap;
};

static void scan_ctx_free(struct scan_ctx *ctx) {
    if (ctx) {
        xfree(ctx->entries);
        xfree(ctx->pattern);
        xfree(ctx);
    }
}

static void scan_work(void *udata) {
    struct scan_ctx *ctx = udata;
    while (ctx->len < ctx->count) {
        struct pogocache_entry *entry;
        entry = pogocache_entry_iter(cache, ctx->now, &ctx->cursor);
        if (!entry) {
            break;
        }
        char buf[128];
        size_t keylen;
        const void *key = pogocache_entry_key(cache, entry, &keylen, buf);
        if (match(ctx->pattern, ctx->plen, key, keylen, 0)) {
            if (ctx->len == ctx->cap) {
                ctx->cap = ctx->cap ? ctx->cap * 2 : 16;
                ctx->entries = xrealloc(ctx->entries, sizeof(void*)*ctx->cap);
            }
            ctx->entries[ctx->len++] = entry;
        } else {
            pogocache_entry_release(cache, entry);
        }
    }
}

static void scan_done(struct conn *conn, void *udata) {
    struct scan_ctx *ctx = udata;
    int proto = conn_proto(conn);
    char scursor[32];
    size_t clen = u64toa(ctx->cursor, (uint8_t*)scursor);
    if (proto == PROTO_POSTGRES) {
        pg_write_row_desc(conn, (const char*[]){ "key", "cursor" }, 2);
    } else {
        conn_write_array(conn, 2);
        conn_write_bulk_cstr(conn, scursor);
        conn_write_array(conn, ctx->len);
    }
    for (size_t i = 0; i < ctx->len; i++) {
        struct pogocache_entry *entry = ctx->entries[i];
        char buf[128];
        size_t keylen;
        const void *key = pogocache_entry_key(cache, entry, &keylen, buf);
        if (proto == PROTO_POSTGRES) {
            pg_write_row_data(conn, (const char*[]){ key, scursor },
                (size_t[]){ keylen, clen }, 2);
        } else {
            conn_write_bulk(conn, key, keylen);
        }
        pogocache_entry_release(cache, entry);
    }
    if (proto == PROTO_POSTGRES) {
        pg_write_completef(conn, "SCAN %zu", ctx->len);
        pg_write_ready(conn, 'I');
    }
    scan_ctx_free(ctx);
}

// SCAN cursor [MATCH pattern] [COUNT count] [TYPE type]
static void cmdSCAN(struct conn *conn, struct args *args) {
    if (args->len < 2) {
        conn_write_error(conn, ERR_WRONG_NUM_ARGS);
        return;
    }
    size_t count = 100;
    const char *stype = "string";
    const void *pattern = "*";
    size_t plen = 1;
    uint64_t cursor;
    if (!argu64(args, 1, &cursor)) {
        conn_write_error(conn, "ERR invalid cursor");
        return;
    }
    for (size_t i = 2; i < args->len; i++) {
        if (argeq(args, i, "match")) {
            i++;
            if (i == args->len) {
                goto err_syntax;
            }
            pattern = args->bufs[i].data;
            plen = args->bufs[i].len;
        } else if (argeq(args, i, "count")) {
            i++;
            if (i == args->len) {
                goto err_syntax;
            }
            uint64_t x;
            if (!argu64(args, i, &x) || x == 0 || x > INT32_MAX) {
                goto err_syntax;
            }
            count = x;
        } else if (argeq(args, i, "type")) {
            i++;
            if (i == args->len) {
                goto err_syntax;
            }
            if (argeq(args, i, "string")) {
                stype = "string";
            } else {
                char str[128];
                snprintf(str, sizeof(str), "ERR unknown type name '%.*s'",
                    (int)args->bufs[i].len, args->bufs[i].data);
                conn_write_error(conn, str);
                return;
            }
        } else {
            goto err_syntax;
        }
    }
    (void)stype;
    int64_t now = sys_now();
    struct scan_ctx *ctx = xmalloc(sizeof(struct scan_ctx));
    memset(ctx, 0, sizeof(struct scan_ctx));
    ctx->pattern = xmalloc(plen+1);
    memcpy(ctx->pattern, pattern, plen);
    ctx->pattern[plen] = '\0';
    ctx->plen = plen;
    ctx->count = count;
    ctx->now = now;
    ctx->cursor = cursor;

    // call in the foreground
    scan_work(ctx);
    scan_done(conn, ctx);
    
    return;
err_syntax:
    conn_write_error(conn, ERR_SYNTAX_ERROR);
}


// Commands hash table. Lazy loaded per thread.
// Simple open addressing using case-insensitive fnv1a hashes.
static int nbuckets;
static struct cmd *buckets;

struct cmd {
    const char *name;
    void (*func)(struct conn *conn, struct args *args);
};

static struct cmd cmds[] = {
    { "set",       cmdSET      }, // pg
    { "get",       cmdGET      }, // pg
    { "del",       cmdDEL      }, // pg
    { "mget",      cmdMGET     }, // pg
    { "mgets",     cmdMGET     }, // pg cas detected
    { "ttl",       cmdTTL      }, // pg
    { "pttl",      cmdTTL      }, // pg
    { "expire",    cmdEXPIRE   }, // pg
    { "setex",     cmdSETEX    }, // pg
    { "dbsize",    cmdDBSIZE   }, // pg
    { "quit",      cmdQUIT     }, // pg
    { "echo",      cmdECHO     }, // pg
    { "exists",    cmdEXISTS   }, // pg
    { "flushdb",   cmdFLUSHALL }, // pg
    { "flushall",  cmdFLUSHALL }, // pg
    { "flush",     cmdFLUSHALL }, // pg
    { "monitor",   cmdMONITOR  }, // pg not available
    { "purge",     cmdPURGE    }, // pg
    { "sweep",     cmdSWEEP    }, // pg
    { "keys",      cmdKEYS     }, // pg
    { "select",    cmdSELECT   }, // pg
    { "ping",      cmdPING     }, // pg
    { "touch",     cmdTOUCH    }, // pg
    { "debug",     cmdDEBUG    }, // pg
    { "incrby",    cmdINCRBY   }, // pg
    { "decrby",    cmdDECRBY   }, // pg
    { "incr",      cmdINCR     }, // pg
    { "decr",      cmdDECR     }, // pg
    { "uincrby",   cmdINCRBY   }, // pg unsigned detected in signed operation
    { "udecrby",   cmdDECRBY   }, // pg unsigned detected in signed operation
    { "uincr",     cmdINCR     }, // pg unsigned detected in signed operation
    { "udecr",     cmdDECR     }, // pg unsigned detected in signed operation
    { "append",    cmdAPPEND   }, // pg
    { "prepend",   cmdPREPEND  }, // pg
    { "auth",      cmdAUTH     }, // pg
    { "save",      cmdSAVELOAD }, // pg
    { "load",      cmdSAVELOAD }, // pg
    { "stats",     cmdSTATS    }, // pg memcache style stats
    { "version",   cmdVERSION  }, // pg
    { "scan",      cmdSCAN     }, // pg
};

static void build_commands_table(void) {
    static __thread bool buckets_ready = false;
    static pthread_mutex_t cmd_build_lock = PTHREAD_MUTEX_INITIALIZER;
    static bool built = false;
    if (!buckets_ready) {
        pthread_mutex_lock(&cmd_build_lock);
        if (!built) {
            int ncmds = sizeof(cmds)/sizeof(struct cmd);
            int n = ncmds*8;
            nbuckets = 2;
            while (nbuckets < n) {
                nbuckets *= 2;
            }
            buckets = xmalloc(nbuckets*sizeof(struct cmd));
            memset(buckets, 0, nbuckets*sizeof(struct cmd));
            uint64_t hash;
            for (int i = 0; i < ncmds; i++) {
                hash = fnv1a_case(cmds[i].name, strlen(cmds[i].name));
                for (int j = 0; j < nbuckets; j++) {
                    int k = (j+hash)&(nbuckets-1);
                    if (!buckets[k].name) {
                        buckets[k] = cmds[i];
                        break;
                    }
                }
            }
            built = true;
        }
        pthread_mutex_unlock(&cmd_build_lock);
        buckets_ready = true;
    }
}

static struct cmd *get_cmd(const char *name, size_t namelen) {
    build_commands_table();
    uint32_t hash = fnv1a_case(name, namelen);
    int j = hash&(nbuckets-1);
    while (1) {
        if (!buckets[j].name) {
            return 0;
        }
        if (argeq_bytes(name, namelen, buckets[j].name)) {
            return &buckets[j];
        }
        j++;
    }
}

void evcommand(struct conn *conn, struct args *args) {
    if (useauth && !conn_auth(conn)) {
        if (conn_proto(conn) == PROTO_HTTP) {
            // Let HTTP traffic through.
            // The request has already been authorized in http.c
        } else {
            cmdAUTH(conn, args);
            return;
        }
    }
    if (verb >= 3) {
        if (!argeq(args, 0, "auth")) {
            args_print(args);
        }
    }

    struct cmd *cmd = get_cmd(args->bufs[0].data, args->bufs[0].len);
    if (cmd) {
        monitor_cmd(sys_unixnow(), 0, conn_addr(conn), args);
        cmd->func(conn, args);
    } else {
        char *errmsg = xmalloc(256);
        snprintf(errmsg, 256, "ERR unknown command '%.*s'",
            (int)args->bufs[0].len, args->bufs[0].data);
        conn_write_error(conn, errmsg);
        xfree(errmsg);
        if (verb >= 1) {
            printf("# Unknown command '%.*s'\n", (int)args->bufs[0].len,
                args->bufs[0].data);
        }
    }
}
