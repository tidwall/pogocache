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
// Unit postgres.c provides the parser for the Postgres wire protocol.
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/types.h>
#include "parse.h"
#include "util.h"
#include "conn.h"
#include "xmalloc.h"

// #define PGDEBUG

#define TEXTOID     25
#define BYTEAOID    17

extern const char *version;
extern const char *auth;

#ifdef PGDEBUG
#define dprintf printf
#else
#define dprintf(...)
#endif

static void print_packet(const char *data, size_t len) {
    dprintf(". PACKET=%03zu [ ", len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    dprintf("]\n");
    dprintf(".            [");
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = data[i];
        if (ch < ' ') {
            ch = '?';
        }
        dprintf("%c", ch);
    }
    dprintf("]\n");
}

static int32_t read_i32(const char *data) {
    return ((uint32_t)(uint8_t)data[0] << 24) |
           ((uint32_t)(uint8_t)data[1] << 16) |
           ((uint32_t)(uint8_t)data[2] << 8) |
           ((uint32_t)(uint8_t)data[3] << 0);
}

static void write_i32(char *data, int32_t x) {
    data[0] = (uint8_t)(((uint32_t)x) >> 24) & 0xFF;
    data[1] = (uint8_t)(((uint32_t)x) >> 16) & 0xFF;
    data[2] = (uint8_t)(((uint32_t)x) >> 8) & 0xFF;
    data[3] = (uint8_t)(((uint32_t)x) >> 0) & 0xFF;
}

static int16_t read_i16(const char *data) {
    return ((uint16_t)(uint8_t)data[0] << 8) |
           ((uint16_t)(uint8_t)data[1] << 0);
}
static void write_i16(char *data, int16_t x) {
    data[0] = (uint8_t)(((uint16_t)x) >> 8) & 0xFF;
    data[1] = (uint8_t)(((uint16_t)x) >> 0) & 0xFF;
}

// parse_begin is called to begin parsing a client message.
#define parse_begin() \
    const char *p = data; \
    const char *e = p+len; \
    (void)args, (void)pg, (void)e;

// parse_end is called when parsing client message is complete.
// This will check that the position of the client stream matches the
// expected lenght provided by the client. 
#define parse_end() \
    if ((size_t)(p-data) != len) { \
        return -1; \
    }

#define parse_cstr() ({ \
    const char *cstr = 0; \
    const char *s = p; \
    while (p < e) { \
        if (*p == '\0') { \
            cstr = s; \
            p++; \
            break; \
        } \
        p++; \
    } \
    if (!cstr) { \
        return -1; \
    } \
    cstr; \
}) 

#define parse_int16() ({ \
    if (e-p < 2) { \
        return -1; \
    } \
    int16_t x = read_i16(p); \
    p += 2; \
    x; \
})

#define parse_byte() ({ \
    if (e-p < 1) { \
        return -1; \
    } \
    uint8_t x = *p; \
    p += 1; \
    x; \
})

#define parse_int32() ({ \
    if (e-p < 4) { \
        return -1; \
    } \
    int32_t x = read_i32(p); \
    p += 4; \
    x; \
})

#define parse_bytes(n) ({ \
    if (e-p < n) { \
        return -1; \
    } \
    const void *s = p; \
    p += (n); \
    s; \
})

static void arg_append_unescape_simplestr(struct args *args, const char *str,
    size_t slen)
{
    size_t str2len = 0;
    char *str2 = xmalloc(slen+1);
    for (size_t i = 0; i < str2len; i++) {
        if (str[i] == '\'' && str[i+1] == '\'') {
            i++;
        }
        str2[str2len++] = str[i];
    }
    args_append(args, str2, str2len, false);
    xfree(str2);
}

static void pg_statement_free(struct pg_statement *statement) {
    args_free(&statement->args);
    buf_clear(&statement->argtypes);
}


static void pg_portal_free(struct pg_portal *portal) {
    args_free(&portal->params);
}

static void statments_free(struct hashmap *map) {
    if (!map) {
        return;
    }
    size_t i = 0;
    void *item;
    while (hashmap_iter(map, &i, &item)) {
        struct pg_statement statement;
        memcpy(&statement, item, sizeof(struct pg_statement));
        pg_statement_free(&statement);
    }
    hashmap_free(map);
}

static void portals_free(struct hashmap *map) {
    if (!map) {
        return;
    }
    size_t i = 0;
    void *item;
    while (hashmap_iter(map, &i, &item)) {
        struct pg_portal portal;
        memcpy(&portal, item, sizeof(struct pg_portal));
        pg_portal_free(&portal);
    }
    hashmap_free(map);
}

struct pg *pg_new(void) {
    struct pg *pg = xmalloc(sizeof(struct pg));
    memset(pg, 0, sizeof(struct pg));
    pg->oid = TEXTOID;
    return pg;
}

void pg_free(struct pg *pg) {
    if (!pg) {
        return;
    }
    xfree(pg->application_name);
    xfree(pg->database);
    xfree(pg->user);
    buf_clear(&pg->buf);
    statments_free(pg->statements);
    portals_free(pg->portals);
    args_free(&pg->targs);
    // args_free(&pg->xargs);
    xfree(pg->desc);
    xfree(pg);
}

static uint64_t pg_statement_hash(const void *item, uint64_t seed0, 
    uint64_t seed1)
{
    struct pg_statement statement;
    memcpy(&statement, item, sizeof(struct pg_statement));
    return hashmap_murmur(statement.name, strlen(statement.name), seed0, seed1);
}

static uint64_t pg_portal_hash(const void *item, uint64_t seed0, 
    uint64_t seed1)
{
    struct pg_portal portal;
    memcpy(&portal, item, sizeof(struct pg_portal));
    return hashmap_murmur(portal.name, strlen(portal.name), seed0, seed1);
}

static int pg_statement_compare(const void *a, const void *b, void *udata) {
    (void)udata;
    struct pg_statement stmta;
    memcpy(&stmta, a, sizeof(struct pg_statement));
    struct pg_statement stmtb;
    memcpy(&stmtb, b, sizeof(struct pg_statement));
    return strcmp(stmta.name, stmtb.name);
}

static int pg_portal_compare(const void *a, const void *b, void *udata) {
    (void)udata;
    struct pg_portal portala;
    memcpy(&portala, a, sizeof(struct pg_portal));
    struct pg_portal portalb;
    memcpy(&portalb, b, sizeof(struct pg_portal));
    return strcmp(portala.name, portalb.name);
}

static void portal_insert(struct pg *pg, struct pg_portal *portal) {
    (void)portal;
    if (!pg->portals) {
        pg->portals = hashmap_new_with_allocator(xmalloc, xrealloc, xfree, 
            sizeof(struct pg_portal), 0, 0, 0, pg_portal_hash, 
            pg_portal_compare, 0, 0);
    }
    const void *ptr = hashmap_set(pg->portals, portal);
    if (ptr) {
        struct pg_portal old;
        memcpy(&old, ptr, sizeof(struct pg_portal));
        pg_portal_free(&old);
    }
}

static void statement_insert(struct pg *pg, struct pg_statement *stmt) {
    if (!pg->statements) {
        pg->statements = hashmap_new_with_allocator(xmalloc, xrealloc, xfree, 
            sizeof(struct pg_statement), 0, 0, 0, pg_statement_hash, 
            pg_statement_compare, 0, 0);
    }
    const void *ptr = hashmap_set(pg->statements, stmt);
    if (ptr) {
        struct pg_statement old;
        memcpy(&old, ptr, sizeof(struct pg_statement));
        pg_statement_free(&old);
    }
}

static bool statement_get(struct pg *pg, const char *name, 
    struct pg_statement *stmt)
{
    if (!pg->statements) {
        return false;
    }
    size_t namelen = strlen(name);
    if (namelen >= PGNAMEDATALEN) {
        return false;
    }
    struct pg_statement key = { 0 };
    strcpy(key.name, name);
    const void *ptr = hashmap_get(pg->statements, &key);
    if (!ptr) {
        return false;
    }
    memcpy(stmt, ptr, sizeof(struct pg_statement));
    return true;
}

static bool portal_get(struct pg *pg, const char *name, 
    struct pg_portal *portal)
{
    if (!pg->portals) {
        return false;
    }
    size_t namelen = strlen(name);
    if (namelen >= PGNAMEDATALEN) {
        return false;
    }
    struct pg_portal key = { 0 };
    strcpy(key.name, name);
    const void *ptr = hashmap_get(pg->portals, &key);
    if (!ptr) {
        return false;
    }
    memcpy(portal, ptr, sizeof(struct pg_portal));
    return true;
}

static const uint8_t hextoks[256] = { 
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,9,0,0,0,0,0,0,
    0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
};

static uint32_t decode_hex(const uint8_t *str) {
    return (((int)hextoks[str[0]])<<12) | (((int)hextoks[str[1]])<<8) |
           (((int)hextoks[str[2]])<<4) | (((int)hextoks[str[3]])<<0);
}

static bool is_surrogate(uint32_t cp) {
    return cp > 55296 && cp < 57344;
}

static uint32_t decode_codepoint(uint32_t cp1, uint32_t cp2) {
    return cp1 > 55296  && cp1 < 56320 && cp2 > 56320 && cp2 < 57344 ?
        ((cp1 - 55296) << 10) | ((cp2 - 56320) + 65536) :
        65533;
}

static inline int encode_codepoint(uint8_t dst[], uint32_t cp) {
    if (cp < 128) {
        dst[0] = cp;
        return 1;
    } else if (cp < 2048) {
        dst[0] = 192 | (cp >> 6);
        dst[1] = 128 | (cp & 63);
        return 2;
    } else if (cp > 1114111 || is_surrogate(cp)) {
        cp = 65533; // error codepoint
    }
    if (cp < 65536) {
        dst[0] = 224 | (cp >> 12);
        dst[1] = 128 | ((cp >> 6) & 63);
        dst[2] = 128 | (cp & 63);
        return 3;
    }
    dst[0] = 240 | (cp >> 18);
    dst[1] = 128 | ((cp >> 12) & 63);
    dst[2] = 128 | ((cp >> 6) & 63);
    dst[3] = 128 | (cp & 63);
    return 4;
}

// for_each_utf8 iterates over each UTF-8 bytes in jstr, unescaping along the
// way. 'f' is a loop expression that will make available the 'ch' char which 
// is just a single byte in a UTF-8 series.
// this is taken from https://github.com/tidwall/json.c
#define for_each_utf8(jstr, len, f) { \
    size_t nn = (len); \
    int ch = 0; \
    (void)ch; \
    for (size_t ii = 0; ii < nn; ii++) { \
        if ((jstr)[ii] != '\\') { \
            ch = (jstr)[ii]; \
            if (1) f \
            continue; \
        }; \
        ii++; \
        if (ii == nn) break; \
        switch  ((jstr)[ii]) { \
        case '\\': ch = '\\'; break; \
        case '/' : ch = '/';  break; \
        case 'b' : ch = '\b'; break; \
        case 'f' : ch = '\f'; break; \
        case 'n' : ch = '\n'; break; \
        case 'r' : ch = '\r'; break; \
        case 't' : ch = '\t'; break; \
        case '"' : ch = '"';  break; \
        case 'u' : \
            if (ii+5 > nn) { nn = 0; continue; }; \
            uint32_t cp = decode_hex((jstr)+ii+1); \
            ii += 5; \
            if (is_surrogate(cp)) { \
                if (nn-ii >= 6 && (jstr)[ii] == '\\' && (jstr)[ii+1] == 'u') { \
                    cp = decode_codepoint(cp, decode_hex((jstr)+ii+2)); \
                    ii += 6; \
                } \
            } \
            uint8_t _bytes[4]; \
            int _n = encode_codepoint(_bytes, cp); \
            for (int _j = 0; _j < _n; _j++) { \
                ch = _bytes[_j]; \
                if (1) f \
            } \
            ii--; \
            continue; \
        default: \
            continue; \
        }; \
        if (1) f \
    } \
}

static void arg_append_unescape_str(struct args *args, const char *str,
    size_t slen)
{
    size_t str2len = 0;
    uint8_t *str2 = xmalloc(slen+1);
    for_each_utf8((uint8_t*)str, slen, {
        str2[str2len++] = ch;
    });
    args_append(args, (char*)str2, str2len, false);
    xfree(str2);
}

// Very simple map to stores all params numbers.
struct pmap {
    int count;
    int nbuckets;
    uint16_t *buckets;
    uint16_t def[8];
};

static void pmap_init(struct pmap *map) {
    memset(map, 0, sizeof(struct pmap));
    map->nbuckets = sizeof(map->def)/sizeof(uint16_t);
    map->buckets = map->def;
}

static void pmap_free(struct pmap *map) {
    if (map->buckets != map->def) {
        xfree(map->buckets);
    }
}

static void pmap_insert0(uint16_t *buckets, int nbuckets, uint16_t param) {
    uint16_t hash = mix13(param);
    int i = hash%nbuckets;
    while (1) {
        if (buckets[i] == 0) {
            buckets[i] = param;
            return;
        }
        i = (i+1)%nbuckets;
    }
}

static void pmap_grow(struct pmap *map) {
    int nbuckets2 = map->nbuckets*2;
    uint16_t *buckets2 = xmalloc(nbuckets2*sizeof(uint16_t));
    memset(buckets2, 0, nbuckets2*sizeof(uint16_t));
    for (int i = 0; i < map->nbuckets; i++) {
        if (map->buckets[i]) {
            pmap_insert0(buckets2, nbuckets2, map->buckets[i]);
        }
    }
    if (map->buckets != map->def) {
        xfree(map->buckets);
    }
    map->buckets = buckets2;
    map->nbuckets = nbuckets2;
}

static void pmap_insert(struct pmap *map, uint16_t param) {
    assert(param != 0);
    if (map->count == (map->nbuckets>>1)+(map->nbuckets>>2)) {
        pmap_grow(map);
    }
    pmap_insert0(map->buckets, map->nbuckets, param);
    map->count++;
}

static bool pmap_exists(struct pmap *map, uint16_t param) {
    uint16_t hash = mix13(param);
    int i = hash%map->nbuckets;
    while (1) {
        if (map->buckets[i] == 0) {
            return false;
        }
        if (map->buckets[i] == param) {
            return true;
        }
        i = (i+1)%map->nbuckets;
    }
}

static bool parse_query_args(const char *query, struct args *args, 
    int *nparams, struct buf *argtypes)
{
    dprintf("parse_query: [%s]\n", query);
    struct pmap pmap;
    pmap_init(&pmap);

    // loop through each keyword
    while (isspace(*query)) {
        query++;
    }
    bool ok = false;
    bool esc = false;
    const char *str;
    const char *p = query;
    bool join = false;
    while (*p) {
        switch (*p) {
        case ';':
            goto break_while;
        case '\"':
            // identifier
            parse_errorf("idenifiers not allowed");
            goto done;
        case '\'':
            // simple string
            p++;
            str = p;
            esc = false;
            while (*p) {
                if (*p == '\'') {
                    if (*(p+1) == '\'') {
                        esc = true;
                        p += 2;
                        continue;
                    }
                    break;
                }
                p++;
            }
            if (*p != '\'') {
                parse_errorf("unterminated quoted string");
                goto done;
            }
            size_t slen = p-str;
            if (!esc) {
                args_append(args, str, slen, true);
            } else {
                arg_append_unescape_simplestr(args, str, slen);
            }
            if (argtypes) {
                buf_append_byte(argtypes, 'A'+join);
                join = *(p+1) && !isspace(*(p+1));
            }
            break;
        case '$':
            // dollar-quote or possible param
            if (*(p+1) >= '0' && *(p+1) <= '9') {
                char *e = 0;
                long param = strtol(p+1, &e, 10);
                if (param == 0 || param > 0xFFFF) {
                    parse_errorf("there is no parameter $%ld", param);
                    goto done;
                }
                pmap_insert(&pmap, param);
                args_append(args, p, e-p, true);
                if (argtypes) {
                    buf_append_byte(argtypes, 'P'+join);
                    join = *e && !isspace(*e);
                }
                p = e;
                continue;
            }
            // dollar-quote strings not
            parse_errorf("dollar-quote strings not allowed");
            goto done;
        case 'E': case 'e':
            if (*(p+1) == '\'') {
                // escaped string
                p += 2;
                str = p;
                while (*p) {
                    if (*p == '\\') {
                        esc = true;
                    } else if (*p == '\'') {
                        size_t x = 0;
                        while (*(p-x-1) == '\\') {
                            x++;
                        }
                        if ((x%2)==0) {
                            break;
                        }
                    }
                    p++;
                }
                if (*p != '\'') {
                    parse_errorf("unterminated quoted string");
                    goto done;
                }
                size_t s_len = p-str;
                if (!esc) {
                    args_append(args, str, s_len, true);
                } else {
                    arg_append_unescape_str(args, str, s_len);
                }
                if (argtypes) {
                    buf_append_byte(argtypes, 'A'+join);
                    join = *(p+1) && !isspace(*(p+1));
                }
                break;
            }
            // fallthrough
        default:
            if (isspace(*p)) {
                p++;
                continue;
            }
            // keyword
            const char *keyword = p;
            while (*p && !isspace(*p)) {
                if (*p == ';' || *p == '\'' || *p == '\"' || *p == '$') {
                    break;
                }
                p++;
            }
            size_t keywordlen = p-keyword;
            args_append(args, keyword, keywordlen, true);
            if (argtypes) {
                buf_append_byte(argtypes, 'A'+join);
                join = *p && !isspace(*p);
            }
            while (isspace(*p)) {
                p++;
            }
            continue;
        }
        p++;
    }
break_while:
    while (*p) {
        if (*p != ';') {
            parse_errorf("unexpected characters at end of query");
            goto done;
        }
        p++;
    }
    ok = true;
done:
    if (ok) {
        // check params
        for (int i = 0; i < pmap.count; i++) {
            if (!pmap_exists(&pmap, i+1)) {
                parse_errorf("missing parameter $%d", i+1);
                ok = false;
                break;
            }
        }
    }
    *nparams = pmap.count;
    pmap_free(&pmap);
    if (argtypes) {
        buf_append_byte(argtypes, '\0');
    }
    return ok;
}

static bool parse_cache_query_args(const char *query, struct args *args,
    int *maxparam, struct buf *argtypes)
{
    while (isspace(*query)) {
        query++;
    }
    if (!parse_query_args(query, args, maxparam, argtypes)) {
        return false;
    }
#ifdef PGDEBUG
    args_print(args);
#endif
    if (argtypes) {
        dprintf("argtypes: [%s]\n", argtypes->data);
    }
    return true;
}

static size_t parseQ(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    // Query
    dprintf(">>> Query\n");
    parse_begin();
    const char *query = parse_cstr();
    parse_end();
    int nparams = 0;
    bool pok = parse_cache_query_args(query, args, &nparams, 0);
    if (!pok) {
        pg->error = 1;
        args_clear(args);
        return len;
    }
    if (nparams > 0) {
        parse_seterror("query cannot have parameters");
        pg->error = 1;
        args_clear(args);
        return len;
    }
    if (args->len == 0) {
        pg->empty_query = 1;
    }
    return len;
}

static size_t parseP(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    // Parse
    dprintf("<<< Parse\n");
    // print_packet(data, len);
    parse_begin();
    const char *stmt_name = parse_cstr();
    const char *query = parse_cstr();
    uint16_t num_param_types = parse_int16();
    // dprintf(". Parse [%s] [%s] [%d]\n", stmt_name, query,
    //    (int)num_param_types);
    for (uint16_t i = 0; i < num_param_types; i++) {
        int32_t param_type = parse_int32();
        (void)param_type;
        // dprintf(".       [%d]\n", param_type);
    }
    parse_end();
    if (strlen(stmt_name) >= PGNAMEDATALEN) {
        parse_seterror("statement name too large");
        pg->error = 1;
        return len;
    }
    int nparams = 0;
    struct buf argtypes = { 0 };
    bool ok = parse_cache_query_args(query, args, &nparams, &argtypes);
    if (!ok) {
        pg->error = 1;
        args_clear(args);
        buf_clear(&argtypes);
        return len;
    }
    // copy over last statement
    struct pg_statement stmt = { 0 };
    strcpy(stmt.name, stmt_name);
    stmt.nparams = nparams;
    // copy over parsed args
    for (size_t i = 0; i < args->len; i++) {
        args_append(&stmt.args, args->bufs[i].data, args->bufs[i].len, false);
    }
    args_clear(args);
    stmt.argtypes = argtypes;
    statement_insert(pg, &stmt);
    pg->parse = 1;
    return len;
}

static size_t parseD(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    // Describe
    dprintf("<<< Describe\n");
    if (pg->describe) {
        // Already has a describe in a sequence
        pg->error = 1;
        parse_errorf("double describe not allowed");
        return -1;
    }
    // print_packet(data, len);
    parse_begin();
    uint8_t type = parse_byte();
    const char *name = parse_cstr();
    parse_end();

    dprintf(". Describe [%c] [%s]\n", type, name);
    if (type == 'P' || type == 'P'+1) {
        struct pg_portal portal;
        if (!portal_get(pg, name, &portal)) {
            parse_errorf("portal not found");
            pg->error = 1;
            return len;
        }
        // Byte1('T')
        // Int32 length
        // Int16 field_count
        // Field[] fields
        // all fields are unnamed text
        char field[] = { 
            0x00,                      // "\0" (field name)
            0x00, 0x00, 0x00, 0x00,    // table_oid = 0
            0x00, 0x00,                // column_attr_no = 0
            0x00, 0x00, 0x00, pg->oid, // type_oid = 25 (text)
            0xFF, 0xFF,                // type_size = -1
            0xFF, 0xFF, 0xFF, 0xFF,    // type_modifier = -1
            0x00, 0x00,                // format_code = 0 (text)
        };
        static_assert(sizeof(field) == 19, "");
        size_t size = 1+4+2+portal.params.len*sizeof(field);
        if (pg->desc) {
            xfree(pg->desc);
        }
        pg->desc = xmalloc(size);
        memset(pg->desc, 0, size);
        char *p1 = pg->desc;
        *(p1++) = 'T';
        write_i32(p1, size-1);
        p1 += 4;
        write_i16(p1, portal.params.len);
        p1 += 2;
        for (size_t i = 0; i < portal.params.len; i++) {
            memcpy(p1, field, sizeof(field));
            p1 += sizeof(field);
        }
        pg->desclen = size;
        return len;
    }

    if (type == 'S') {
        struct pg_statement stmt;
        if (!statement_get(pg, name, &stmt)) {
            parse_errorf("statement not found");
            pg->error = 1;
            return len;
        }
        // Byte1('t')
        // Int32 length
        // Int16 num_params
        // Int32[] param_type_oids
        size_t size = 1+4+2+stmt.nparams*4;
        if (pg->desc) {
            xfree(pg->desc);
        }
        pg->desc = xmalloc(size);
        memset(pg->desc, 0, size);
        char *p1 = pg->desc;
        *(p1++) = 't';
        write_i32(p1, size-1);
        p1 += 4;
        write_i16(p1, stmt.nparams);
        p1 += 2;
        for (int i = 0; i < stmt.nparams; i++) {
            write_i32(p1, pg->oid);
            p1 += 4;
        }
        pg->desclen = size;
        pg->describe = 1;
        return len;
    }
    parse_errorf("unsupported describe type '%c'", type);
    pg->error = 1;
    return len;
}

static size_t parseB(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    (void)args, (void)pg;

    // Bind
    dprintf("<<< Bind\n");

    // print_packet(data, len);

    // X Byte1('B')               # Bind message identifier
    // X Int32 length             # Message length including self
    //
    // String portal_name       # Destination portal ("" = unnamed)
    // String statement_name    # Prepared statement name (from Parse)
    // Int16 num_format_codes   # 0 = all text, 1 = one for all, or N
    // [Int16] format_codes     # 0 = text, 1 = binary
    // Int16 num_parameters
    // [parameter values]
    // Int16 num_result_formats
    // [Int16] result_format_codes

    parse_begin();
    const char *portal_name = parse_cstr();
    const char *stmt_name = parse_cstr();
    int num_formats = parse_int16();
    for (int i = 0; i < num_formats; i++) {
        int format = parse_int16();
        if (format != 0 && format != 1) {
            parse_errorf("only text or binary format allowed");
            pg->error = 1;
            return len;
        }
    }
    uint16_t num_params = parse_int16();
    args_clear(&pg->targs);
    for (int i = 0; i < num_params; i++) {
        int32_t n = parse_int32();
        if (n <= 0) {
            // Nulls are empty strings
            n = 0;
        }
        const char *b = parse_bytes(n);
        args_append(&pg->targs, b, n, false);
    }
    // ignore result formats
    uint16_t num_result_formats = parse_int16();
    for (int i = 0; i < num_result_formats; i++) {
        int result_format_codes = parse_int16();
        (void)result_format_codes;
    }
    parse_end();

    if (strlen(portal_name) >= PGNAMEDATALEN) {
        parse_seterror("portal name too large");
        pg->error = 1;
        return len;
    }
    if (strlen(stmt_name) >= PGNAMEDATALEN) {
        parse_seterror("statement name too large");
        pg->error = 1;
        return len;
    }
    struct pg_portal portal = { 0 };
    strcpy(portal.name, portal_name);
    strcpy(portal.stmt, stmt_name);
    memcpy(&portal.params, &pg->targs, sizeof(struct args));
    memset(&pg->targs, 0, sizeof(struct args));
    portal_insert(pg, &portal);
    pg->bind = 1;
    return len;
}

static size_t parseX(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    (void)args, (void)pg;
    // Close
    dprintf("<<< Close\n");
    parse_begin();
    parse_end();
    pg->close = 1;
    return len;
}

static size_t parseE(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    (void)args, (void)pg;
    // Execute
    dprintf("<<< Execute\n");
    parse_begin();
    const char *portal_name = parse_cstr();
    size_t max_rows = parse_int32();
    parse_end();
    struct pg_portal portal;
    if (!portal_get(pg, portal_name, &portal)) {
        parse_seterror("portal not found");
        pg->error = 1;
        return len;
    }
    struct pg_statement stmt;
    if (!statement_get(pg, portal.stmt, &stmt)) {
        parse_seterror("statement not found");
        pg->error = 1;
        return len;
    }
    if ((size_t)stmt.nparams != portal.params.len) {
        parse_seterror("portal params mismatch");
        pg->error = 1;
        return len;
    }
    // ignore max_rows
    (void)max_rows;

    // 
    args_clear(&pg->targs);
    for (size_t i = 0; i < stmt.args.len; i++) {
        const char *arg = stmt.args.bufs[i].data;
        size_t arglen = stmt.args.bufs[i].len;
        char atype = stmt.argtypes.data[i];
        dprintf("[%.*s] [%c]\n", (int)arglen, arg, atype);
        bool join = false;
        switch (atype) {
        case 'A'+1:
            atype = 'A';
            join = true;
            break;
        case 'P':
            join = false;
            break;
        case 'P'+1:
            atype = 'P';
            join = true;
            break;
        }
        if (atype == 'P') {
            if (arglen == 0 || arg[0] != '$') {
                goto internal_error;
            }
            uint64_t x;
            bool ok = parse_u64(arg+1, arglen-1, &x);
            if (!ok || x == 0 || x > 0xFFFF) {
                goto internal_error;
            }
            size_t paramidx = x-1;
            if (paramidx >= portal.params.len) {
                goto internal_error;
            }
            arg = portal.params.bufs[paramidx].data;
            arglen = portal.params.bufs[paramidx].len;
        }
        if (join) {
            assert(pg->targs.len > 0);
            buf_append(&pg->targs.bufs[pg->targs.len-1], arg, arglen);
        } else {
            args_append(&pg->targs, arg, arglen, false);
        }
    }

    struct args swapargs = *args;
    *args = pg->targs;
    pg->targs = swapargs;

#ifdef PGDEBUG
    args_print(args);
#endif

    pg->execute = 1;
    return len;
internal_error:
    parse_seterror("portal params internal error");
    pg->error = 1;
    return len;
}

static size_t parseS(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    (void)args;
    // Sync
    dprintf("<<< Sync\n");
    // print_packet(data, len);
    parse_begin();
    parse_end();
    pg->sync = 1;
    return len;
}

static size_t parsep(const char *data, size_t len, struct args *args, 
    struct pg *pg)
{
    // PasswordMessage
    parse_begin();
    const char *password = parse_cstr();
    parse_end();
    if (strcmp(password, auth) != 0) {
        parse_seterror(
            "WRONGPASS invalid username-password pair or user is disabled.");
        return -1;
    }
    pg->auth = 1;
    return len;
}

static ssize_t parse_message(const char *data, size_t len, struct args *args,
    struct pg *pg)
{
    if (len < 5) {
        return 0;
    }
    int msgbyte = data[0];
    size_t msglen = read_i32(data+1);
    if (len < msglen+1) {
        return 0;
    }
    msglen -= 4;
    data += 5;
    ssize_t ret;
    switch (msgbyte) {
    case 'Q':
        ret = parseQ(data, msglen, args, pg);
        break;
    case 'P':
        ret = parseP(data, msglen, args, pg);
        break;
    case 'X':
        ret = parseX(data, msglen, args, pg);
        break;
    case 'E':
        ret = parseE(data, msglen, args, pg);
        break;
    case 'p': // lowercase
        ret = parsep(data, msglen, args, pg);
        break;
    case 'D':
        ret = parseD(data, msglen, args, pg);
        break;
    case 'B':
        ret = parseB(data, msglen, args, pg);
        break;
    case 'S':
        ret = parseS(data, msglen, args, pg);
        break;
    default:
        pg->error = 1;
        parse_errorf("unknown message '%c'", msgbyte);
        ret = msglen;
    }
    if (ret == -1 || (size_t)ret != msglen) {
        return -1;
    }
    return msglen+5;
}

static ssize_t parse_magic_ssl(const char *data, size_t len, struct pg *pg) {
    (void)data;
    // SSLRequest
    pg->ssl = 1;
    return len;
}

static ssize_t parse_magic_proto3(const char *data, size_t len, struct pg *pg) {
    // StartupMessage
    const char *p = (void*)data;
    const char *e = p+len;
    // Read parameters
    const char *user = "";
    const char *database = "";
    const char *application_name = "";
    const char *client_encoding = "";
    const char *name = 0;
    const char *s = (char*)p;
    while (p < e) {
        if (*p == '\0') {
            if (s != p) {
                if (name) {
                    if (strcmp(name, "database") == 0) {
                        database = s;
                    } else if (strcmp(name, "application_name") == 0) {
                        application_name = s;
                    } else if (strcmp(name, "client_encoding") == 0) {
                        client_encoding = s;
                    } else if (strcmp(name, "user") == 0) {
                        user = s;
                    }
                    name = 0;
                } else {
                    name = s;
                }
            }
            s = p+1;
        }
        p++;
    }
    // dprintf(". database=%s, application_name=%s, client_encoding=%s, "
    //     "user=%s\n", database, application_name, client_encoding, user);
    if (*client_encoding && strcmp(client_encoding, "UTF8") != 0) {
        printf("# Invalid Postgres client_encoding (%s)\n",
            client_encoding);
        return -1;
    }
    pg->user = xmalloc(strlen(user)+1);
    strcpy((char*)pg->user, user);
    pg->database = xmalloc(strlen(database)+1);
    strcpy((char*)pg->database, database);
    pg->application_name = xmalloc(strlen(application_name)+1);
    strcpy((char*)pg->application_name, application_name);
    pg->startup = 1;
    return p-data;
}

static ssize_t parse_magic_cancel(const char *data, size_t len, struct pg *pg) {
    (void)data; (void)len; (void)pg;
    parse_errorf("cancel message unsupported");
    return -1;
}

static ssize_t parse_magic(const char *data, size_t len, struct pg *pg) {
    (void)data; (void)len; (void)pg;
    if (len < 4) {
        return 0;
    }
    size_t msglen = read_i32(data);
    if (msglen > 65536) {
        parse_errorf("message too large");
        return -1;
    }
    if (len < msglen) {
        return 0;
    }
    if (msglen < 8) {
        parse_errorf("invalid message");
        return -1;
    }
    // dprintf("parse_magic\n");
    uint32_t magic = read_i32(data+4);
    data += 8;
    msglen -= 8;
    ssize_t ret;
    switch (magic) {
    case 0x04D2162F: 
        ret = parse_magic_ssl(data, msglen, pg);
        break;
    case 0x00030000: 
        ret = parse_magic_proto3(data, msglen, pg);
        break;
    case 0xFFFF0000: 
        ret = parse_magic_cancel(data, msglen, pg);
        break;
    default:
        parse_errorf("Protocol error: unknown magic number %08x", magic);
        ret = -1;
    }
    if (ret == -1 || (size_t)ret != msglen) {
        return -1;
    }
    return msglen+8;
}

ssize_t parse_postgres(const char *data, size_t len, struct args *args,
    struct pg **pgptr)
{
    (void)print_packet;
    // print_packet(data, len);
    struct pg *pg = *pgptr;
    if (!pg) {
        pg = pg_new();
        *pgptr = pg;
    }
    pg->error = 0;
    if (len == 0) {
        return 0;
    }
    if (data[0] == 0) {
        return parse_magic(data, len, pg);
    }
    return parse_message(data, len, args, pg);
}

void pg_write_auth(struct conn *conn, unsigned char code) {
    unsigned char bytes[] = { 
        'R', 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, code,
    };
    conn_write_raw(conn, bytes, sizeof(bytes));
}

void pg_write_ready(struct conn *conn, unsigned char code) {
    if (!pg_execute(conn)) {
        unsigned char bytes[] = { 
            'Z', 0x0, 0x0, 0x0, 0x5, code,
        };
        conn_write_raw(conn, bytes, sizeof(bytes));
    }
}

void pg_write_status(struct conn *conn, const char *key, const char *val) {
    size_t keylen = strlen(key);
    size_t vallen = strlen(val);
    int32_t size = 4+keylen+1+vallen+1;
    char *bytes = xmalloc(1+size);
    bytes[0] = 'S';
    write_i32(bytes+1, size);
    memcpy(bytes+1+4,key,keylen+1);
    memcpy(bytes+1+4+keylen+1,val,vallen+1);
    conn_write_raw(conn, bytes, 1+size);
    xfree(bytes);
}

void pg_write_row_desc(struct conn *conn, const char **fields, int nfields){
    size_t size = 1+4+2;
    for (int i = 0; i < nfields; i++) {
        size += strlen(fields[i])+1;
        size += 4+2+4+2+4+2;
    }
    int oid = conn_pg(conn)->oid;
    char *bytes = xmalloc(size);
    bytes[0] = 'T';
    write_i32(bytes+1, size-1); // message_size
    write_i16(bytes+1+4, nfields); // field_count
    char *p = bytes+1+4+2;
    for (int i = 0; i < nfields; i++) {
        size_t fsize = strlen(fields[i]);
        memcpy(p, fields[i], fsize+1);
        p += fsize+1;
        write_i32(p, 0); // table_oid
        p += 4;
        write_i16(p, 0); // column_attr_number
        p += 2;
        write_i32(p, oid); // type_oid
        p += 4;
        write_i16(p, -1); // type_size
        p += 2;
        write_i32(p, -1); // type_modifier
        p += 4;
        write_i16(p, 1); // format_code
        p += 2;
    }
    conn_write_raw(conn, bytes, size);
    xfree(bytes);
}

void pg_write_row_data(struct conn *conn, const char **cols, 
    const size_t *collens, int ncols)
{
    size_t size = 1+4+2;
    for (int i = 0; i < ncols; i++) {
        size += 4+collens[i];
    }
    char *bytes = xmalloc(size);
    bytes[0] = 'D';
    write_i32(bytes+1, size-1); // message_size
    write_i16(bytes+1+4, ncols); // column_count
    char *p = bytes+1+4+2;
    for (int i = 0; i < ncols; i++) {
        write_i32(p, collens[i]); // column_length
        p += 4;
#ifdef PGDEBUG
        printf("  ROW >>>> len:%zu [", collens[i]);
        binprint(cols[i], collens[i]);
        printf("]\n");
#endif
        memcpy(p, cols[i], collens[i]); // column_data
        p += collens[i];
    }
    
    conn_write_raw(conn, bytes, size);
    xfree(bytes);
}

void pg_write_complete(struct conn *conn, const char *tag){
    size_t taglen = strlen(tag);
    size_t size = 1+4+taglen+1;
    char *bytes = xmalloc(size);
    bytes[0] = 'C';
    write_i32(bytes+1, size-1); // message_size
    memcpy(bytes+1+4, tag, taglen+1);
    conn_write_raw(conn, bytes, size);
    xfree(bytes);
}

void pg_write_completef(struct conn *conn, const char *tag_format, ...){
    // initializing list pointer
    char tag[128];
    va_list ap;
    va_start(ap, tag_format);
    vsnprintf(tag, sizeof(tag)-1, tag_format, ap);
    va_end(ap);
    pg_write_complete(conn, tag);
}

void pg_write_simple_row_data_ready(struct conn *conn, const char *desc,
    const void *row, size_t len, const char *tag)
{
    pg_write_row_desc(conn, (const char*[]){ desc }, 1);
    pg_write_row_data(conn, (const char*[]){ row }, (size_t[]){ len }, 1);
    pg_write_complete(conn, tag);
    pg_write_ready(conn, 'I');
}

void pg_write_simple_row_str_ready(struct conn *conn, const char *desc,
    const char *row, const char *tag)
{
    pg_write_simple_row_data_ready(conn, desc, row, strlen(row), tag);
}

void pg_write_simple_row_i64_ready(struct conn *conn, const char *desc,
    int64_t row, const char *tag)
{
    char val[32];
    snprintf(val, sizeof(val), "%" PRIi64, row);
    pg_write_simple_row_str_ready(conn, desc, val, tag);
}

void pg_write_simple_row_str_readyf(struct conn *conn, const char *desc,
    const char *row, const char *tag_format, ...)
{
    char tag[128];
    va_list ap;
    va_start(ap, tag_format);
    vsnprintf(tag, sizeof(tag)-1, tag_format, ap);
    va_end(ap);
    pg_write_simple_row_str_ready(conn, desc, row, tag);
}

void pg_write_simple_row_i64_readyf(struct conn *conn, const char *desc,
    int64_t row, const char *tag_format, ...)
{
    char tag[128];
    va_list ap;
    va_start(ap, tag_format);
    vsnprintf(tag, sizeof(tag)-1, tag_format, ap);
    va_end(ap);
    pg_write_simple_row_i64_ready(conn, desc, row, tag);
}

static void write_auth_ok(struct conn *conn, struct pg *pg) {
    // dprintf(">> AuthOK\n");
    pg_write_auth(conn, 0); // AuthOK;
    // startup message received, respond
    pg_write_status(conn, "client_encoding", "UTF8");
    pg_write_status(conn, "server_encoding", "UTF8");
    char status[128];
    snprintf(status, sizeof(status), "%s (Pogocache)", version);
    pg_write_status(conn, "server_version", status);
    pg_write_ready(conn, 'I'); // Idle;
    pg->ready = 1;
}

// Respond to various the connection states.
// Returns true if the all responses complete or false if there was an
// error.
bool pg_respond(struct conn *conn, struct pg *pg) {
    if (pg->error) {
        conn_write_error(conn, parse_lasterror());
        return true;
    }
    if (pg->empty_query) {
        dprintf("====== pg_respond(pg->empty_query) =====\n");
        conn_write_raw(conn, "I\0\0\0\4", 5);
        conn_write_raw(conn, "Z\0\0\0\5I", 6);
        pg->empty_query = 0;
        return true;
    }
    if (pg->parse) {
        dprintf("====== pg_respond(pg->parse) =====\n");
        conn_write_raw(conn, "1\0\0\0\4", 5);
        pg->parse = 0;
        return true;
    }
    if (pg->bind) {
        dprintf("====== pg_respond(pg->bind) =====\n");
        conn_write_raw(conn, "2\0\0\0\4", 5);
        pg->bind = 0;
        return true;
    }
    if (pg->describe) {
        dprintf("====== pg_respond(pg->describe) =====\n");
        assert(pg->desc);
        conn_write_raw(conn, pg->desc, pg->desclen);
        xfree(pg->desc);
        pg->desc = 0;
        pg->desclen = 0;
        pg->describe = 0;
        return true;
    }
    if (pg->sync) {
        dprintf("====== pg_respond(pg->sync) =====\n");
        pg->execute = 0;
        pg_write_ready(conn, 'I');
        pg->sync = 0;
        return true;
    }
    if (pg->close) {
        dprintf("====== pg_respond(pg->close) =====\n");
        pg->close = 0;
        return false;
    }
    if (pg->ssl == 1) {
        if (!conn_istls(conn)) {
            conn_write_raw_cstr(conn, "N");
        } else {
            conn_write_raw_cstr(conn, "Y");
        }
        pg->ssl = 0;
        return true;
    }
    if (pg->auth == 1) {
        if (pg->startup == 0) {
            return false;
        }
        conn_setauth(conn, true);
        write_auth_ok(conn, pg);
        pg->auth = 0;
        return true;
    }
    if (pg->startup == 1) {
        if (auth && *auth) {
            pg_write_auth(conn, 3); // AuthenticationCleartextPassword;
        } else {
            write_auth_ok(conn, pg);
            pg->startup = 0;
        }
        return true;
    }
    return true;
}

void pg_write_error(struct conn *conn, const char *msg) {
    size_t msglen = strlen(msg);
    size_t size = 1+4;
    size += 1+5+1;      // 'S' "ERROR" \0
    size += 1+5+1;      // 'V' "ERROR" \0
    size += 1+5+1;      // 'C' "23505" \0
    size += 1+msglen+1; // 'M' msg \0
    size += 1;          // null-terminator
    char *bytes = xmalloc(size);
    bytes[0] = 'E';
    write_i32(bytes+1, size-1);
    char *p = bytes+1+4;
    memcpy(p, "SERROR", 7);
    p += 7;
    memcpy(p, "VERROR", 7);
    p += 7;
    memcpy(p, "C23505", 7);
    p += 7;
    p[0] = 'M';
    p++;
    memcpy(p, msg, msglen+1);
    p += msglen+1;
    p[0] = '\0';
    conn_write_raw(conn, bytes, size);
    xfree(bytes);
}

// return true if the command need further execution, of false if this
// operation handled it already
bool pg_precommand(struct conn *conn, struct args *args, struct pg *pg) {
#ifdef PGDEBUG
    printf("precommand: ");
    args_print(args);
#endif
    if (args->len > 0 && args->bufs[0].len > 0) {
        char c = tolower(args->bufs[0].data[0]);
        if (c == 'b' || c == 'r' || c == 'c') {
            // silently ignore transaction commands.
            if (c == 'b' && argeq(args, 0, "begin")) {
                pg_write_completef(conn, "BEGIN");
                pg_write_ready(conn, 'I');
                return false;
            }
            if (argeq(args, 0, "rollback")) {
                pg_write_completef(conn, "ROLLBACK");
                pg_write_ready(conn, 'I');
                return false;
            }
            if (argeq(args, 0, "commit")) {
                pg_write_completef(conn, "COMMIT");
                pg_write_ready(conn, 'I');
                return false;
            }
        }
        if (c == ':' && args->bufs[0].len > 1 && args->bufs[0].data[1] == ':') {
            if (argeq(args, 0, "::bytea") || argeq(args, 0, "::bytes")) {
                pg->oid = BYTEAOID;
            } else if (argeq(args, 0, "::text")) {
                pg->oid = TEXTOID;
            } else {
                char err[128];
                snprintf(err, sizeof(err), "unknown type '%.*s'", 
                    (int)(args->bufs[0].len-2), args->bufs[0].data+2);
                pg_write_error(conn, err);
                pg_write_ready(conn, 'I');
                return false;
            }
            args_remove_first(args);
            if (args->len == 0) {
                if (pg->oid == BYTEAOID) {
                    pg_write_completef(conn, "BYTEA");
                } else {
                    pg_write_completef(conn, "TEXT");
                }
                pg_write_ready(conn, 'I');
                return false;
            }
        }
    }
    return true;
}
