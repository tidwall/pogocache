// https://github.com/tidwall/pogocache
//
// Copyright 2025 Polypoint Labs, LLC. All rights reserved.
// This file is part of the Pogocache project.
// Use of this source code is governed by the AGPL that can be found in
// the LICENSE file.
//
// For alternative licensing options or general questions, please contact
// us at licensing@polypointlabs.com.
//
// Unit pogocache.c is the primary caching engine library, which is designed
// to be standalone and embeddable.
#include <stdbool.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "pogocache.h"

#define MINLOADFACTOR_RH 55     // 55%
#define MAXLOADFACTOR_RH 95     // 95%
#define DEFLOADFACTOR    75     // 75%
#define SHRINKAT         10     // 10%
#define DEFSHARDS        4096   // default number of shards
#define INITCAP          64     // intial number of buckets per shard

// #define DBGCHECKENTRY
// #define EVICTONITER
// #define HALFSECONDTIME
// #define NO48BITPTRS

#if INTPTR_MAX == INT64_MAX
#ifdef NO48BITPTRS
#define PTRSIZE 8
#else
#define PTRSIZE 6
#endif
#elif INTPTR_MAX == INT32_MAX
#define PTRSIZE 4
#else
#error Unknown pointer size
#endif

static struct pogocache_count_opts defcountopts = { 0 };
static struct pogocache_total_opts deftotalopts = { 0 };
static struct pogocache_size_opts defsizeopts = { 0 };
static struct pogocache_sweep_opts defsweepopts = { 0 };
static struct pogocache_clear_opts defclearopts = { 0 };
static struct pogocache_store_opts defstoreopts = { 0 };
static struct pogocache_load_opts defloadopts = { 0 };
static struct pogocache_delete_opts defdeleteopts = { 0 };
static struct pogocache_iter_opts defiteropts = { 0 };
static struct pogocache_sweep_poll_opts defsweeppollopts = { 0 };

static int64_t nanotime(struct timespec *ts) {
    int64_t x = ts->tv_sec;
    x *= 1000000000;
    x += ts->tv_nsec;
    return x;
}

// returns monotonic nanoseconds of the CPU clock.
static int64_t gettime(void) {
    struct timespec now = { 0 };
#ifdef __linux__
    clock_gettime(CLOCK_BOOTTIME, &now);
#elif defined(__APPLE__)
    clock_gettime(CLOCK_UPTIME_RAW, &now);
#else
    clock_gettime(CLOCK_MONOTONIC, &now);
#endif
    return nanotime(&now);
}

// returns offset of system clock since first call in thread.
static int64_t getnow(void) {
    return gettime();
}

// https://github.com/tidwall/th64
static uint64_t th64(const void *data, size_t len, uint64_t seed) {
    uint8_t*p=(uint8_t*)data,*e=p+len;
    uint64_t r=0x14020a57acced8b7,x,h=seed;
    while(p+8<=e)memcpy(&x,p,8),x*=r,p+=8,x=x<<31|x>>33,h=h*r^x,h=h<<31|h>>33;
    while(p<e)h=h*r^*(p++);
    return(h=h*r+len,h^=h>>31,h*=r,h^=h>>31,h*=r,h^=h>>31,h*=r,h);
}

// Load a pointer from an unaligned memory.
static void *load_ptr(const uint8_t data[PTRSIZE]) {
#if PTRSIZE == 4
    uint32_t uptr;
    memcpy(&uptr, data, 4);
    return (void*)(uintptr_t)uptr;
#elif PTRSIZE == 6
    uint64_t uptr = 0;
    uptr |= ((uint64_t)data[0])<<0;
    uptr |= ((uint64_t)data[1])<<8;
    uptr |= ((uint64_t)data[2])<<16;
    uptr |= ((uint64_t)data[3])<<24;
    uptr |= ((uint64_t)data[4])<<32;
    uptr |= ((uint64_t)data[5])<<40;
    return (void*)(uintptr_t)uptr;
#elif PTRSIZE == 8
    uint64_t uptr;
    memcpy(&uptr, data, 8);
    return (void*)(uintptr_t)uptr;
#endif
}

// Store a pointer into unaligned memory.
static void store_ptr(uint8_t data[PTRSIZE], void *ptr) {
#if PTRSIZE == 4
    uint32_t uptr = (uintptr_t)(void*)ptr;
    memcpy(data, &uptr, 4);
#elif PTRSIZE == 6
    uint64_t uptr = (uintptr_t)(void*)ptr;
    data[0] = (uptr>>0)&0xFF;
    data[1] = (uptr>>8)&0xFF;
    data[2] = (uptr>>16)&0xFF;
    data[3] = (uptr>>24)&0xFF;
    data[4] = (uptr>>32)&0xFF;
    data[5] = (uptr>>40)&0xFF;
#elif PTRSIZE == 8
    uint64_t uptr = (uintptr_t)(void*)ptr;
    memcpy(data, &uptr, 8);
#endif
}

// https://zimbry.blogspot.com/2011/09/better-bit-mixing-improving-on.html
static uint64_t mix13(uint64_t key) {
    key ^= (key >> 30);
    key *= UINT64_C(0xbf58476d1ce4e5b9);
    key ^= (key >> 27);
    key *= UINT64_C(0x94d049bb133111eb);
    key ^= (key >> 31);
    return key;
}

// Sixpack compression algorithm
// - Converts a simple 8-bit string into 6-bit string.
// - Intended to be used on small strings that only use characters commonly
//   used for keys in KV data stores.
// - Allows the following 64 item character set:
//    -.0123456789:ABCDEFGHIJKLMNOPRSTUVWXY_abcdefghijklmnopqrstuvwxy
//   Note that the characters "QZz" are not included.
// - Sortable and comparable using memcmp.
static char tosix[256] = {
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 0-15
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  // 16-31
     0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  0,  // 32-47
     3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13,  0,  0,  0,  0,  0,  // 48-63
     0, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,  // 64-79
    29,  0, 30, 31, 32, 33, 34, 35, 36, 37,  0,  0,  0,  0,  0, 38,  // 80-95
     0, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,  // 96-111
    54, 55, 56, 57, 58, 59, 60, 61, 62, 63,  0,  0,  0,  0,  0,  0,  // 112-127
};

static char fromsix[] = {
      0, '-', '.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':',
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', '_', 'a', 'b', 'c',
    'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
    'r', 's', 't', 'u', 'v', 'w', 'x', 'y'
};

// 0: [000000..]                      bitpos: 0
// 1: [00000011][1111....]            bitpos: 6
// 2: [00000011][11112222][22......]  bitpos: 12 
// 3: [00000011][11112222][22333333]  bitpos: 18

// Sixpack data
// Fills the data in dst and returns the number of bytes filled.
// Returns 0 if not a sixpackable.
// The dst array must be large enough to hold packed value
static int sixpack(const char *data, int len, char dst[]){
    const unsigned char *bytes = (unsigned char*)data;
    int j = 0;
    for (int i = 0; i < len; i++) {
        int k6v = tosix[bytes[i]];
        if (k6v == 0) {
            return 0;
        }
        if (i%4 == 0) {
            dst[j++] = k6v<<2;
        } else if (i%4 == 1) {
            dst[j-1] |= k6v>>4;
            dst[j++] = k6v<<4;
        } else if (i%4 == 2) {
            dst[j-1] |= k6v>>2;
            dst[j++] = k6v<<6;
        } else {
            dst[j-1] |= k6v;
        }
    }
    return j;
}

// (Un)sixpack data.
// Fills the data in dst and returns the len of original data.
// The data must be sixpacked and len must be > 0.
// The dst array must be large enough to hold unpacked value
static int unsixpack(const char *data, int len, char dst[]) {
    const unsigned char *bytes = (unsigned char*)data;
    int j = 0;
    int k = 0;
    for (int i = 0; i < len; i++) {
        if (k == 0) {
            dst[j++] = fromsix[bytes[i]>>2];
            k++;
        } else if (k == 1) {
            dst[j++] = fromsix[((bytes[i-1]<<4)|(bytes[i]>>4))&63];
            k++;
        } else {
            dst[j++] = fromsix[((bytes[i-1]<<2)|(bytes[i]>>6))&63];
            dst[j++] = fromsix[bytes[i]&63];
            k = 0;
        }
    }
    if (j > 0 && dst[j-1] == 0) {
        j--;
    }
    return j;
}

// Safely adds two int64_t values, clamping on overflow.
static int64_t int64_add_clamp(int64_t a, int64_t b) {
    if (!((a ^ b) < 0)) { // Opposite signs can't overflow
        if (a > 0) {
            if (b > INT64_MAX - a) {
                return INT64_MAX;
            }
        } else if (b < INT64_MIN - a) {
            return INT64_MIN;
        }
    }
    return a + b;
}

/// https://github.com/tidwall/varint.c
static int varint_write_u64(void *data, uint64_t x) {
    uint8_t *bytes = data;
    if (x < 128) {
        *bytes = x;
        return 1;
    }
    int n = 0;
    do {
        bytes[n++] = (uint8_t)x | 128;
        x >>= 7;
    } while (x >= 128);
    bytes[n++] = (uint8_t)x;
    return n;
}

static int varint_read_u64(const void *data, size_t len, uint64_t *x) {
    const uint8_t *bytes = data;
    if (len > 0 && bytes[0] < 128) {
        *x = bytes[0];
        return 1;
    }
    uint64_t b;
    *x = 0;
    size_t i = 0;
    while (i < len && i < 10) {
        b = bytes[i]; 
        *x |= (b & 127) << (7 * i); 
        if (b < 128) {
            return i + 1;
        }
        i++;
    }
    return i == 10 ? -1 : 0;
}

#ifdef HALFSECONDTIME
typedef uint32_t etime_t;
#else
typedef int64_t etime_t;
#endif


// Mostly a copy of the pogocache_opts, but used internally
// See the opts_to_ctx function for translation.
struct pgctx {
    void *(*malloc)(size_t);
    void (*free)(void*);
    size_t (*malloc_size)(void*);
    void (*yield)(void *udata);
    void (*evicted)(int shard, int reason, int64_t time, const void *key,
        size_t keylen, const void *val, size_t vallen, int64_t expires,
        uint32_t flags, uint64_t cas, void *udata);
    void *udata;
    bool usecas;
    bool nosixpack;
    bool noevict;
    bool allowshrink;
    bool usethreadbatch;
    int nshards;
    double loadfactor;
    double shrinkfactor;
    uint64_t seed;
};

// The entry structure is a simple allocation with all the fields, being 
// variable in size, slammed together contiguously. There's a one byte header
// that provides information about what is available in the structure.
// The format is: (header,time,expires?,flags?,cas?,key,value)
// The expires, flags, and cas fields are optional. The optionality depends on
// header bit flags.
struct entry;

// Returns the sizeof the entry struct, which takes up no space at all.
// This would be like doing a sizeof(struct entry), if entry had a structure.
static size_t entry_struct_size(void) {
    return 0;
}

// Returns the data portion of the entry, which is the entire allocation.
static const uint8_t *entry_data(const struct entry *entry) {
    return (uint8_t*)entry;
}

static int64_t entry_expires(const struct entry *entry) {
    const uint8_t *p = entry_data(entry);
    uint8_t hdr = *(p++); // hdr
    p += sizeof(etime_t); // time
    int64_t x = 0;
    if ((hdr>>0)&1) {
        memcpy(&x, p, 8);
    }
    return x;
}

static int64_t entry_time(struct entry *entry) {
    const uint8_t *p = entry_data(entry);
    etime_t etime;
    memcpy(&etime, p+1, sizeof(etime_t));
#ifdef HALFSECONDTIME
    int64_t time = (int64_t)etime * INT64_C(500000000);
#else 
    int64_t time = etime;
#endif    
    return time;
}

static void entry_settime(struct entry *entry, int64_t time) {
    const uint8_t *p = entry_data(entry);
#ifdef HALFSECONDTIME
    // Eviction time is stored as half seconds.
    etime_t etime = time / INT64_C(500000000);
    etime = etime > UINT32_MAX ? UINT32_MAX : etime;
#else
    etime_t etime = time;
#endif
    memcpy((uint8_t*)(p+1), &etime, sizeof(etime_t));
}

static int entry_alive_exp(int64_t expires, int64_t etime, int64_t now,
    int64_t cleartime)
{
    return etime < cleartime ? POGOCACHE_REASON_CLEARED :
           expires > 0 && expires <= now ? POGOCACHE_REASON_EXPIRED :
           0;
}

static int entry_alive(struct entry *entry, int64_t now, int64_t cleartime) {
    int64_t etime = entry_time(entry);
    int64_t expires = entry_expires(entry);
    return entry_alive_exp(expires, etime, now, cleartime);
}

static uint64_t entry_cas(const struct entry *entry) {
    const uint8_t *p = entry_data(entry);
    uint8_t hdr = *(p++); // hdr
    p += sizeof(etime_t); // time
    if ((hdr>>0)&1) {
        p += 8; // expires
    }
    if ((hdr>>1)&1) {
        p += 4; // flags
    }
    uint64_t x = 0;
    if ((hdr>>2)&1) {
        memcpy(&x, p, 8);
    }
    return x;
}

// returns the key. If using sixpack make sure to copy the result asap.
static const char *entry_key(const struct entry *entry, size_t *keylen_out,
    char buf[128])
{
    const uint8_t *p = entry_data(entry);
    const uint8_t hdr = *(p++); // hdr
    p += sizeof(etime_t); // time
    if ((hdr>>0)&1) {
        p += 8; // expires
    }
    if ((hdr>>1)&1) {
        p += 4; // flags
    }
    if ((hdr>>2)&1) {
        p += 8; // cas
    }
    uint64_t x;
    p += varint_read_u64(p, 10, &x); // keylen
    size_t keylen = x;
    char *key = (char*)p;
    if ((hdr>>3)&1) {
        keylen = unsixpack(key, (int)keylen, buf);
        key = buf;
    }
    *keylen_out = keylen;
    return key;
}

// returns the raw key. sixpack will be returned in it's raw format
static const char *entry_rawkey(const struct entry *entry, size_t *keylen_out) {
    const uint8_t *p = entry_data(entry);
    const uint8_t hdr = *(p++); // hdr
    p += sizeof(etime_t); // time
    if ((hdr>>0)&1) {
        p += 8; // expires
    }
    if ((hdr>>1)&1) {
        p += 4; // flags
    }
    if ((hdr>>2)&1) {
        p += 8; // cas
    }
    uint64_t x;
    p += varint_read_u64(p, 10, &x); // keylen
    size_t keylen = x;
    char *key = (char*)p;
    *keylen_out = keylen;
    return key;
}

static bool entry_sixpacked(const struct entry *entry) {
    const uint8_t *p = entry_data(entry);
    uint8_t hdr = *(p);
    return (hdr>>3)&1;
}

static size_t entry_extract(const struct entry *entry, const char **key,
    size_t *keylen, char buf[128], const char **val, size_t *vallen, 
    int64_t *expires, uint32_t *flags, uint64_t *cas,
    struct pgctx *ctx)
{
    const uint8_t *p = entry_data(entry);
    uint8_t hdr = *(p++); // hdr
    p += sizeof(etime_t); // time
    if ((hdr>>0)&1) {
        if (expires) {
            memcpy(expires, p, 8);
        }
        p += 8; // expires
    } else {
        if (expires) {
            *expires = 0;
        }
    }
    if ((hdr>>1)&1) {
        if (flags) {
            memcpy(flags, p, 4);
        }
        p += 4; // flags
    } else {
        if (flags) {
            *flags = 0;
        }
    }
    if (ctx->usecas) {
        if (cas) {
            memcpy(cas, p, 8);
        }
        p += 8; // cas
    } else {
        if (cas) {
            *cas = 0;
        }
    }
    uint64_t x;
    p += varint_read_u64(p, 10, &x); // keylen
    if (key) {
        *key = (char*)p;
        *keylen = x;
        if ((hdr>>3)&1) {
            *keylen = unsixpack(*key, (int)*keylen, buf);
            *key = buf;
        }
    }
    p += x;                          // key
    p += varint_read_u64(p, 10, &x); // vallen
    if (val) {
        *val = (char*)p;
        *vallen = x;
    }
    p += x;                          // val
    return entry_struct_size()+(p-(uint8_t*)entry);
}

static size_t entry_memsize(const struct entry *entry,
    struct pgctx *ctx)
{
    const uint8_t *p = entry_data(entry);
    uint8_t hdr = *(p++); // hdr
    p += sizeof(etime_t); // time
    if ((hdr>>0)&1) {
        p += 8; // expires
    }
    if ((hdr>>1)&1) {
        p += 4; // flags
    }
    if (ctx->usecas) {
        p += 8; // cas
    }
    uint64_t x;
    p += varint_read_u64(p, 10, &x); // keylen
    p += x;                          // key
    p += varint_read_u64(p, 10, &x); // vallen
    p += x;                          // val
    return entry_struct_size()+(p-(uint8_t*)entry);
}

// The 'cas' param should always be set to zero unless loading from disk. 
// Setting to zero will set a new unique cas to the entry.
static struct entry *entry_new(const char *key, size_t keylen, const char *val,
    size_t vallen, int64_t expires, uint32_t flags, uint64_t cas,
    struct pgctx *ctx)
{
    bool usesixpack = !ctx->nosixpack;
#ifdef DBGCHECKENTRY
    // printf("entry_new(key=[%.*s], keylen=%zu, val=[%.*s], vallen=%zu, "
    //     "expires=%" PRId64 ", flags=%" PRId32 ", cas=%" PRIu64 ", "
    //     "usesixpack=%d\n", (int)keylen, key, keylen, (int)vallen, key, vallen,
    //     expires, flags, cas, usesixpack);
    int64_t oexpires = expires;
    uint32_t oflags = flags;
    uint64_t ocas = cas;
    const char *okey = key;
    size_t okeylen = keylen;
    const char *oval = val;
    size_t ovallen = vallen;
#endif
    uint8_t hdr = 0;
    uint8_t keylenbuf[10];
    uint8_t vallenbuf[10];
    int nexplen, nflagslen, ncaslen, nkeylen, nvallen;
    if (expires > 0) {
        hdr |= 1;
        nexplen = 8;
    } else {
        nexplen = 0;
    }
    if (flags > 0) {
        hdr |= 2;
        nflagslen = 4;
    } else {
        nflagslen = 0;
    }
    if (ctx->usecas) {
        hdr |= 4;
        ncaslen = 8;
    } else {
        ncaslen = 0;
    }
    char buf[128];
    if (usesixpack && keylen <= 128) {
        size_t len = sixpack(key, keylen, buf);
        if (len > 0) {
            hdr |= 8;
            keylen = len;
            key = buf;
        }
    }
    nkeylen = varint_write_u64(keylenbuf, keylen);
    nvallen = varint_write_u64(vallenbuf, vallen);
    struct entry *entry_out = 0;
    size_t size = entry_struct_size()+1+sizeof(etime_t)+nexplen+nflagslen+
        ncaslen+nkeylen+keylen+nvallen+vallen;
    // printf("malloc=%p size=%zu, ctx=%p\n", ctx->malloc, size, ctx);
    void *mem = ctx->malloc(size);
    struct entry *entry = mem;
    if (!entry) {
        return 0;
    }
    uint8_t *p = (void*)entry_data(entry);
    *(p++) = hdr;
    memset(p, 0, sizeof(etime_t));
    p += sizeof(etime_t); // time
    if (nexplen > 0) {
        memcpy(p, &expires, nexplen);
        p += nexplen;
    }
    if (nflagslen > 0) {
        memcpy(p, &flags, nflagslen);
        p += nflagslen;
    }
    if (ncaslen > 0) {
        memcpy(p, &cas, ncaslen);
        p += ncaslen;
    }
    memcpy(p, keylenbuf, nkeylen);
    p += nkeylen;
    memcpy(p, key, keylen);
    p += keylen;
    memcpy(p, vallenbuf, nvallen);
    p += nvallen;
    memcpy(p, val, vallen);
    p += vallen;
    entry_out = entry;
#ifdef DBGCHECKENTRY
    // check the key
    const char *key2, *val2;
    size_t keylen2, vallen2;
    int64_t expires2;
    uint32_t flags2;
    uint64_t cas2;
    char buf1[256];
    entry_extract(entry_out, &key2, &keylen2, buf1, &val2, &vallen2, &expires2,
        &flags2, &cas2, ctx);
    assert(expires2 == oexpires);
    assert(flags2 == oflags);
    assert(cas2 == ocas);
    assert(keylen2 == okeylen);
    assert(memcmp(key2, okey, okeylen) == 0);
    assert(vallen2 == ovallen);
    assert(memcmp(val2, oval, ovallen) == 0);
#endif
    return entry_out;
}

static void entry_free(struct entry *entry, struct pgctx *ctx) {
    ctx->free(entry);
}

static int entry_compare(const struct entry *a, const struct entry *b) {
    size_t akeylen, bkeylen;
    char buf1[256], buf2[256];
    const char *akey;
    const char *bkey;
    if (entry_sixpacked(a) == entry_sixpacked(b)) {
        akey = entry_rawkey(a, &akeylen);
        bkey = entry_rawkey(b, &bkeylen);
    } else {
        akey = entry_key(a, &akeylen, buf1);
        bkey = entry_key(b, &bkeylen, buf2);
    }
    size_t size = akeylen < bkeylen ? akeylen : bkeylen;
    int cmp = memcmp(akey, bkey, size);
    if (cmp == 0) {
        cmp = akeylen < bkeylen ? -1 : akeylen > bkeylen;
    }
    return cmp;
}

#ifndef HASHSIZE
#define HASHSIZE 3
#endif
#if HASHSIZE < 1 || HASHSIZE > 4
#error bad hash size
#endif

struct bucket {
    uint8_t entry[PTRSIZE]; // 48-bit pointer
    uint8_t hash[HASHSIZE]; // 24-bit hash
    uint8_t dib;            // distance to bucket
};

static_assert(sizeof(struct bucket) == PTRSIZE+HASHSIZE+1, "bad bucket size");

struct map {
    int cap;         // initial capacity
    int nbuckets;    // number of buckets
    int count;       // current entry count
    int mask;        // bit mask for 
    int growat;
    int shrinkat;
    struct bucket *buckets;
    uint64_t total;  // current entry count
    size_t entsize;  // memory size of all entries
    
};

struct shard {
    atomic_uintptr_t lock; // spinlock (batch pointer)
    uint64_t cas;          // compare and store value
    int64_t cleartime;     // last clear time
    int clearcount;        // number of items cleared
    struct map map;        // robinhood hashmap
    // for batch linked list only
    struct shard *next;
};

static void lock_init(struct shard *shard) {
    atomic_init(&shard->lock, 0);
}

struct batch {
    struct pogocache *cache; // associated cache.
    struct shard *shard;     // first locked shard
    int64_t time;            // timestamp
};

struct pogocache {
    bool isbatch; 
    union {
        struct pgctx ctx;
        struct batch batch;
    };
    struct shard shards[];
};

static struct entry *get_entry(struct bucket *bucket) {
    return load_ptr(bucket->entry);
}

static void set_entry(struct bucket *bucket, struct entry *entry) {
    store_ptr(bucket->entry, entry);
}

#if HASHSIZE == 1
static uint32_t clip_hash(uint32_t hash) {
    return hash&0xFF;
}
static void write_hash(uint8_t data[1], uint32_t hash) {
    data[0] = (hash>>0)&0xFF;
}

static uint32_t read_hash(uint8_t data[1]) {
    uint32_t hash = 0;
    hash |= ((uint64_t)data[0])<<0;
    return hash;
}
#elif HASHSIZE == 2
static uint32_t clip_hash(uint32_t hash) {
    return hash&0xFFFF;
}
static void write_hash(uint8_t data[2], uint32_t hash) {
    data[0] = (hash>>0)&0xFF;
    data[1] = (hash>>8)&0xFF;
}

static uint32_t read_hash(uint8_t data[2]) {
    uint32_t hash = 0;
    hash |= ((uint64_t)data[0])<<0;
    hash |= ((uint64_t)data[1])<<8;
    return hash;
}
#elif HASHSIZE == 3
static uint32_t clip_hash(uint32_t hash) {
    return hash&0xFFFFFF;
}
static void write_hash(uint8_t data[3], uint32_t hash) {
    data[0] = (hash>>0)&0xFF;
    data[1] = (hash>>8)&0xFF;
    data[2] = (hash>>16)&0xFF;
}

static uint32_t read_hash(uint8_t data[3]) {
    uint32_t hash = 0;
    hash |= ((uint64_t)data[0])<<0;
    hash |= ((uint64_t)data[1])<<8;
    hash |= ((uint64_t)data[2])<<16;
    return hash;
}
#else 
static uint32_t clip_hash(uint32_t hash) {
    return hash;
}
static void write_hash(uint8_t data[4], uint32_t hash) {
    data[0] = (hash>>0)&0xFF;
    data[1] = (hash>>8)&0xFF;
    data[2] = (hash>>16)&0xFF;
    data[3] = (hash>>24)&0xFF;
}

static uint32_t read_hash(uint8_t data[4]) {
    uint32_t hash = 0;
    hash |= ((uint64_t)data[0])<<0;
    hash |= ((uint64_t)data[1])<<8;
    hash |= ((uint64_t)data[2])<<16;
    hash |= ((uint64_t)data[3])<<24;
    return hash;
}
#endif

static uint32_t get_hash(struct bucket *bucket) {
    return read_hash(bucket->hash);
}

static void set_hash(struct bucket *bucket, uint32_t hash) {
    write_hash(bucket->hash, hash);
}

static uint8_t get_dib(struct bucket *bucket) {
    return bucket->dib;
}

static void set_dib(struct bucket *bucket, uint8_t dib) {
    bucket->dib = dib;
}

static bool map_init(struct map *map, size_t cap, struct pgctx *ctx) {
    map->cap = cap;
    map->nbuckets = cap;
    map->count = 0;
    map->mask = map->nbuckets-1;
    map->growat = map->nbuckets * ctx->loadfactor;
    map->shrinkat = map->nbuckets * ctx->shrinkfactor;
    size_t size = sizeof(struct bucket)*map->nbuckets;
    map->buckets = ctx->malloc(size);
    if (!map->buckets) {
        // nomem
        memset(map, 0, sizeof(struct map));
        return false;
    }
    memset(map->buckets, 0, size);
    return true;
}

static bool resize(struct map *map, size_t new_cap, struct pgctx *ctx) {
    struct map map2;
    if (!map_init(&map2, new_cap, ctx)) {
        return false;
    }
    for (int i = 0; i < map->nbuckets; i++) {
        struct bucket ebkt = map->buckets[i];
        if (get_dib(&ebkt)) {
            set_dib(&ebkt, 1);
            size_t j = get_hash(&ebkt) & map2.mask;
            while (1) {
                if (get_dib(&map2.buckets[j]) == 0) {
                    map2.buckets[j] = ebkt;
                    break;
                }
                if (get_dib(&map2.buckets[j]) < get_dib(&ebkt)) {
                    struct bucket tmp = map2.buckets[j];
                    map2.buckets[j] = ebkt;
                    ebkt = tmp;
                }
                j = (j + 1) & map2.mask;
                set_dib(&ebkt, get_dib(&ebkt)+1);
            }
        }
    }
    int org_cap = map->cap;
    int org_count = map->count;
    ctx->free(map->buckets);
    memcpy(map, &map2, sizeof(struct map));
    map->cap = org_cap;
    map->count = org_count;
    return true;
}

static bool map_insert(struct map *map, struct entry *entry, uint32_t hash,
    struct entry **old, struct pgctx *ctx)
{
    hash = clip_hash(hash);
    if (map->count >= map->growat) {
        if (!resize(map, map->nbuckets*2, ctx)) {
            *old = 0;
            return false;
        }
    }
    map->entsize += entry_memsize(entry, ctx);
    struct bucket ebkt;
    set_entry(&ebkt, entry);
    set_hash(&ebkt, hash);
    set_dib(&ebkt, 1);
    size_t i = hash & map->mask;
    while (1) {
        if (get_dib(&map->buckets[i]) == 0) {
            // new entry
            map->buckets[i] = ebkt;
            map->count++;
            map->total++;
            *old = 0;
            return true;
        }
        if (get_hash(&ebkt) == get_hash(&map->buckets[i]) && 
            entry_compare(get_entry(&ebkt), get_entry(&map->buckets[i])) == 0)
        {
            // replaced
            *old = get_entry(&map->buckets[i]);
            map->entsize -= entry_memsize(*old, ctx);
            set_entry(&map->buckets[i], get_entry(&ebkt));
            return true;
        }
        if (get_dib(&map->buckets[i]) < get_dib(&ebkt)) {
            struct bucket tmp = map->buckets[i];
            map->buckets[i] = ebkt;
            ebkt = tmp;
        }
        i = (i + 1) & map->mask;
        set_dib(&ebkt, get_dib(&ebkt)+1);
    }
}

static bool bucket_eq(struct map *map, size_t i, const char *key,
    size_t keylen, uint32_t hash)
{
    if (get_hash(&map->buckets[i]) != hash) {
        return false;
    }
    size_t keylen2;
    char buf[128];
    const char *key2 = entry_key(get_entry(&map->buckets[i]), &keylen2, buf);
    return keylen == keylen2 && memcmp(key, key2, keylen) == 0;
}

// Returns the bucket index for key, or -1 if not found.
static int map_get_bucket(struct map *map, const char *key, size_t keylen,
    uint32_t hash)
{
    hash = clip_hash(hash);
    size_t i = hash & map->mask;
    while (1) {
        struct bucket *bkt = &map->buckets[i];
        if (get_dib(bkt) == 0) {
            return -1;
        }
        if (bucket_eq(map, i, key, keylen, hash)) {
            return i;
        }
        i = (i + 1) & map->mask;
    }
}

static struct entry *map_get_entry(struct map *map, const char *key,
    size_t keylen, uint32_t hash, int *bkt_idx_out)
{
    int i = map_get_bucket(map, key, keylen, hash);
    *bkt_idx_out = i;
    return i >= 0 ? get_entry(&map->buckets[i]) : 0;
}

// This deletes entry from bucket and adjusts the dibs buckets to right, if
// needed.
static void delbkt(struct map *map, size_t i) {
    set_dib(&map->buckets[i], 0);
    while (1) {
        size_t h = i;
        i = (i + 1) & map->mask;
        if (get_dib(&map->buckets[i]) <= 1) {
            set_dib(&map->buckets[h], 0);
            break;
        }
        map->buckets[h] = map->buckets[i];
        set_dib(&map->buckets[h], get_dib(&map->buckets[h])-1);
    }
    map->count--;
}

static bool needsshrink(struct map *map, struct pgctx *ctx) {
    return ctx->allowshrink && map->nbuckets > map->cap && 
        map->count <= map->shrinkat;
}

// Try to shrink the hashmap. If needed, this will allocate a new hashmap that
// has fewer buckets and move all existing entries into the smaller map.
// The 'multi' param is a hint that multi entries may have been deleted, such
// as with the iter or clear operations.
// If the resize fails due to an allocation error then the existing hashmap
// will be retained.
static void tryshrink(struct map *map, bool multi, struct pgctx *ctx) {
    if (!needsshrink(map, ctx)) {
        return;
    }
    int cap;
    if (multi) {
        // Determine how many buckets are needed to store all entries.
        cap = map->cap;
        int growat = cap * ctx->loadfactor;
        while (map->count >= growat) {
            cap *= 2;
            growat = cap * ctx->loadfactor;
        }
    } else {
        // Just half the buckets
        cap = map->nbuckets / 2;
    }
    resize(map, cap, ctx);
}

// delete an entry at bucket position. not called directly
static struct entry *delentry_at_bkt(struct map *map, size_t i, 
    struct pgctx *ctx)
{
    struct entry *old = get_entry(&map->buckets[i]);
    assert(old);
    map->entsize -= entry_memsize(old, ctx);
    delbkt(map, i);
    return old;
}

static struct entry *map_delete(struct map *map, const char *key,
    size_t keylen, uint32_t hash, struct pgctx *ctx)
{
    hash = clip_hash(hash);
    int i = hash & map->mask;
    while (1) {
        if (get_dib(&map->buckets[i]) == 0) {
            return 0;
        }
        if (bucket_eq(map, i, key, keylen, hash)) {
            return delentry_at_bkt(map, i, ctx);
        }
        i = (i + 1) & map->mask;
    }
}

static size_t evict_entry(struct shard *shard, int shardidx, 
    struct entry *entry, int64_t now, int reason, struct pgctx *ctx)
{
    char buf[128];
    size_t keylen;
    const char *key = entry_key(entry, &keylen, buf);
    uint32_t hash = th64(key, keylen, ctx->seed);
    struct entry *del = map_delete(&shard->map, key, keylen, hash, ctx);
    assert(del == entry); (void)del;
    if (ctx->evicted) {
        // Notify user that an entry was evicted.
        const char *val;
        size_t vallen;
        int64_t expires = 0;
        uint32_t flags = 0;
        uint64_t cas = 0;
        entry_extract(entry, 0, 0, 0, &val, &vallen, &expires, &flags, &cas,
            ctx);
        ctx->evicted(shardidx, reason, now, key, keylen, val,
            vallen, expires, flags, cas, ctx->udata);
    }
    shard->clearcount -= (reason==POGOCACHE_REASON_CLEARED);
    size_t size = entry_memsize(entry, ctx);
    entry_free(entry, ctx);
    return size;
}

// evict an entry using the 2-random algorithm.
// Pick two random entries and delete the one with the oldest access time.
// Do not evict the entry if it matches the provided hash.
static void auto_evict_entry(struct shard *shard, int shardidx, uint32_t hash,
    int64_t now, struct pgctx *ctx)
{
    hash = clip_hash(hash);
    struct map *map = &shard->map;
    struct entry *entries[2];
    int count = 0;
    for (int i = 1; i < map->nbuckets && count < 2; i++) {
        size_t j = (i+hash)&(map->nbuckets-1);
        struct bucket *bkt = &map->buckets[j];
        if (get_dib(bkt) == 0) {
            continue;
        }
        struct entry *entry = get_entry(bkt);
        int reason = entry_alive(entry, now, shard->cleartime);
        if (reason) {
            // Entry has expired. Evict this one instead.
            evict_entry(shard, shardidx, entry, now, reason, ctx);
            return;
        }
        if (get_hash(bkt) == hash) {
            continue;
        }
        entries[count++] = entry;
    }
    int choose;
    if (count == 1) {
        choose = 0;
    } else if (count == 2) {
        // We now have two candidates.
        if (entry_time(entries[0]) < entry_time(entries[1])) {
            choose = 0;
        } else {
            choose = 1;
        }
    } else {
        return;
    }
    evict_entry(shard, shardidx, entries[choose], now, POGOCACHE_REASON_LOWMEM,
        ctx);
}

static void shard_deinit(struct shard *shard, struct pgctx *ctx) {
    struct map *map = &shard->map;
    if (!map->buckets) {
        return;
    }
    for (int i = 0; i < map->nbuckets; i++) {
        struct bucket *bkt = &map->buckets[i];
        if (get_dib(bkt) == 0) {
            continue;
        }
        struct entry *entry = get_entry(bkt);
        entry_free(entry, ctx);
    }
    ctx->free(map->buckets);
}

static bool shard_init(struct shard *shard, struct pgctx *ctx) {
    memset(shard, 0, sizeof(struct shard));
    lock_init(shard);
    shard->cas = 1;
    if (!map_init(&shard->map, INITCAP, ctx)) {
        // nomem
        shard_deinit(shard, ctx);
        return false;
    }
    return true;
}

/// Free all cache and shard hashmap allocations.
/// This does not access the value data in any of the entries. If it is needed
/// for the further cleanup at an entry value level, then use the
/// pogocache_iter to perform the cleanup on each entry before calling this
/// operation.
/// Also this is not threadsafe. Make sure that other threads are not
/// currently using the cache concurrently nor after this function is called.
void pogocache_free(struct pogocache *cache) {
    if (!cache) {
        return;
    }
    struct pgctx *ctx = &cache->ctx;
    for (int i = 0; i < cache->ctx.nshards; i++) {
        shard_deinit(&cache->shards[i], ctx);
    }
    cache->ctx.free(cache);
}

static void opts_to_ctx(int nshards, struct pogocache_opts *opts,
    struct pgctx *ctx)
{
    ctx->nshards = nshards;
    int loadfactor = 0;
    if (opts) {
        ctx->yield = opts->yield;
        ctx->evicted = opts->evicted;
        ctx->udata = opts->udata;
        ctx->usecas = opts->usecas;
        ctx->nosixpack = opts->nosixpack;
        ctx->noevict = opts->noevict;
        ctx->seed = opts->seed;
        loadfactor = opts->loadfactor;
        ctx->allowshrink = opts->allowshrink;
        ctx->usethreadbatch = opts->usethreadbatch;
    }
    // make loadfactor a floating point
    loadfactor = loadfactor == 0 ? DEFLOADFACTOR :
        loadfactor < MINLOADFACTOR_RH ? MINLOADFACTOR_RH :
        loadfactor > MAXLOADFACTOR_RH ? MAXLOADFACTOR_RH :
        loadfactor;
    ctx->loadfactor = ((double)loadfactor/100.0);
    ctx->shrinkfactor = ((double)SHRINKAT/100.0);
}

static struct pogocache_opts newdefopts = { 0 };

/// Returns a new cache or null if there is not enough memory available.
/// See 'pogocache_opts' for all options.
struct pogocache *pogocache_new(struct pogocache_opts *opts) {
    if (!opts) {
        opts = &newdefopts;
    }
    void *(*_malloc)(size_t) = opts->malloc ? opts->malloc : malloc;
    void (*_free)(void*) = opts->free ? opts->free : free;
    int shards = !opts || opts->nshards <= 0 ? DEFSHARDS : opts->nshards;
    size_t size = sizeof(struct pogocache)+shards*sizeof(struct shard);
    struct pogocache *cache = _malloc(size);
    if (!cache) {
        return 0;
    }
    memset(cache, 0, sizeof(struct pogocache));
    struct pgctx *ctx = &cache->ctx;
    opts_to_ctx(shards, opts, ctx);
    ctx->malloc = _malloc;
    ctx->free = _free;
    for (int i = 0; i < ctx->nshards; i++) {
        if (!shard_init(&cache->shards[i], ctx)) {
            // nomem
            pogocache_free(cache);
            return 0;
        }
    }
    return cache;
}

static int shard_index(struct pogocache *cache, uint64_t hash) {
    return (hash>>32)%cache->ctx.nshards;
}

static struct shard *shard_get(struct pogocache *cache, int index) {
    return &cache->shards[index];
}

/// Returns a timestamp.
int64_t pogocache_now(void) {
    return getnow();
}

static __thread struct pogocache thbatch;

struct pogocache *pogocache_begin(struct pogocache *cache) {
    struct pogocache *batch;
    if (cache->ctx.usethreadbatch) {
        batch = &thbatch;
    } else {
        batch = cache->ctx.malloc(sizeof(struct pogocache));
        if (!batch) {
            return 0;
        }
    }
    batch->isbatch = true;
    batch->batch.cache = cache;
    batch->batch.shard = 0;
    batch->batch.time = 0;
    return batch;
}

void pogocache_end(struct pogocache *batch) {
    assert(batch->isbatch);
    struct shard *shard = batch->batch.shard;
    while (shard) {
        struct shard *next = shard->next;
        shard->next = 0;
        atomic_store_explicit(&shard->lock, 0, __ATOMIC_RELEASE);
        shard = next;
    }
    if (!batch->batch.cache->ctx.usethreadbatch) {
        batch->batch.cache->ctx.free(batch);
    }
}

static void lock(struct batch *batch, struct shard *shard, struct pgctx *ctx) {
    if (batch) {
        while (1) {
            uintptr_t val = 0;
            if (atomic_compare_exchange_weak_explicit(&shard->lock, &val, 
                (uintptr_t)(void*)batch, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            {
                shard->next = batch->shard;
                batch->shard = shard;
                break;
            }
            if (val == (uintptr_t)(void*)batch) {
                break;
            }
            if (ctx->yield) {
                ctx->yield(ctx->udata);
            }
        }
    } else {
        while (1) {
            uintptr_t val = 0;
            if (atomic_compare_exchange_weak_explicit(&shard->lock, &val, 
                UINTPTR_MAX, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
            {
                break;
            }
            if (ctx->yield) {
                ctx->yield(ctx->udata);
            }
        }
    }
}

static bool acquire_for_scan(int shardidx, struct shard **shard_out, 
    struct pogocache **cache_inout)
{
    struct pogocache *cache = *cache_inout;
    struct batch *batch = 0;
    if (cache->isbatch) {
        // use batch
        batch = &cache->batch;
        cache = batch->cache;
    }
    struct pgctx *ctx = &cache->ctx;
    struct shard *shard = shard_get(cache, shardidx);
    lock(batch, shard, ctx);
    *shard_out = shard;
    *cache_inout = cache;
    return batch != 0;
}

// acquire a lock for the key
static bool acquire_for_key(const char *key, size_t keylen, uint32_t *hash_out,
    struct shard **shard_out, int *shardidx_out, struct pogocache **cache_inout)
{
    struct pogocache *cache = *cache_inout;
    struct batch *batch = 0;
    if (cache->isbatch) {
        // use batch
        batch = &cache->batch;
        cache = batch->cache;
    }
    struct pgctx *ctx = &cache->ctx;
    uint64_t fhash = th64(key, keylen, cache->ctx.seed);
    int shardidx = shard_index(cache, fhash);
    struct shard *shard = shard_get(cache, shardidx);
    lock(batch, shard, ctx);
    *hash_out = fhash;
    *shard_out = shard;
    *shardidx_out = shardidx;
    *cache_inout = cache;
    return batch != 0;
}

// Acquire a lock on the shard for key and execute the provided operation.
#define ACQUIRE_FOR_KEY_AND_EXECUTE(rettype, key, keylen, op) ({ \
    int shardidx; \
    uint32_t hash; \
    struct shard *shard; \
    bool usebatch = acquire_for_key((key), (keylen), &hash, &shard, &shardidx, \
        &cache); \
    struct pgctx *ctx = &cache->ctx; \
    (void)shardidx, (void)hash, (void)ctx; \
    rettype status = op; \
    if (!usebatch) { \
        atomic_store_explicit(&shard->lock, 0, __ATOMIC_RELEASE); \
    } \
    status; \
})

// Acquire a lock on the shard at index and execute the provided operation.
#define ACQUIRE_FOR_SCAN_AND_EXECUTE(rettype, shardidx, op) ({ \
    struct shard *shard; \
    bool usebatch = acquire_for_scan((shardidx), &shard, &cache); \
    struct pgctx *ctx = &cache->ctx; \
    (void)ctx; \
    rettype status = op; \
    if (!usebatch) { \
        atomic_store_explicit(&shard->lock, 0, __ATOMIC_RELEASE); \
    } \
    status; \
})

static int loadop(const void *key, size_t keylen, 
    struct pogocache_load_opts *opts, struct shard *shard, int shardidx, 
    uint32_t hash, struct pgctx *ctx)
{
    opts = opts ? opts : &defloadopts;
    int64_t now = opts->time > 0 ? opts->time : getnow();
    // Get the entry bucket index for the entry with key.
    int bidx = map_get_bucket(&shard->map, key, keylen, hash);
    if (bidx == -1) {
        return POGOCACHE_NOTFOUND;
    }
    // Extract the bucket, entry, and values.
    struct bucket *bkt = &shard->map.buckets[bidx];
    struct entry *entry = get_entry(bkt);
    const char *val;
    size_t vallen;
    int64_t expires;
    uint32_t flags;
    uint64_t cas;
    entry_extract(entry, 0, 0, 0, &val, &vallen, &expires, &flags, &cas, ctx);
    int reason = entry_alive(entry, now, shard->cleartime);
    if (reason) {
        // Entry is no longer alive. Evict the entry and clear the bucket.
        if (ctx->evicted) {
            ctx->evicted(shardidx, reason, now, key, keylen, val, vallen,
                expires, flags, cas, ctx->udata);
        }
        shard->clearcount -= (reason==POGOCACHE_REASON_CLEARED);
        entry_free(entry, ctx);
        delbkt(&shard->map, bidx);
        return POGOCACHE_NOTFOUND;
    }
    if (!opts->notouch) {
        entry_settime(entry, now);
    }
    if (opts->entry) {
        struct pogocache_update *update = 0;
        opts->entry(shardidx, now, key, keylen, val, vallen, expires, flags,
            cas, &update, opts->udata);
        if (update) {
            // User wants to update the entry.
            shard->cas++;
            struct entry *entry2 = entry_new(key, keylen, update->value,
                update->valuelen, update->expires, update->flags, shard->cas, 
                ctx);
            if (!entry2) {
                return POGOCACHE_NOMEM;
            }
            entry_settime(entry2, now);
            set_entry(bkt, entry2);
            entry_free(entry, ctx);
        }
    }
    return POGOCACHE_FOUND;
}

/// Loads an entry from the cache.
/// Use the pogocache_load_opts.entry callback to access the value of the entry.
/// It's possible to update the value using the 'update' param in the callback.
/// See 'pogocache_load_opts' for all options.
/// @returns POGOCACHE_FOUND when the entry was found.
/// @returns POGOCACHE_NOMEM when the entry cannot be updated due to no memory.
/// @returns POGOCACHE_NOTFOUND when the entry was not found.
int pogocache_load(struct pogocache *cache, const void *key, size_t keylen, 
    struct pogocache_load_opts *opts)
{
    return ACQUIRE_FOR_KEY_AND_EXECUTE(int, key, keylen, 
        loadop(key, keylen, opts, shard, shardidx, hash, ctx)
    );
}

static int deleteop(const void *key, size_t keylen, 
    struct pogocache_delete_opts *opts, struct shard *shard, int shardidx, 
    uint32_t hash, struct pgctx *ctx)
{
    opts = opts ? opts : &defdeleteopts;
    int64_t now = opts->time > 0 ? opts->time : getnow();
    struct entry *entry = map_delete(&shard->map, key, keylen, hash, ctx);
    if (!entry) {
        // Entry does not exist
        return POGOCACHE_NOTFOUND;
    }
    const char *val;
    size_t vallen;
    int64_t expires;
    uint32_t flags;
    uint64_t cas;
    int reason = entry_alive(entry, now, shard->cleartime);
    if (reason) {
        // Entry is no longer alive. It was already deleted from the map but
        // we still need to notify the user.
        if (ctx->evicted) {
            entry_extract(entry, 0, 0, 0, &val, &vallen, &expires, &flags, &cas,
                ctx);
            ctx->evicted(shardidx, reason, now, key, keylen, val, vallen,
                expires, flags, cas, ctx->udata);
        }
        shard->clearcount -= (reason==POGOCACHE_REASON_CLEARED);
        tryshrink(&shard->map, false, ctx);
        entry_free(entry, ctx);
        return POGOCACHE_NOTFOUND;
    }
    if (opts->entry) {
        entry_extract(entry, 0, 0, 0, &val, &vallen, &expires, &flags, &cas,
            ctx);
        if (!opts->entry(shardidx, now, key, keylen, val, vallen,
            expires, flags, cas, opts->udata))
        {
            // User canceled the delete. Put it back into the map.
            // This insert will not cause an allocation error because the 
            // previous delete operation left us with at least one available
            // bucket.
            struct entry *old;
            bool ok = map_insert(&shard->map, entry, hash, &old, ctx);
            assert(ok); (void)ok;
            assert(!old);
            return POGOCACHE_CANCELED;
        }
    }
    // Entry was successfully deleted.
    tryshrink(&shard->map, false, ctx);
    entry_free(entry, ctx);
    return POGOCACHE_DELETED;
}

/// Deletes an entry from the cache.
/// See 'pogocache_delete_opts' for all options.
/// @returns POGOCACHE_DELETED when the entry was successfully deleted.
/// @returns POGOCACHE_NOTFOUND when the entry was not found.
/// @returns POGOCACHE_CANCELED when opts.entry callback returned false.
int pogocache_delete(struct pogocache *cache, const void *key, size_t keylen, 
    struct pogocache_delete_opts *opts)
{
    return ACQUIRE_FOR_KEY_AND_EXECUTE(int, key, keylen,
        deleteop(key, keylen, opts, shard, shardidx, hash, ctx)
    );
}

static int storeop(const void *key, size_t keylen, const void *val,
    size_t vallen, struct pogocache_store_opts *opts, struct shard *shard,
    int shardidx, uint32_t hash, struct pgctx *ctx)
{
    int count = shard->map.count;
    opts = opts ? opts : &defstoreopts;
    int64_t now = opts->time > 0 ? opts->time : getnow();
    int64_t expires = 0;
    if (opts->expires > 0) {
        expires = opts->expires;
    } else if (opts->ttl > 0) {
        expires = int64_add_clamp(now, opts->ttl);
    }
    if (opts->keepttl) {
        // User wants to keep the existing ttl. Get the existing entry from the
        // map first and take its expiration.
        int i;
        struct entry *old = map_get_entry(&shard->map, key, keylen, hash, &i);
        if (old) {
            int reason = entry_alive(old, now, shard->cleartime);
            if (reason == 0) {
                expires = entry_expires(old);
            }
        }
    }
    shard->cas++;
    struct entry *entry = entry_new(key, keylen, val, vallen, expires,
        opts->flags, shard->cas, ctx);
    if (!entry) {
        goto nomem;
    }
    entry_settime(entry, now);
    if (opts->lowmem && ctx->noevict) {
        goto nomem;
    }
    // Insert new entry into map
    struct entry *old;
    if (!map_insert(&shard->map, entry, hash, &old, ctx)) {
        goto nomem;
    }
    if (old) {
        int reason = entry_alive(old, now, shard->cleartime);
        if (reason) {
            // There's an old entry, but it's no longer alive.
            // Treat this like an eviction and notify the user.
            if (ctx->evicted) {
                const char *oval;
                size_t ovallen;
                int64_t oexpires = 0;
                uint32_t oflags = 0;
                uint64_t ocas = 0;
                entry_extract(old, 0, 0, 0,
                    &oval, &ovallen, &oexpires, &oflags, &ocas, ctx);
                ctx->evicted(shardidx, reason, now, key, keylen, oval, ovallen,
                    oexpires, oflags, ocas, ctx->udata);
            }
            shard->clearcount -= (reason==POGOCACHE_REASON_CLEARED);
            entry_free(old, ctx);
            old = 0;
        }
    }
    int put_back_status = 0;
    if (old) {
        if (opts->casop) {
            // User is requesting the cas operation.
            if (ctx->usecas) {
                uint64_t old_cas = entry_cas(old);
                if (opts->cas != old_cas) {
                    // CAS test failed.
                    // printf(". cas failed: expected %" PRIu64 ", "
                    //     "got %" PRIu64 "\n", cas, old_cas);
                    put_back_status = POGOCACHE_FOUND;
                }
            } else {
                put_back_status = POGOCACHE_FOUND;
            }
        } else if (opts->nx) {
            put_back_status = POGOCACHE_FOUND;
        }
        if (put_back_status) {
        put_back:;
            // The entry needs be put back into the map and operation must
            // return early.
            // This insert operation must not fail since the entry 'e' and
            // 'old' both exist and will always be bucket swapped. There will
            // never be a new allocation.
            struct entry *e = 0;
            bool ok = map_insert(&shard->map, old, hash, &e, ctx);
            assert(ok); (void)ok;
            assert(e == entry);
            entry_free(entry, ctx);
            return put_back_status;
        }
    } else if (opts->xx || opts->casop) {
        // The new entry must not be inserted.
        // Delete it and return early.
        struct entry *e = map_delete(&shard->map, key, keylen, hash, ctx);
        assert(e == entry); (void)e;
        entry_free(entry, ctx);
        return POGOCACHE_NOTFOUND;
    }
    if (old && opts->entry) {
        // User is requesting to verify the old entry before allowing it to be
        // replaced by the new entry.
        const char *val_;
        size_t vallen_;
        int64_t oexpires = 0;
        uint32_t oflags = 0;
        uint64_t ocas = 0;
        entry_extract(old, 0, 0, 0, &val_, &vallen_, &oexpires, &oflags, &ocas,
            ctx);
        if (!opts->entry(shardidx, now, key, keylen, val_, vallen_, oexpires,
            oflags, ocas, opts->udata))
        {
            // User wants to keep the old entry.
            put_back_status = POGOCACHE_CANCELED;
            goto put_back;
        }
    }
    // The new entry was inserted.
    if (old) {
        entry_free(old, ctx);
        return POGOCACHE_REPLACED;
    } else {
        if (opts->lowmem && shard->map.count > count) {
            // The map grew by one bucket, yet the user indicates that there is
            // a low memory event. Evict one entry.
            auto_evict_entry(shard, shardidx, hash, now, ctx);
        }
        return POGOCACHE_INSERTED;
    }
nomem:
    entry_free(entry, ctx);
    return POGOCACHE_NOMEM;
}

/// Insert or replace an entry in the cache.
/// If an entry with the same key already exists then the cache then the 
/// the opts.entry callback can be used to check the existing
/// value first, allowing the operation to be canceled.
/// See 'pogocache_store_opts' for all options.
/// @returns POGOCACHE_INSERTED when the entry was inserted.
/// @returns POGOCACHE_REPLACED when the entry replaced an existing one.
/// @returns POGOCACHE_FOUND when the entry already exists. (cas/nx)
/// @returns POGOCACHE_CANCELED when the operation was canceled.
/// @returns POGOCACHE_NOMEM when there is system memory available.
int pogocache_store(struct pogocache *cache, const void *key, size_t keylen, 
    const void *val, size_t vallen, struct pogocache_store_opts *opts)
{
    return ACQUIRE_FOR_KEY_AND_EXECUTE(int, key, keylen,
        storeop(key, keylen, val, vallen, opts, shard, shardidx, hash, ctx)
    );
}


static struct pogocache *rootcache(struct pogocache *cache) {
    return cache->isbatch ? cache->batch.cache : cache;
}

/// Returns the number of shards in cache
int pogocache_nshards(struct pogocache *cache) {
    cache = rootcache(cache);
    return cache->ctx.nshards;
}

static int iterop(struct shard *shard, int shardidx, int64_t now,
    struct pogocache_iter_opts *opts, struct pgctx *ctx)
{
    char buf[128];
    int status = POGOCACHE_FINISHED;
    for (int i = 0; i < shard->map.nbuckets; i++) {
        struct bucket *bkt = &shard->map.buckets[i];
        if (get_dib(bkt) == 0) {
            continue;
        }
        struct entry *entry = get_entry(bkt);
        const char *key, *val;
        size_t keylen, vallen;
        int64_t expires;
        uint32_t flags;
        uint64_t cas;
        entry_extract(entry, &key, &keylen, buf, &val, &vallen,
            &expires, &flags, &cas, ctx);
        int reason = entry_alive(entry, now, shard->cleartime);
        if (reason) {
#ifdef EVICTONITER
            if (ctx->evicted) {
                ctx->evicted(shardidx, reason, now, key, keylen, val, vallen,
                    expires, flags, cas, ctx->udata);
            }
            shard->clearcount -= (reason==POGOCACHE_REASON_CLEARED);
            // Delete entry at bucket.
            delbkt(&shard->map, i);
            entry_free(entry, ctx);
            i--;
#endif
        } else {
            // Entry is alive, check with user for next action.
            int action = POGOCACHE_ITER_CONTINUE;
            if (opts->entry) {
                action = opts->entry(shardidx, now, key, keylen, val,
                    vallen, expires, flags, cas, opts->udata);
            }
            if (action != POGOCACHE_ITER_CONTINUE) {
                if (action&POGOCACHE_ITER_DELETE) {
                    // Delete entry at bucket
                    delbkt(&shard->map, i);
                    entry_free(entry, ctx);
                    i--;
                }
                if (action&POGOCACHE_ITER_STOP) {
                    status = POGOCACHE_CANCELED;
                    break;
                }
            }
        }
    }
    tryshrink(&shard->map, true, ctx);
    return status;
}

/// Iterate over entries in the cache.
/// There's an option to allow for isolating the operation to a single shard.
/// The pogocache_iter_opts.entry callback can be used to perform actions such
/// as: deleting entries and stopping iteration early. 
/// See 'pogocache_iter_opts' for all options.
/// @return POGOCACHE_FINISHED if iteration completed
/// @return POGOCACHE_CANCELED if iteration stopped early
int pogocache_iter(struct pogocache *cache, struct pogocache_iter_opts *opts) {
    int nshards = pogocache_nshards(cache);
    opts = opts ? opts : &defiteropts;
    int64_t now = opts->time > 0 ? opts->time : getnow();
    if (opts->oneshard) {
        if (opts->oneshardidx < 0 || opts->oneshardidx >= nshards) {
            return POGOCACHE_FINISHED;
        }
        return ACQUIRE_FOR_SCAN_AND_EXECUTE(int, opts->oneshardidx,
            iterop(shard, opts->oneshardidx, now, opts, &cache->ctx)
        );
    }
    for (int i = 0; i < nshards; i++) {
        const int rc = ACQUIRE_FOR_SCAN_AND_EXECUTE(int, i,
            iterop(shard, i, now, opts, &cache->ctx)
        );
        if (rc != POGOCACHE_FINISHED) {
            return rc;
        }
    }
    return POGOCACHE_FINISHED;
}

static size_t countop(struct shard *shard) {
    return shard->map.count - shard->clearcount;
}

/// Returns the number of entries in the cache.
/// There's an option to allow for isolating the operation to a single shard.
size_t pogocache_count(struct pogocache *cache,
    struct pogocache_count_opts *opts)
{
    int nshards = pogocache_nshards(cache);
    opts = opts ? opts : &defcountopts;
    if (opts->oneshard) {
        if (opts->oneshardidx < 0 || opts->oneshardidx >= nshards) {
            return 0;
        }
        return ACQUIRE_FOR_SCAN_AND_EXECUTE(size_t, opts->oneshardidx,
            countop(shard);
        );
    }
    size_t count = 0;
    for (int i = 0; i < nshards; i++) {
        count += ACQUIRE_FOR_SCAN_AND_EXECUTE(size_t, i,
            countop(shard);
        );
    }
    return count;
}

static uint64_t totalop(struct shard *shard) {
    return shard->map.total;
}

/// Returns the total number of entries that have ever been stored in the cache.
/// For the current number of entries use pogocache_count().
/// There's an option to allow for isolating the operation to a single shard.
uint64_t pogocache_total(struct pogocache *cache,
    struct pogocache_total_opts *opts)
{
    int nshards = pogocache_nshards(cache);
    opts = opts ? opts : &deftotalopts;
    if (opts->oneshard) {
        if (opts->oneshardidx < 0 || opts->oneshardidx >= nshards) {
            return 0;
        }
        return ACQUIRE_FOR_SCAN_AND_EXECUTE(uint64_t, opts->oneshardidx,
            totalop(shard);
        );
    }
    uint64_t count = 0;
    for (int i = 0; i < nshards; i++) {
        count += ACQUIRE_FOR_SCAN_AND_EXECUTE(uint64_t, i,
            totalop(shard);
        );
    }
    return count;
}

static size_t sizeop(struct shard *shard, bool entriesonly) {
    size_t size = 0;
    if (!entriesonly) {
        size += sizeof(struct shard);
        size += sizeof(struct bucket)*shard->map.nbuckets;
    }
    size += shard->map.entsize;
    return size;
}

/// Returns the total memory size of the shard.
/// This includes the memory size of all data structures and entries.
/// Use the entriesonly option to limit the result to only the entries.
/// There's an option to allow for isolating the operation to a single shard.
size_t pogocache_size(struct pogocache *cache,
    struct pogocache_size_opts *opts)
{
    int nshards = pogocache_nshards(cache);
    opts = opts ? opts : &defsizeopts;
    if (opts->oneshard) {
        if (opts->oneshardidx < 0 || opts->oneshardidx >= nshards) {
            return 0;
        }
        return ACQUIRE_FOR_SCAN_AND_EXECUTE(size_t, opts->oneshardidx,
            sizeop(shard, opts->entriesonly);
        );
    }
    size_t count = 0;
    for (int i = 0; i < nshards; i++) {
        count += ACQUIRE_FOR_SCAN_AND_EXECUTE(size_t, i,
            sizeop(shard, opts->entriesonly);
        );
    }
    return count;
}



static int sweepop(struct shard *shard, int shardidx, int64_t now,
    size_t *swept, size_t *kept, struct pgctx *ctx)
{
    char buf[128];
    for (int i = 0; i < shard->map.nbuckets; i++) {
        struct bucket *bkt = &shard->map.buckets[i];
        if (get_dib(bkt) == 0) {
            continue;
        }
        struct entry *entry = get_entry(bkt);
        int64_t expires = entry_expires(entry);
        int64_t etime = entry_time(entry);
        int reason = entry_alive_exp(expires, etime, now, shard->cleartime);
        if (reason == 0) {
            // entry is still alive
            (*kept)++;
            continue;
        }
        // entry is no longer alive.
        if (ctx->evicted) {
            const char *key, *val;
            size_t keylen, vallen;
            int64_t expires_;
            uint32_t flags;
            uint64_t cas;
            entry_extract(entry, &key, &keylen, buf, &val, &vallen, &expires_,
                &flags, &cas, ctx);
            // Report eviction to user
            ctx->evicted(shardidx, reason, now, key, keylen, val, vallen,
                expires_, flags, cas, ctx->udata);
        }
        shard->clearcount -= (reason==POGOCACHE_REASON_CLEARED);
        delbkt(&shard->map, i);
        entry_free(entry, ctx);
        (*swept)++;
        // Entry was deleted from bucket, which may move entries to the right
        // over one bucket to the left. So we need to check the same bucket
        // again.
        i--;
    }
    tryshrink(&shard->map, true, ctx);
    return 0;
}

/// Remove expired entries from the cache.
/// There's an option to allow for isolating the operation to a single shard.
/// The final 'kept' or 'swept' counts are returned.
/// @return POGOCACHE_FINISHED when iteration completed
/// @return POGOCACHE_CANCELED when iteration stopped early
void pogocache_sweep(struct pogocache *cache, size_t *swept, size_t *kept, 
    struct pogocache_sweep_opts *opts)
{
    int nshards = pogocache_nshards(cache);
    opts = opts ? opts : &defsweepopts;
    int64_t now = opts->time > 0 ? opts->time : getnow();
    size_t sweptc = 0;
    size_t keptc = 0;
    if (opts->oneshard) {
        if (opts->oneshardidx >= 0 && opts->oneshardidx < nshards) {
            ACQUIRE_FOR_SCAN_AND_EXECUTE(int, opts->oneshardidx,
                sweepop(shard, opts->oneshardidx, now, &sweptc, &keptc,
                    &cache->ctx);
            );
        }
    } else {
        for (int i = 0; i < nshards; i++) {
            size_t sweptc2 = 0;
            size_t keptc2 = 0;
            ACQUIRE_FOR_SCAN_AND_EXECUTE(int, i,
                sweepop(shard, i, now, &sweptc2, &keptc2, &cache->ctx);
            );
            sweptc += sweptc2;
            keptc += keptc2;
        }
    }
    if (swept) {
        *swept = sweptc;
    }
    if (kept) {
        *kept = keptc;
    }
}

static int clearop(struct shard *shard, int shardidx, int64_t now, 
    struct pgctx *ctx)
{
    (void)shardidx, (void)ctx;
    shard->cleartime = now;
    shard->clearcount += (shard->map.count-shard->clearcount);
    return 0;
}

/// Clear the cache.
/// There's an option to allow for isolating the operation to a single shard.
void pogocache_clear(struct pogocache *cache, struct pogocache_clear_opts *opts)
{
    int nshards = pogocache_nshards(cache);
    opts = opts ? opts : &defclearopts;
    int64_t now = opts->time > 0 ? opts->time : getnow();
    if (opts->oneshard) {
        if (opts->oneshardidx < 0 || opts->oneshardidx >= nshards) {
            return;
        }
        ACQUIRE_FOR_SCAN_AND_EXECUTE(int, opts->oneshardidx,
            clearop(shard, opts->oneshardidx, now, &cache->ctx);
        );
        return;
    }
    for (int i = 0; i < cache->ctx.nshards; i++) {
        ACQUIRE_FOR_SCAN_AND_EXECUTE(int, i,
            clearop(shard, i, now, &cache->ctx);
        );
    }
}

static int sweeppollop(struct shard *shard, int shardidx, int64_t now, 
    int pollsize, double *percent)
{
    // start at random bucket
    int count = 0;
    int dead = 0;
    int bidx = mix13(now+shardidx)%shard->map.nbuckets;
    for (int i = 0; i < shard->map.nbuckets && count < pollsize; i++) {
        struct bucket *bkt = &shard->map.buckets[(bidx+i)%shard->map.nbuckets];
        if (get_dib(bkt) == 0) {
            continue;
        }
        struct entry *entry = get_entry(bkt);
        count++;
        dead += (entry_alive(entry, now, shard->cleartime) != 0);
    }
    if (count == 0) {
        *percent = 0;
        return 0;
    }
    *percent = (double)dead/(double)count;
    return 0;
}

double pogocache_sweep_poll(struct pogocache *cache, 
    struct pogocache_sweep_poll_opts *opts)
{
    int nshards = pogocache_nshards(cache);
    opts = opts ? opts : &defsweeppollopts;
    int64_t now = opts->time > 0 ? opts->time : getnow();
    int pollsize = opts->pollsize == 0 ? 20 : opts->pollsize;
    
    // choose a random shard
    int shardidx = mix13(now)%nshards;
    double percent;
    ACQUIRE_FOR_SCAN_AND_EXECUTE(int, shardidx,
        sweeppollop(shard, shardidx, now, pollsize, &percent);
    );
    return percent;
}
