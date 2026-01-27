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
// Unit save.c provides an interface for saving and loading Pogocache
// data files.
#include <assert.h>
#include <stdatomic.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <libgen.h>
#include "save.h"
#include "pogocache.h"
#include "buf.h"
#include "util.h"
#include "lz4.h"
#include "sys.h"
#include "xmalloc.h"

#define BLOCKSIZE 1048576
#define COMPRESS

extern struct pogocache *cache;
extern const int verb;

struct savectx {
    pthread_t th;          // work thread
    int index;             // thread index
    pthread_mutex_t *lock; // write lock
    int fd;                // work file descriptor
    int start;             // current shard
    int count;             // number of shards to process
    struct buf buf;        // block buffer
    bool ok;               // final ok
    int errnum;            // final errno status
    struct buf dst;        // compressed buffer space
    size_t nentries;       // number of entried in block buffer
};

static int flush(struct savectx *ctx) {
    if (ctx->nentries == 0) {
        ctx->buf.len = 0;
        return 0;
    }
    // Make sure that there's enough space in the dst buffer to store the
    // header (16 bytes) and the compressed data.
    size_t bounds = LZ4_compressBound(ctx->buf.len);
    buf_ensure(&ctx->dst, 16+bounds);
    // Compress the block
    uint32_t len = LZ4_compress_default((char*)ctx->buf.data, 
        (char*)ctx->dst.data+16, ctx->buf.len, bounds);
    // The block is now compressed.
    // Genreate a checksum of the compressed data.
    uint32_t crc = crc32(ctx->dst.data+16, len);
    // Write the 16 byte header
    // (0-3) 'POGO' tag
    memcpy(ctx->dst.data, "POGO", 4);
    // (4-7) Checksum
    write_u32(ctx->dst.data+4, crc);
    // (8-11) Len of decompressed data 
    write_u32(ctx->dst.data+8, ctx->buf.len);
    // (12-15) Len of compressed data 
    write_u32(ctx->dst.data+12, len);
    // The rest of the dst buffer contains the compressed bytes
    uint8_t *p = (uint8_t*)ctx->dst.data;
    uint8_t *end = p + len+16;
    bool ok = true;
    pthread_mutex_lock(ctx->lock);
    while (p < end) {
        ssize_t n = write(ctx->fd, p, end-p);
        if (n < 0) {
            ok = false;
            break;
        }
        p += n;
    }
    pthread_mutex_unlock(ctx->lock);
    ctx->buf.len = 0;
    ctx->nentries = 0;
    return ok ? 0 : -1;
}

static int save_entry(int shard, int64_t time, const void *key, size_t keylen,
    const void *value, size_t valuelen, int64_t expires, uint32_t flags,
    uint64_t cas, void *udata)
{
    (void)shard;
    struct savectx *ctx = udata;
    buf_append_byte(&ctx->buf, 0); // entry type. zero=k/v string pair;
    buf_append_uvarint(&ctx->buf, keylen);
    buf_append(&ctx->buf, key, keylen);
    buf_append_uvarint(&ctx->buf, valuelen);
    buf_append(&ctx->buf, value, valuelen);
    if (expires > 0) {
        int64_t ttl = expires-time;
        assert(ttl > 0);
        buf_append_uvarint(&ctx->buf, ttl);
    } else {
        buf_append_uvarint(&ctx->buf, 0);
    }
    buf_append_uvarint(&ctx->buf, flags);
    buf_append_uvarint(&ctx->buf, cas);
    ctx->nentries++;
    return POGOCACHE_ITER_CONTINUE;
}

static void *thsave(void *arg) {
    struct savectx *ctx = arg;
    for (int i = 0; i < ctx->count; i++) {
        int shardidx = ctx->start+i;
        struct pogocache_iter_opts opts = {
            .oneshard = true,
            .oneshardidx = shardidx,
            .time = sys_now(),
            .entry = save_entry,
            .udata = ctx,
        };
        // write the unix timestamp before entries
        buf_append_uvarint(&ctx->buf, sys_unixnow());
        int status = pogocache_iter(cache, &opts);
        if (status == POGOCACHE_CANCELED) {
            goto done;
        }
        if (flush(ctx) == -1) {
            goto done;
        }
    }
    ctx->ok = true;
done:
    buf_clear(&ctx->buf);
    buf_clear(&ctx->dst);
    ctx->errnum = errno;
    return 0;
}

int save(const char *path, bool fast) {
    uint64_t seed = sys_seed();
    size_t psize = strlen(path)+32;
    char *workpath = xmalloc(psize);
    snprintf(workpath, psize, "%s.%08x.pogocache.work", path, 
        (int)(seed%INT_MAX));
    if (verb >= 2) {
        printf(". Saving to work file %s\n", workpath);
    }
    int fd = open(workpath, O_RDWR|O_CREAT, S_IRUSR|S_IRGRP|S_IROTH);
    if (fd == -1) {
        return -1;
    }
    int nshards = pogocache_nshards(cache);
    int nprocs = sys_nprocs();
    if (nprocs > nshards) {
        nprocs = nshards;
    }
    if (!fast) {
        nprocs = 1;
    }
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    struct savectx *ctxs = xmalloc(nprocs*sizeof(struct savectx));
    memset(ctxs, 0, nprocs*sizeof(struct savectx));
    bool ok = false;
    int start = 0;
    for (int i = 0; i < nprocs; i++) {
        struct savectx *ctx = &ctxs[i];
        ctx->index = i;
        ctx->start = start;
        ctx->count = nshards/nprocs;
        ctx->fd = fd;
        ctx->lock = &lock;
        if (i == nprocs-1) {
            ctx->count = nshards-ctx->start;
        }
        if (nprocs > 1) {
            if (pthread_create(&ctx->th, 0, thsave, ctx) == -1) {
                ctx->th = 0;
            }
        }
        start += ctx->count;
    }
    // execute operations on failed threads (or fast=false)
    for (int i = 0; i < nprocs; i++) {
        struct savectx *ctx = &ctxs[i];
        if (ctx->th == 0) {
            thsave(ctx);
        }
    }
    // wait for threads to finish
    for (int i = 0; i < nprocs; i++) {
        struct savectx *ctx = &ctxs[i];
        if (ctx->th != 0) {
            pthread_join(ctx->th, 0);
        }
    }
    // check for any failures
    for (int i = 0; i < nprocs; i++) {
        struct savectx *ctx = &ctxs[i];
        if (!ctx->ok) {
            errno = ctx->errnum;
            goto done;
        }
    }
    // Move file work file to final path
    if (rename(workpath, path) == -1) {
        goto done;
    }
    ok = true;
done:
    close(fd);
    unlink(workpath);
    xfree(workpath);
    xfree(ctxs);
    return ok ? 0 : -1;
}

// compressed block
struct cblock {
    struct buf cdata;   // compressed data
    size_t dlen;        // decompressed size
};

struct loadctx {
    pthread_t th;

    // shared context
    pthread_mutex_t *lock;
    pthread_cond_t *cond;
    bool *donereading;       // shared done flag
    int *nblocks;            // number of blocks in queue
    struct cblock *blocks;   // the block queue
    bool *failure;           // a thread will set this upon error

    // thread status
    atomic_bool ok;
    int errnum;
    size_t ninserted;
    size_t nexpired;
};

static bool load_block(struct cblock *block, struct loadctx *ctx) {
    (void)ctx;
    bool ok = false;

    int64_t now = sys_now();
    int64_t unixnow = sys_unixnow();

    // decompress block
    char *ddata = xmalloc(block->dlen);
    int ret = LZ4_decompress_safe(block->cdata.data, ddata, block->cdata.len, 
        block->dlen);
    if (ret < 0 || (size_t)ret != block->dlen) {
        printf(". bad compressed block\n");
        goto done;
    }
    buf_clear(&block->cdata);
    uint8_t *p = (void*)ddata;
    uint8_t *e = p + block->dlen;

    int n;
    uint64_t x;
    // read unix time
    n = varint_read_u64(p, e-p, &x);
    if (n <= 0 || (int64_t)x < 0) {
        printf(". bad unix time\n");
        goto done;
    }
    p += n;

    int64_t unixtime = x;
    // printf(". unixtime=%lld\n", unixtime);

    // Read each entry from decompressed data
    while (e > p) {
        /////////////////////
        // kind
        uint8_t kind = *(p++);
        
        if (kind != 0) {
            // only k/v strings allowed at this time.
            printf(">> %d\n", kind);
            printf(". unknown kind\n");
            goto done;
        }
        /////////////////////
        // key
        n = varint_read_u64(p, e-p, &x);
        if (n <= 0 || x > SIZE_MAX) {
            goto done;
        }
        p += n;
        size_t keylen = x;
        if ((size_t)(e-p) < keylen) {
            goto done;
        }
        const uint8_t *key = p;
        p += keylen;
        /////////////////////
        // val
        n = varint_read_u64(p, e-p, &x);
        if (n <= 0 || x > SIZE_MAX) {
            goto done;
        }
        p += n;
        size_t vallen = x;
        if ((size_t)(e-p) < vallen) {
            goto done;
        }
        const uint8_t *val = p;
        p += vallen;
        /////////////////////
        // ttl
        n = varint_read_u64(p, e-p, &x);
        if (n <= 0 || (int64_t)x < 0) {
            goto done;
        }
        int64_t ttl = x;
        p += n;
        /////////////////////
        // flags
        n = varint_read_u64(p, e-p, &x);
        if (n <= 0 || x > UINT32_MAX) {
            goto done;
        }
        uint32_t flags = x;
        p += n;
        /////////////////////
        // cas
        n = varint_read_u64(p, e-p, &x);
        if (n <= 0) {
            goto done;
        }
        uint64_t cas = x;
        p += n;
        if (ttl > 0) {
            int64_t unixexpires = int64_add_clamp(unixtime, ttl);
            if (unixexpires < unixnow) {
                // already expired, skip this entry
                ctx->nexpired++;
                continue;
            }
            ttl = unixexpires-unixnow;
        }
        struct pogocache_store_opts opts = {
            .flags = flags,
            .time = now,
            .ttl = ttl,
            .cas = cas,
        };
        // printf("[%.*s]=[%.*s]\n", (int)keylen, key, (int)vallen, val);
        ret = pogocache_store(cache, key, keylen, val, vallen, &opts);
        assert(ret == POGOCACHE_INSERTED || ret == POGOCACHE_REPLACED);
        ctx->ninserted++;
    }
    ok = true;
done:
    buf_clear(&block->cdata);
    xfree(ddata);
    if (!ok) {
        printf(". bad block\n");
    }
    return ok;
}

static void *thload(void *arg) {
    struct loadctx *ctx = arg;
    pthread_mutex_lock(ctx->lock);
    while (1) {
        if (*ctx->failure) {
            break;
        }
        if (*ctx->nblocks > 0) {
            // Take a block for processing
            struct cblock block = ctx->blocks[(*ctx->nblocks)-1];
            (*ctx->nblocks)--;
            pthread_mutex_unlock(ctx->lock);
            pthread_cond_broadcast(ctx->cond); // notify reader thread
            ctx->ok = load_block(&block, ctx);
            pthread_mutex_lock(ctx->lock);
            if (!ctx->ok) {
                *ctx->failure = true;
                break;
            }
            // next block
            continue;
        }
        if (*ctx->donereading) {
            break;
        }
        pthread_cond_wait(ctx->cond, ctx->lock);
    }
    pthread_mutex_unlock(ctx->lock);
    pthread_cond_broadcast(ctx->cond); // notify reader thread
    if (!ctx->ok) {
        ctx->errnum = errno;
    }
    return 0;
}

// load data into cache from path
int load(const char *path, bool fast, struct load_stats *stats) {
    // Use a single stream reader. Handing off blocks to threads.
    struct load_stats sstats;
    if (!stats) {
        stats = &sstats;
    }
    memset(stats, 0, sizeof(struct load_stats));

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -1;
    }

    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    bool donereading = false;
    bool failure = false;

    int nprocs = fast ?  sys_nprocs() : 1;
    struct loadctx *ctxs = xmalloc(nprocs*sizeof(struct loadctx));
    memset(ctxs, 0, nprocs*sizeof(struct loadctx));
    int nblocks = 0;
    struct cblock *blocks = xmalloc(sizeof(struct cblock)*nprocs);
    memset(blocks, 0, sizeof(struct cblock)*nprocs);
    int therrnum = 0;
    bool ok = true;
    for (int i = 0; i < nprocs; i++) {
        struct loadctx *ctx = &ctxs[i];
        ctx->lock = &lock;
        ctx->cond = &cond;
        ctx->donereading = &donereading;
        ctx->nblocks = &nblocks;
        ctx->failure = &failure;
        ctx->blocks = blocks;
        atomic_init(&ctx->ok, true);
        if (pthread_create(&ctx->th, 0, thload, ctx) == -1) {
            ctx->th = 0;
            ok = false;
            if (therrnum == 0) {
                therrnum = errno;
            }
        }
    }
    if (!ok) {
        // there was an error creating a thread. 
        // At this point there may be some orphaned threads waiting on 
        // a condition variable. 
        goto shutdown_threads;
    }

    // Read the blocks from file, one at a time, handing putting blocks into
    // the 'blocks' queue. The running threads will pick these up and 
    // process them in no specific order.
    struct buf cdata = { 0 };
    bool shortread = false;
    while (ok) {
        uint8_t head[16];
        ssize_t size = read(fd, head, 16);
        if (size <= 0) {
            if (size == -1) {
                ok = false;
            }
            break;
        }
        if (size < 16) {
            printf(". bad head size\n");
            ok = false;
            break;
        }
        if (memcmp(head, "POGO", 4) != 0) {
            printf(". missing 'POGO'\n");
            ok = false;
            break;
        }
        uint32_t crc;
        memcpy(&crc, head+4, 4);
        size_t dlen = read_u32(head+8);
        size_t clen = read_u32(head+12);
        buf_ensure(&cdata, clen);
        bool okread = true;
        size_t total = 0;
        while (total < clen) {
            ssize_t rlen = read(fd, cdata.data+total, clen-total);
            if (rlen <= 0) {
                shortread = true;
                okread = false;
                break;
            }
            total += rlen;
        }
        if (!okread) {
            if (shortread) {
                printf(". shortread\n");
            }
            ok = false;
            break;
        }
        cdata.len = clen;
        stats->csize += clen;
        stats->dsize += dlen;
        uint32_t crc2 = crc32(cdata.data, clen);
        if (crc2 != crc) {
            printf(". bad crc\n");
            ok = false;
            goto bdone;
        }
        // We have a good block. Push it into the queue
        pthread_mutex_lock(&lock);
        while (1) {
            if (failure) {
                // A major error occured, stop reading now
                ok = false;
                break;
            }
            if (nblocks == nprocs) {
                // Queue is currently filled up.
                // Wait and try again.
                pthread_cond_wait(&cond, &lock);
                continue;
            }
            // Add block to queue
            blocks[nblocks++] = (struct cblock){ 
                .cdata = cdata,
                .dlen = dlen,
            };
            memset(&cdata, 0, sizeof(struct buf));
            pthread_cond_broadcast(&cond);
            break;
        }
        pthread_mutex_unlock(&lock);
    }
bdone:
    buf_clear(&cdata);


shutdown_threads:
    // Stop all threads
    pthread_mutex_lock(&lock);
    donereading = true;
    pthread_mutex_unlock(&lock);
    pthread_cond_broadcast(&cond);

    // Wait for threads to finish
    for (int i = 0; i < nprocs; i++) {
        struct loadctx *ctx = &ctxs[i];
        if (ctx->th != 0) {
            pthread_join(ctx->th, 0);
            stats->nexpired += ctx->nexpired;
            stats->ninserted += ctx->ninserted;
        }
    }

    // Get the current error, if any
    errno = 0;
    ok = ok && !failure;
    if (!ok) {
        errno = therrnum;
        for (int i = 0; i < nprocs; i++) {
            struct loadctx *ctx = &ctxs[i];
            if (ctx->th != 0) {
                if (!ctx->ok) {
                    errno = ctx->errnum;
                    break;
                }
            }
        }
    }

    // Free all resources.
    for (int i = 0; i < nblocks; i++) {
        buf_clear(&blocks[i].cdata);
    }
    xfree(blocks);
    xfree(ctxs);
    close(fd);
    return ok ? 0 : -1;
}

// removes all work files and checks that the current directory is valid.
bool cleanwork(const char *persist) {
    if (*persist == '\0') {
        return false;
    }
    bool ok = false;
    char *path = xmalloc(strlen(persist)+1);
    strcpy(path, persist);
    char *dirpath = dirname(path);
    DIR *dir = opendir(dirpath);
    if (!dir) {
        perror("# opendir");
        goto done;
    }
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_type != DT_REG) {
            continue;
        }
        const char *ext = ".pogocache.work";
        if (strlen(entry->d_name) < strlen(ext) ||
            strcmp(entry->d_name+strlen(entry->d_name)-strlen(ext), ext) != 0)
        {
            continue;
        }
        size_t filepathcap = strlen(dirpath)+1+strlen(entry->d_name)+1;
        char *filepath = xmalloc(filepathcap);
        snprintf(filepath, filepathcap, "%s/%s", dirpath, entry->d_name);
        if (unlink(filepath) == 0) {
            printf("# deleted work file %s\n", filepath);
        } else {
            perror("# unlink");
        }
        xfree(filepath);
    }
    ok = true;
done:
    if (dir) {
        closedir(dir);
    }
    xfree(path);
    return ok;
}
