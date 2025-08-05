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
// Unit main.c is the main entry point for the Pogocache program.
#include <sys/resource.h>
#include <signal.h>
#include <inttypes.h>
#include <stdio.h>
#include <errno.h>
#include <assert.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>
#include "net.h"
#include "conn.h"
#include "sys.h"
#include "cmds.h"
#include "save.h"
#include "xmalloc.h"
#include "util.h"
#include "tls.h"
#include "pogocache.h"
#include "gitinfo.h"
#include "uring.h"

// default user flags
int nthreads = 0;             // number of client threads
char *port = "9401";          // default tcp port (non-tls)
char *host = "127.0.0.1";     // default hostname or ip address
char *persist = "";           // file to load and save data to
char *unixsock = "";          // use a unix socket
char *reuseport = "no";       // reuse tcp port for other programs
char *tcpnodelay = "yes";     // disable nagle's algorithm
char *quickack = "no";        // enable quick acks
char *usecas = "no";          // enable compare and store
char *keepalive = "yes";      // socket keepalive setting
int backlog = 1024;           // network socket accept backlog
int queuesize = 128;          // event queue size
char *maxmemory = "80%";      // Maximum memory allowed - 80% total system
char *evict = "yes";          // evict keys when maxmemory reached
int loadfactor = 75;          // hashmap load factor
char *keysixpack = "yes";     // use sixpack compression on keys
char *trackallocs = "no";     // track allocations (for debugging)
char *auth = "";              // auth token or pa
char *tlsport = "";           // enable tls over tcp port
char *tlscertfile = "";       // tls cert file
char *tlskeyfile = "";        // tls key file
char *tlscacertfile = "";     // tls ca cert file
char *uring = "yes";          // use uring (linux only)
int maxconns = 1024;          // maximum number of sockets
char *noticker = "no";
char *warmup = "yes";

// Global variables calculated in main().
// These should never change during the lifetime of the process.
// Other source files must use the "extern const" specifier.
char *version;
char *githash;
uint64_t seed;
size_t sysmem;
size_t memlimit;
int verb;           // verbosity, 0=no, 1=verbose, 2=very, 3=extremely
bool usesixpack;
int useallocator;
bool usetrackallocs;
bool useevict;
int nshards;
bool usetls;        // use tls security (pemfile required);
bool useauth;       // use auth password
bool usecolor;      // allow color in terminal
char *useid;        // instance id (unique to every process run)
int64_t procstart;  // proc start boot time, for uptime stat

// Global atomic variable. These are safe to read and modify by other source
// files, as long as those sources use "atomic_" methods.
atomic_int shutdownreq;          // shutdown request counter
atomic_int_fast64_t flush_delay; // delay in seconds to next async flushall
atomic_bool sweep;               // mark for async sweep, asap
atomic_bool registered;          // registration is active
atomic_bool lowmem;              // system is in low memory mode.

struct pogocache *cache;

// min max robinhood load factor (75% performs pretty well)
#define MINLOADFACTOR_RH 55
#define MAXLOADFACTOR_RH 95

static void ready(void *udata) {
    (void)udata;
    printf("* Ready to accept connections\n");
}

#define noopt "<noopt>%s"

#define HELP(format, ...) \
    fprintf(file, format, ##__VA_ARGS__)

#define HOPT(opt, desc, format, ...) \
    fprintf(file, "  "); \
    fprintf(file, "%-22s ", opt); \
    fprintf(file, "%-30s ", desc); \
    if (strcmp(format, noopt) != 0) { \
        fprintf(file, "(default: " format ")", ##__VA_ARGS__); \
    } \
    fprintf(file, "\n");

static int calc_nshards(int nprocs) {
    switch (nprocs) {
    case 1:  return 64;
    case 2:  return 128;
    case 3:  return 256;
    case 4:  return 512;
    case 5:  return 1024;
    case 6:  return 2048;
    default: return 4096;
    }
}

static void showhelp(FILE *file) {
    int nprocs = sys_nprocs();
    int nshards = calc_nshards(nprocs);

    HELP("Usage: %s [options]\n", "pogocache");
    HELP("\n");

    HELP("Basic options:\n");
    HOPT("-h hostname", "listening host", "%s", host);
    HOPT("-p port", "listening port", "%s", port);
    HOPT("-s socket", "unix socket file", "%s", *unixsock?unixsock:"none");

    HOPT("-v,-vv,-vvv", "verbose logging level", noopt, "");
    HELP("\n");
    
    HELP("Additional options:\n");
    HOPT("--threads count", "number of threads", "%d", nprocs);
    HOPT("--maxmemory value", "set max memory usage", "%s", maxmemory);
    HOPT("--evict yes/no", "evict keys at maxmemory", "%s", evict);
    HOPT("--persist path", "persistence file", "%s", *persist?persist:"none");
    HOPT("--maxconns conns", "maximum connections", "%d", maxconns);
    HELP("\n");
    
    HELP("Security options:\n");
    HOPT("--auth passwd", "auth token or password", "%s", *auth?auth:"none");
#ifndef NOOPENSSL
    HOPT("--tlsport port", "enable tls on port", "%s", "none");
    HOPT("--tlscert certfile", "tls cert file", "%s", "none");
    HOPT("--tlskey keyfile", "tls key file", "%s", "none");
    HOPT("--tlscacert cacertfile", "tls ca-cert file", "%s", "none");
#endif
    HELP("\n");

    HELP("Advanced options:\n");
    HOPT("--shards count", "number of shards", "%d", nshards);
    HOPT("--backlog count", "accept backlog", "%d", backlog);
    HOPT("--queuesize count", "event queuesize size", "%d", queuesize);
    HOPT("--reuseport yes/no", "reuseport for tcp", "%s", reuseport);
    HOPT("--tcpnodelay yes/no", "disable nagle's algo", "%s", tcpnodelay);
    HOPT("--quickack yes/no", "use quickack (linux)", "%s", quickack);
    HOPT("--uring yes/no", "use uring (linux)", "%s", uring);
    HOPT("--loadfactor percent", "hashmap load factor", "%d", loadfactor);
    HOPT("--keysixpack yes/no", "sixpack compress keys", "%s", keysixpack);
    HOPT("--cas yes/no", "use compare and store", "%s", usecas);
    HELP("\n");
}

static void showversion(FILE *file) {
#ifdef CCSANI
    fprintf(file, "pogocache %s (CCSANI)\n", version);
#else
    fprintf(file, "pogocache %s\n", version);
#endif
}

static size_t calc_memlimit(char *maxmemory) {
    if (strcmp(maxmemory, "unlimited") == 0) {
        return SIZE_MAX;
    }
    char *oval = maxmemory;
    while (isspace(*maxmemory)) {
        maxmemory++;
    }
    char *end;
    errno = 0;
    double mem = strtod(maxmemory, &end);
    if (errno || !(mem > 0) || !isfinite(mem)) {
        goto fail;
    }
    while (isspace(*end)) {
        end++;
    }
    #define exteq(c) \
        (tolower(end[0])==c&& (!end[1]||(tolower(end[1])=='b'&&!end[2])))

    if (strcmp(end, "") == 0) {
        return mem;
    } else if (strcmp(end, "%") == 0) {
        return (((double)mem)/100.0) * sysmem;
    } else if (exteq('k')) {
        return mem*1024.0;
    } else if (exteq('m')) {
        return mem*1024.0*1024.0;
    } else if (exteq('g')) {
        return mem*1024.0*1024.0*1024.0;
    } else if (exteq('t')) {
        return mem*1024.0*1024.0*1024.0*1024.0;
    }
fail:
    fprintf(stderr, "# Invalid maxmemory '%s'\n", oval);
    showhelp(stderr);
    exit(1);
}

static size_t setmaxrlimit(void) {
    size_t maxconns = 0;
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        maxconns = rl.rlim_max;
        rl.rlim_cur = rl.rlim_max;
        rl.rlim_max = rl.rlim_max;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
            perror("# setrlimit(RLIMIT_NOFILE)");
            abort();
        }
    } else {
        perror("# getrlimit(RLIMIT_NOFILE)");
        abort();
    }
    return maxconns;
}

static void evicted(int shard, int reason, int64_t time, const void *key,
    size_t keylen, const void *value, size_t valuelen, int64_t expires,
    uint32_t flags, uint64_t cas, void *udata)
{
    (void)value, (void)valuelen, (void)expires, (void)udata;
    return;
    printf(". evicted shard=%d, reason=%d, time=%" PRIi64 ", key='%.*s'"
        ", flags=%" PRIu32 ", cas=%" PRIu64 "\n",
        shard, reason, time, (int)keylen, (char*)key, flags, cas);
}

#define BEGIN_FLAGS() \
    if (0) {
#define BFLAG(opt, op) \
    } else if (strcmp(argv[i], opt) == 0) { \
        i++; \
        if (i == argc) { \
            fprintf(stderr, "# Option %s missing value\n", opt); \
            exit(1); \
        } \
        if (!dryrun) { \
            char *flag = argv[i]; op; \
        }
#define TFLAG(opt, op) \
    } else if (strcmp(argv[i], opt) == 0) { \
        if (!dryrun) { \
            op; \
        }
#define AFLAG(name, op) \
    } else if (strcmp(argv[i], "--" name) == 0) { \
        i++; \
        if (i == argc) { \
            fprintf(stderr, "# Option --%s missing value\n", name); \
            exit(1); \
        } \
        if (!dryrun) { \
            char *flag = argv[i]; op; \
        } \
    } else if (strstr(argv[i], "--" name "=") == argv[i]) { \
        if (!dryrun) { \
            char *flag = argv[i]+strlen(name)+3; op; \
        }
#define END_FLAGS() \
    } else { \
        fprintf(stderr, "# Unknown program option %s\n", argv[i]); \
        exit(1); \
    }

#define INVALID_FLAG(name, value) \
    fprintf(stderr, "# Option --%s is invalid\n", name); \
    exit(1);

static atomic_bool loaded = false;

void sigterm(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        if (!atomic_load(&loaded) || !*persist) {
            printf("# Pogocache exiting now\n");
            _Exit(0);
        }
        if (*persist) {
            printf("* Saving data to %s, please wait...\n", persist);
            int ret = save(persist, true);
            if (ret != 0) {
                perror("# Save failed");
                _Exit(1);
            }
            printf("# Pogocache exiting now\n");
            _Exit(0);
        }

        int count = atomic_fetch_add(&shutdownreq, 1);
        if (count > 0 && sig == SIGINT) {
            printf("# User forced shutdown\n");
            printf("# Pogocache exiting now\n");
            _Exit(0);
        }
    }
}

static void tick(void) {
    if (!atomic_load_explicit(&loaded, __ATOMIC_ACQUIRE)) {
        return;
    }
    // Memory usage check
    if (memlimit < SIZE_MAX) {
        struct sys_meminfo meminfo;
        sys_getmeminfo(&meminfo);
        size_t memusage = meminfo.rss;
        if (!lowmem) {
            if (memusage > memlimit) {
                atomic_store(&lowmem, true);
                if (verb > 0) {
                    printf("# Low memory mode on\n");
                }
            }
        } else {
            if (memusage < memlimit) {
                atomic_store(&lowmem, false);
                if (verb > 0) {
                    printf("# Low memory mode off\n");
                }
            }
        }
    }

    // Print allocations to terminal.
    if (usetrackallocs) {
        printf(". keys=%zu, allocs=%zu, conns=%zu\n",
            pogocache_count(cache, 0), xallocs(), net_nconns());
    }

}

static void *ticker(void *arg) {
    (void)arg;
    while (1) {
        tick();
        sleep(1);
    }
    return 0;
}

static void listening(void *udata) {
    (void)udata;
    printf("* Network listener established\n");
    if (*persist) {
        if (!cleanwork(persist)) {
            // An error message has already been printed
            _Exit(0);
        }
        if (access(persist, F_OK) == 0) {
            printf("* Loading data from %s, please wait...\n", persist);
            struct load_stats stats;
            int64_t start = sys_now();
            int ret = load(persist, true, &stats);
            if (ret != 0) {
                perror("# Load failed");
                _Exit(1);
            }
            double elapsed = (sys_now()-start)/1e9;
            printf("* Loaded %zu entries (%zu expired) (%.3f MB in %.3f secs) "
                "(%.0f entries/sec, %.0f MB/sec) \n", 
                stats.ninserted, stats.nexpired,
                stats.csize/1024.0/1024.0, elapsed, 
                (stats.ninserted+stats.nexpired)/elapsed, 
                stats.csize/1024.0/1024.0/elapsed);
        }
    }
    atomic_store(&loaded, true);
}

static void yield(void *udata) {
    (void)udata;
    sched_yield();
}

int main(int argc, char *argv[]) {
    procstart = sys_now();

    // Intercept signals
    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT, sigterm);
    signal(SIGTERM, sigterm);

    // Line buffer logging so pipes will stream.
    setvbuf(stdout, 0, _IOLBF, 0);
    setvbuf(stderr, 0, _IOLBF, 0);
    char guseid[17];
    memset(guseid, 0, 17);
    useid = guseid;
    sys_genuseid(useid);    
    const char *maxmemorymb = 0;
    seed = sys_seed();
    verb = 0;
    usetls = false;
    useauth = false;
    lowmem = false;
    version = (char*)GITVERS;
    githash = (char*)GITHASH;

    


    if (uring_available()) {
        uring = "yes";
    } else {
        uring = "no";
    }

    atomic_init(&shutdownreq, 0);
    atomic_init(&flush_delay, 0);
    atomic_init(&sweep, false);
    atomic_init(&registered, false);

    // Parse program flags
    for (int ii = 0; ii < 2; ii++) {
        bool dryrun = ii == 0;
        for (int i = 1; i < argc; i++) {
            if (strcmp(argv[i], "--help") == 0) {
                showhelp(stdout);
                exit(0);
            }
            if (strcmp(argv[i], "--version") == 0) {
                showversion(stdout);
                exit(0);
            }
            BEGIN_FLAGS()
            BFLAG("-p", port = flag)
            BFLAG("-h", host = flag)
            BFLAG("-s", unixsock = flag)
            TFLAG("-v", verb = 1)
            TFLAG("-vv", verb = 2)
            TFLAG("-vvv", verb = 3)
            AFLAG("port", port = flag)
            AFLAG("threads", nthreads = atoi(flag))
            AFLAG("shards", nshards = atoi(flag))
            AFLAG("backlog", backlog = atoi(flag))
            AFLAG("queuesize", queuesize = atoi(flag))
            AFLAG("maxmemory", maxmemory = flag)
            AFLAG("evict", evict = flag)
            AFLAG("reuseport", reuseport = flag)
            AFLAG("uring", uring = flag)
            AFLAG("tcpnodelay", tcpnodelay = flag)
            AFLAG("keepalive", keepalive = flag)
            AFLAG("quickack", quickack = flag)
            AFLAG("trackallocs", trackallocs = flag)
            AFLAG("cas", usecas = flag)
            AFLAG("maxconns", maxconns = atoi(flag))
            AFLAG("loadfactor", loadfactor = atoi(flag))
            AFLAG("sixpack", keysixpack = flag)
            AFLAG("seed", seed = strtoull(flag, 0, 10))
            AFLAG("auth", auth = flag)
            AFLAG("persist", persist = flag)
            AFLAG("noticker", noticker = flag)
            AFLAG("warmup", warmup = flag)
#ifndef NOOPENSSL
            // TLS flags
            AFLAG("tlsport", tlsport = flag)
            AFLAG("tlscert", tlscertfile = flag)
            AFLAG("tlscacert", tlscacertfile = flag)
            AFLAG("tlskey", tlskeyfile = flag)
#endif
            // Hidden or alternative flags
            BFLAG("-t", nthreads = atoi(flag))  // --threads=<num>
            BFLAG("-m", maxmemorymb = flag)     // --maxmemory=<mb>M
            TFLAG("-M", evict = "no")           // --evict=no
            END_FLAGS()
        }
    }

    usecolor = isatty(fileno(stdout));

    if (strcmp(evict, "yes") == 0) {
        useevict = true;
    } else if (strcmp(evict, "no") == 0) {
        useevict = false;
    } else {
        INVALID_FLAG("evict", evict);
    }

    bool usereuseport;
    if (strcmp(reuseport, "yes") == 0) {
        usereuseport = true;
    } else if (strcmp(reuseport, "no") == 0) {
        usereuseport = false;
    } else {
        INVALID_FLAG("reuseport", reuseport);
    }

    if (strcmp(trackallocs, "yes") == 0) {
        usetrackallocs = true;
    } else if (strcmp(trackallocs, "no") == 0) {
        usetrackallocs = false;
    } else {
        INVALID_FLAG("trackallocs", trackallocs);
    }

    bool usetcpnodelay;
    if (strcmp(tcpnodelay, "yes") == 0) {
        usetcpnodelay = true;
    } else if (strcmp(tcpnodelay, "no") == 0) {
        usetcpnodelay = false;
    } else {
        INVALID_FLAG("tcpnodelay", tcpnodelay);
    }

    bool usekeepalive;
    if (strcmp(keepalive, "yes") == 0) {
        usekeepalive = true;
    } else if (strcmp(keepalive, "no") == 0) {
        usekeepalive = false;
    } else {
        INVALID_FLAG("keepalive", keepalive);
    }


    bool usecasflag;
    if (strcmp(usecas, "yes") == 0) {
        usecasflag = true;
    } else if (strcmp(usecas, "no") == 0) {
        usecasflag = false;
    } else {
        INVALID_FLAG("usecas", usecas);
    }

    if (maxconns <= 0) {
        maxconns = 1024;
    }


#ifndef __linux__
    bool useuring = false;
#else
    bool useuring;
    if (strcmp(uring, "yes") == 0) {
        useuring = true;
    } else if (strcmp(uring, "no") == 0) {
        useuring = false;
    } else {
        INVALID_FLAG("uring", uring);
    }
    if (useuring) {
        if (!uring_available()) {
            useuring = false;
        }
    }
#endif

#ifndef __linux__
    quickack = "no";
#endif
    bool usequickack;
    if (strcmp(quickack, "yes") == 0) {
        usequickack = true;
    } else if (strcmp(quickack, "no") == 0) {
        usequickack = false;
    } else {
        INVALID_FLAG("quickack", quickack);
    }

    if (strcmp(keysixpack, "yes") == 0) {
        usesixpack = true;
    } else if (strcmp(keysixpack, "no") == 0) {
        usesixpack = false;
    } else {
        INVALID_FLAG("sixpack", keysixpack);
    }

    // Threads
    if (nthreads <= 0) {
        nthreads = sys_nprocs();
    } else if (nthreads > 4096) {
        nthreads = 4096; 
    }

    if (nshards == 0) {
        nshards = calc_nshards(nthreads);
    }
    if (nshards <= 0 || nshards > 65536) {
        nshards = 65536;
    }

    if (loadfactor < MINLOADFACTOR_RH) {
        loadfactor = MINLOADFACTOR_RH;
        printf("# loadfactor minumum set to %d\n", MINLOADFACTOR_RH);
    } else if (loadfactor > MAXLOADFACTOR_RH) {
        loadfactor = MAXLOADFACTOR_RH;
        printf("# loadfactor maximum set to %d\n", MAXLOADFACTOR_RH);
    }

    if (queuesize < 1) {
        queuesize = 1;
        printf("# queuesize adjusted to 1\n");
    } else if (queuesize > 4096) {
        queuesize = 4096;
        printf("# queuesize adjusted to 4096\n");
    }

    if (maxmemorymb) {
        size_t sz = strlen(maxmemorymb)+2;
        char *str = xmalloc(sz);
        snprintf(str, sz, "%sM", maxmemorymb);
        maxmemory = str;
    }

    if (!*port || strcmp(port, "0") == 0) {
        port = "";
    }

    if (!*tlsport || strcmp(tlsport, "0") == 0) {
        usetls = false;
        tlsport = "";
    } else {
        usetls = true;
        tls_init();
    }

    if (*auth) {
        useauth = true;
    }
    setmaxrlimit();
    sysmem = sys_memory();
    memlimit = calc_memlimit(maxmemory);

    if (memlimit == SIZE_MAX) {
        evict = "no";
        useevict = false;
    }

    struct pogocache_opts opts = {
        .yield = yield,
        .seed = seed,
        .malloc = xmalloc,
        .free = xfree,
        .nshards = nshards,
        .loadfactor = loadfactor,
        .usecas = usecasflag,
        .evicted = evicted,
        .allowshrink = true,
        .usethreadbatch = true,
    };
    // opts.yield = 0;

    cache = pogocache_new(&opts);
    if (!cache) {
        perror("pogocache_new");
        abort();
    }

    // Print the program details
    printf("* Pogocache (pid: %d, arch: %s%s, version: %s, git: %s)\n",
        getpid(), sys_arch(), sizeof(uintptr_t)==4?", mode: 32-bit":"", version,
        githash);
    char buf0[64], buf1[64];
    char buf2[64];
    if (memlimit < SIZE_MAX) {
        snprintf(buf2, sizeof(buf2), "%.0f%%/%s", (double)memlimit/sysmem*100.0,
            memstr(memlimit, buf1));
    } else {
        strcpy(buf2, "unlimited");
    }
    printf("* Memory (system: %s, max: %s, evict: %s)\n", memstr(sysmem, buf0),
        buf2, evict);
    printf("* Features (verbosity: %s, sixpack: %s, cas: %s, persist: %s, "
        "uring: %s)\n",
        verb==0?"normal":verb==1?"verbose":verb==2?"very":"extremely",
        keysixpack, usecas, *persist?persist:"none", useuring?"yes":"no");
    char tcp_addr[256];
    snprintf(tcp_addr, sizeof(tcp_addr), "%s:%s", host, port);
    printf("* Network (port: %s, unixsocket: %s, backlog: %d, reuseport: %s, "
        "maxconns: %d)\n", *port?port:"none", *unixsock?unixsock:"none",
        backlog, reuseport, maxconns);
    printf("* Socket (tcpnodelay: %s, keepalive: %s, quickack: %s)\n",
        tcpnodelay, keepalive, quickack);
    printf("* Threads (threads: %d, queuesize: %d)\n", nthreads, queuesize);
    printf("* Shards (shards: %d, loadfactor: %d%%)\n", nshards, loadfactor);
    printf("* Security (auth: %s, tlsport: %s)\n", 
        strlen(auth)>0?"enabled":"disabled", *tlsport?tlsport:"none");
    if (strcmp(noticker,"yes") == 0) {
        printf("# NO TICKER\n");
    } else {
        pthread_t th;
        int ret = pthread_create(&th, 0, ticker, 0);
        if (ret == -1) {
            perror("# pthread_create(ticker)");
            exit(1);
        }
    }
#ifdef DATASETOK
    printf("# DATASETOK\n");
#endif
#ifdef CMDGETNIL
    printf("# CMDGETNIL\n");
#endif
#ifdef CMDSETOK
    printf("# CMDSETOK\n");
#endif
#ifdef ENABLELOADREAD
    printf("# ENABLELOADREAD\n");
#endif
    struct net_opts nopts = {
        .host = host,
        .port = port,
        .tlsport = tlsport,
        .unixsock = unixsock,
        .reuseport = usereuseport,
        .tcpnodelay = usetcpnodelay,
        .keepalive = usekeepalive,
        .quickack = usequickack,
        .backlog = backlog,
        .queuesize = queuesize,
        .nthreads = nthreads,
        .nowarmup = strcmp(warmup, "no") == 0,
        .nouring = !useuring,
        .listening = listening,
        .ready = ready,
        .data = evdata,
        .opened = evopened,
        .closed = evclosed,
        .maxconns = maxconns,
    };
    net_main(&nopts);
    return 0;
}
