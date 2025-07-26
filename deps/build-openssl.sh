#!/usr/bin/env bash

set -e
cd $(dirname "${BASH_SOURCE[0]}")

vers=3.5.1

./download.sh https://github.com/openssl/openssl openssl $vers openssl-$vers

if [[ ! -d "openssl" ]]; then
    rm -rf openssl/
    tar -xzf openssl-$vers.tar.gz
    mv openssl-openssl-$vers openssl
fi

cd openssl
if [[ ! -f "config.ready" ]]; then
    # Compile only the required TLS features.
    ./Configure \
        no-uplink no-ssl3-method no-tls1-method no-tls1_1-method \
        no-dtls1-method no-dtls1_2-method no-argon2 no-bf no-blake2 no-cast \
        no-cmac no-dsa no-idea no-md4 no-mdc2 no-ocb no-rc2 no-rc4 no-rmd160 \
        no-scrypt no-siphash no-siv no-sm2 no-sm3 no-sm4 no-whirlpool \
        no-shared no-afalgeng no-async no-capieng no-cmp no-cms \
        no-comp no-ct no-docs no-dgram no-dso no-dynamic-engine no-engine \
        no-filenames no-gost no-http no-legacy no-module no-nextprotoneg \
        no-static-engine no-tests no-thread-pool no-ts no-ui-console \
        no-quic no-padlockeng no-ssl-trace no-ocsp no-srp no-srtp

    touch config.ready
fi

if [[ ! -f "build.ready" ]]; then
    make -j32
    touch build.ready
fi
