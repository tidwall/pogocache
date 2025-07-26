#!/usr/bin/env bash

set -e
cd $(dirname "${BASH_SOURCE[0]}")

vers=2.11

./download.sh https://github.com/axboe/liburing liburing $vers liburing-$vers

if [[ ! -d "liburing" ]]; then
    rm -rf liburing/
    tar -xzf liburing-$vers.tar.gz
    mv liburing-liburing-$vers liburing
fi

cd liburing
if [[ ! -f "config.ready" ]]; then
    ./configure
    touch config.ready
fi

if [[ ! -f "build.ready" ]]; then
    make -j32
    touch build.ready
fi
