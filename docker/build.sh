#!/bin/sh

set -e

owner=$(stat -c '%u:%g' .)
trap 'chown -R ${owner:?} build' EXIT

rm -rf build 
cmake -B build
cmake --build build

if [ "$SHA256SUMS" = update ]; then
    sha256sum build/tiniktls >SHA256SUMS
else
    sha256sum -c SHA256SUMS
fi
