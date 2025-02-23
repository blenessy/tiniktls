#!/bin/sh

set -ex

owner=$(stat -c '%u:%g' .)
trap 'chown -R ${owner:?} build' EXIT

rm -rf build 
cmake -B build
cmake --build build
