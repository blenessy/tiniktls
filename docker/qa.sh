#!/bin/sh

set -ex

test -e build/tiniktls

owner=$(stat -c '%u:%g' .)
trap 'chown -R ${owner:?} src' EXIT

echo "=== Testing ==="
TINIKTLS_CA_CHAIN=test/certs/ca-chain.pem build/tiniktls -- python3 test/ktls_tests.py

echo "=== Fixing Code Style ==="
clang-format -i -style=google src/ktls.*

echo "=== Static Analysis ==="
# -clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling: only Microsoft stuff support fprintf_s and friends
echo "NOTE: clang-tidy stdout is piped to clang-tidy.log"
clang-tidy --checks=-clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling \
    --format-style=google --warnings-as-errors=* src/ktls.c
