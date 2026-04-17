#!/bin/bash
set -euo pipefail

ASAN=OFF
RUN_TEST=1
for arg in "$@"; do
    case "$arg" in
        --asan) ASAN=ON ;;
        --no-test) RUN_TEST=0 ;;
        --clean) rm -rf build ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

mkdir -p build
cd build
cmake -DSPROTOCOL_ASAN=${ASAN} ..
cmake --build . -j

if [ "$RUN_TEST" = "1" ] && [ -x ./bin/sprotocol_test ]; then
    echo "==== Running sprotocol_test ===="
    ./bin/sprotocol_test
fi
