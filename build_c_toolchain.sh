#!/usr/bin/env bash

set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

mkdir -p $SCRIPT_DIR/toolchain

pushd riscv-gnu-toolchain
./configure --prefix=$SCRIPT_DIR/toolchain --with-arch=rv64ia --with-abi=lp64\
make linux
popd

