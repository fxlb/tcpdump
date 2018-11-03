#!/bin/sh

set -e

CC=$1 CFLAGS='-fno-omit-frame-pointer -fsanitize=address -fno-optimize-sibling-calls -fPIC -Wextra -g3 -ggdb3 -O0' ./configure
make -s clean all
make check
