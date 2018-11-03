#!/bin/sh

#set -e

set -x

echo $CC
echo $CFLAGS
export LSAN_OPTIONS=verbosity=1:log_threads=1

CC=$1 CFLAGS='-fno-omit-frame-pointer -fsanitize=address -fno-optimize-sibling-calls -fPIC -Wextra -g3 -ggdb3 -O0' ./configure
if [ $? != 0 ]; then cat config.log; exit 1; fi
make -s clean all
make check
