#!/usr/local/bin/bash

CC=/usr/local/opt/gcc-4.7.0/bin/gcc; export CC
CFLAGS="-Wall -Wextra -O -g"; export CFLAGS
../pstacku/configure \
    --enable-maintainer-mode \
    --with-libunwind=/usr/home/kostik/build/bsd/libunwind/usr32
