#!/usr/local/bin/bash

CC=/usr/local/opt/gcc-14.2.0/bin/gcc; export CC
CFLAGS="-Wall -Wextra -O -g"; export CFLAGS

../pstacku/configure \
    --enable-maintainer-mode \
    --with-libunwind=/usr/local
