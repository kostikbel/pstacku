#!/usr/local/bin/bash

CC=/usr/local/opt/gcc-4.7.0/bin/gcc; export CC
CFLAGS="-Wall -Wextra -O -g"; export CFLAGS

case $(sysctl -n hw.machine) in
    amd64) bitness=64 ;;
    i386)  bitness=32 ;;
    *) echo "Unknown arch"; exit 1;;
esac

../pstacku/configure \
    --enable-maintainer-mode \
    --with-libunwind=/usr/home/kostik/build/bsd/libunwind/usr$bitness
