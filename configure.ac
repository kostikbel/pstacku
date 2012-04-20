AC_INIT(pstacku, 0.1, kib@FreeBSD.org)
AC_PREREQ([2.68])
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE([foreign])
AM_MAINTAINER_MODE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AM_PROG_LIBTOOL

AC_ARG_WITH([libunwind],
    [AS_HELP_STRING([--with-libunwind@<:@=DIR@:>@],
        [a directory where libunwind is installed @<:@default=/usr/local@:>@])],
    [with_libunwind="$withval"],
    AC_ERROR([Cannot build without libunwind]))

LIBUNWIND=$with_libunwind
AC_SUBST([LIBUNWIND])

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
