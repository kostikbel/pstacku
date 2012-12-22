ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = pstack

pstack_SOURCES = pstack.c pstack.h
dist_pstack_MANS = pstack.man

EXTRA_pstack_SOURCES = pstack-i386.c pstack-amd64.c
pstack_DEPENDENCIES = @ARCH_OBJ@
pstack_LDADD = @ARCH_OBJ@

AM_CPPFLAGS = -I @LIBUNWIND@/include
pstack_LDADD +=  -L@LIBUNWIND@/lib -lunwind -lunwind-ptrace -lunwind-generic
