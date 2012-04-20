ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = pstack

pstack_SOURCES = pstack.c

AM_CPPFLAGS = -I @LIBUNWIND@/include
pstack_LDADD = -L@LIBUNWIND@/lib -lunwind -lunwind-ptrace -lunwind-generic
