/*-
 * Copyright (c) 2012 Konstantin Belousov <kib@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <libunwind.h>
#include "pstack.h"

/*
 * On i386, this function naively assumes that the frame layout is
 * completely standard:
 *
 *   +----------------+
 *   |     arg3       |
 *   +----------------+
 *   |     arg2       |
 *   +----------------+
 *   |     arg1       |
 *   +----------------+
 *   |     ret        |
 *   +----------------+
 *   |    prev %ebp   |
 *   +----------------+  <--- %ebp
 *
 * Unfortunately, typical modern code has a gap between ret and
 * previous %ebp due to the local stack alignment.  As a result, the
 * arguments printed are shifted by the random amount, and looks like
 * garbage.
 */
int
pstack_get_arg(unw_addr_space_t as, void *ui, unw_cursor_t *c,
    int index, unw_word_t *arg)
{
	unw_accessors_t *a;
	unw_word_t ebp;
	int ret;

	ret = unw_get_reg(c, UNW_X86_EBP, &ebp);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_X86_EBP) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	a = unw_get_accessors(as);
	ret = a->access_mem(as, ebp + 8 + 4 * index, arg, 0, ui);
	if (ret < 0) {
		if (verbose) {
			warnx("access_mem(0x%lx) for arg %d failed, %s",
			    (long)ebp, index, unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}
