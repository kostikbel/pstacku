#include <err.h>

#include <libunwind.h>

#include "pstack.h"

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
