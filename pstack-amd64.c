#include <assert.h>
#include <err.h>

#include <libunwind.h>

#include "pstack.h"

int
pstack_get_arg(unw_addr_space_t as, void *ui, unw_cursor_t *c,
    int index, unw_word_t *arg)
{
	int reg, ret;

	switch (index) {
	case 0:
		reg = UNW_X86_64_RDI;
		break;
	case 1:
		reg = UNW_X86_64_RSI;
		break;
	case 2:
		reg = UNW_X86_64_RDX;
		break;
	case 3:
		reg = UNW_X86_64_RCX;
		break;
	case 4:
		reg = UNW_X86_64_R8;
		break;
	case 5:
		reg = UNW_X86_64_R9;
		break;
	default:
		assert(0);
	}
	ret = unw_get_reg(c, reg, arg);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(%d) failed, %s", reg,
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}
