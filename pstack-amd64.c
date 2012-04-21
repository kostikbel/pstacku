#include <err.h>

#include <libunwind.h>

#include "pstack.h"

int
pstack_get_arg0(unw_cursor_t *c, unw_word_t *arg)
{
	int ret;

	ret = unw_get_reg(c, UNW_X86_64_RDI, arg);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_X86_64_RDI) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}

int
pstack_get_arg1(unw_cursor_t *c, unw_word_t *arg)
{
	int ret;

	ret = unw_get_reg(c, UNW_X86_64_RSI, arg);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_X86_64_RSI) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}

int
pstack_get_arg2(unw_cursor_t *c, unw_word_t *arg)
{
	int ret;

	ret = unw_get_reg(c, UNW_X86_64_RDX, arg);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_X86_64_RDX) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}

int
pstack_get_arg3(unw_cursor_t *c, unw_word_t *arg)
{
	int ret;

	ret = unw_get_reg(c, UNW_X86_64_RCX, arg);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_X86_64_RCX) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}

int
pstack_get_arg4(unw_cursor_t *c, unw_word_t *arg)
{
	int ret;

	ret = unw_get_reg(c, UNW_X86_64_R8, arg);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_X86_64_R8) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}

int
pstack_get_arg5(unw_cursor_t *c, unw_word_t *arg)
{
	int ret;

	ret = unw_get_reg(c, UNW_X86_64_R9, arg);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_X86_64_R9) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}
