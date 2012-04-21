#include <err.h>
#include <libunwind.h>

#include "pstack.h"

int
pstack_get_arg0(unw_cursor_t *c, unw_word_t *arg)
{
	int ret;

	ret = unw_get_reg(c, UNW_REG_RDI, &ip);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_REG_RDI) failed, %s",
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

	ret = unw_get_reg(c, UNW_REG_RSI, &ip);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_REG_RSI) failed, %s",
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

	ret = unw_get_reg(c, UNW_REG_RDX, &ip);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_REG_RDX) failed, %s",
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

	ret = unw_get_reg(c, UNW_REG_RCX, &ip);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_REG_RCX) failed, %s",
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

	ret = unw_get_reg(c, UNW_REG_R8, &ip);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_REG_R8) failed, %s",
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

	ret = unw_get_reg(c, UNW_REG_R9, &ip);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_get_reg(UNW_REG_R9) failed, %s",
			      unw_strerror(ret));
		}
		return (0);
	}
	return (1);
}
