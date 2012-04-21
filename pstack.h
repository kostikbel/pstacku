#ifndef	PSTACK_H
#define	PSTACK_H

extern int verbose;

int pstack_get_arg0(unw_cursor_t *c, unw_word_t *arg);
int pstack_get_arg1(unw_cursor_t *c, unw_word_t *arg);
int pstack_get_arg2(unw_cursor_t *c, unw_word_t *arg);
int pstack_get_arg3(unw_cursor_t *c, unw_word_t *arg);
int pstack_get_arg4(unw_cursor_t *c, unw_word_t *arg);
int pstack_get_arg5(unw_cursor_t *c, unw_word_t *arg);

#endif
