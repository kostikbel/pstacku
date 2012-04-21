#ifndef	PSTACK_H
#define	PSTACK_H

extern int verbose;

int pstack_get_arg(unw_addr_space_t as, void *ui, unw_cursor_t *c,
    int index, unw_word_t *arg);

#endif
