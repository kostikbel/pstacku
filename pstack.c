#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

#ifndef KERN_PROC_OSREL
#define	KERN_PROC_OSREL	40
#endif

static void
backtrace_lwp(unw_addr_space_t as, void *ui, lwpid_t lwpid)
{
	char buf[512];
	unw_cursor_t c;
	unw_word_t ip, sp, start_ip, off;
	size_t len;
	int n, ret;

	printf("Thread %d:\n", lwpid);
	ret = unw_init_remote(&c, as, ui);
	if (ret < 0) {
		warnx("unw_init_remote() failed, %s", unw_strerror(ret));
		return;
	}

	n = 0;
	start_ip = 0; /* shut down compiler */
	do {
		ret = unw_get_reg(&c, UNW_REG_IP, &ip);
		if (ret < 0) {
			warnx("unw_get_reg(UNW_REG_IP) failed, %s",
			    unw_strerror(ret));
			return;
		}
		ret = unw_get_reg(&c, UNW_REG_SP, &sp);
		if (ret < 0) {
			warnx("unw_get_reg(UNW_REG_SP) failed, %s",
			    unw_strerror(ret));
			return;
		}

		if (n == 0)
			start_ip = ip;

		buf[0] = '\0';
		ret = unw_get_proc_name(&c, buf, sizeof(buf), &off);
		if (ret < 0) {
			strcpy(buf, "????????");
			off = 0;
		}
		if (off != 0) {
			len = strlen(buf);
			if (len >= sizeof(buf) - 32)
				len = sizeof(buf) - 32;
			snprintf(buf + len, sizeof(buf) - len, "+0x%lx",
			    (unsigned long)off);
		}
		printf (" 0x%0lx %s (sp=0x%0lx)\n", (long)ip, buf, (long)sp);

		ret = unw_step(&c);
		if (ret < 0) {
			unw_get_reg(&c, UNW_REG_IP, &ip);
			warnx(
			    "unw_step() error for ip %0lx/start ip %0lx, %s",
			    (long)ip, (long)start_ip, unw_strerror(ret));
			return;
		}
		n++;
	} while (ret > 0);
}

static void
pid_proc_info(pid_t pid)
{
	char path[PATH_MAX];
	int error, mib[4], osrel;
	size_t len;

	mib[0] = CTL_KERN;
	mib[1] = KERN_PROC;
	mib[2] = KERN_PROC_PATHNAME;
	mib[3] = pid;

	len = sizeof(path);
	error = sysctl(mib, 4, path, &len, NULL, 0);
	if (error == -1)
		strcpy(path, "????????");

	mib[2] = KERN_PROC_OSREL;

	len = sizeof(osrel);
	error = sysctl(mib, 4, &osrel, &len, NULL, 0);
	if (error == -1)
		osrel = 0;

	printf("%d: %s (osrel %d)\n", pid, path, osrel);
}

static void
backtrace_proc(pid_t pid)
{
	lwpid_t *lwpids;
	unw_addr_space_t as;
	struct UPT_info *ui;
	int error, i, lwpnums, status;

	error = ptrace(PT_ATTACH, pid, NULL, 0);
	if (error == -1)
		err(1, "Error attaching to pid %d", pid);
	error = waitpid(pid, &status, WSTOPPED);
	if (error == -1)
		err(1, "Error waiting for attach to pid %d", pid);
	assert(error == pid);

	pid_proc_info(pid);

	error = ptrace(PT_GETNUMLWPS, pid, NULL, 0);
	if (error == -1) {
		error = errno;
		ptrace(PT_DETACH, pid, (caddr_t)1, 0);
		errc(1, error, "Error getting the number of lwps");
	}
	lwpnums = error;
	lwpids = calloc(lwpnums, sizeof(lwpid_t));
	if (lwpids == NULL) {
		error = errno;
		ptrace(PT_DETACH, pid, (caddr_t)1, 0);
		errc(1, error, "Error getting the number of lwps");
	}
	error = ptrace(PT_GETLWPLIST, pid, (caddr_t)lwpids, lwpnums *
	    sizeof(lwpid_t));
	if (error == -1) {
		error = errno;
		ptrace(PT_DETACH, pid, (caddr_t)1, 0);
		errc(1, error, "Error getting the lwp list");
	}
	assert(lwpnums == error);
	lwpnums = error;
	
	as = unw_create_addr_space(&_UPT_accessors, 0);
	if (as == NULL) {
		ptrace(PT_DETACH, pid, (caddr_t)1, 0);
		errx(1, "unw_create_addr_space() failed");
	}

	for (i = 0; i < lwpnums; i++) {
		ui = _UPT_create(lwpids[i]);
		backtrace_lwp(as, ui, lwpids[i]);
		_UPT_destroy(ui);
	}

	unw_destroy_addr_space(as);
	ptrace(PT_DETACH, pid, (caddr_t)1, 0);
}

static void
usage(void)
{

	/* XXXKIB */
	exit(2);
}

int
main(int argc, char **argv)
{
	int target_pid;

	if (argc < 2)
		usage();
	target_pid = atoi(argv[1]);
	if (target_pid == 0) {
		/* XXXKIB core support */
		usage();
	}

	backtrace_proc(target_pid);
	return (0);
}
