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
#include <time.h>
#include <unistd.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "pstack.h"

#ifndef KERN_PROC_OSREL
#define	KERN_PROC_OSREL	40
#endif

#define timespecsub(vvp, uvp)						\
	do {								\
		(vvp)->tv_sec -= (uvp)->tv_sec;				\
		(vvp)->tv_nsec -= (uvp)->tv_nsec;			\
		if ((vvp)->tv_nsec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_nsec += 1000000000;			\
		}							\
	} while (0)

static int arg_count;
static int frame_count = -1;
static int show_obj;
static int show_obj_full;
static int show_susp_time;
int verbose;
static struct timespec susp_start, susp_end;

static int
get_obj_path(int pid, unw_word_t ip, char *buf, size_t bufsize)
{
	struct ptrace_vm_entry pve;
	int error, first, ts;

restart:
	bzero(&pve, sizeof(pve));
	for (first = 1; ; first = 0) {
		pve.pve_path = buf;
		pve.pve_pathlen = bufsize;
	
		error = ptrace(PT_VM_ENTRY, pid, (caddr_t)&pve, 0);
		if (error == -1) {
			if (errno == ENOENT)
				return (0);
			if (verbose)
				warn("ptrace PT_VM_ENTRY");
			return (0);
		}
		if (first)
			ts = pve.pve_timestamp;
		else if (ts != pve.pve_timestamp)
			     goto restart;
		if (pve.pve_start <= ip && pve.pve_end >= ip)
			return (1);
	}
}

static void
backtrace_lwp(unw_addr_space_t as, void *ui, int pid, lwpid_t lwpid)
{
	char buf[PATH_MAX];
	char *p;
	unw_cursor_t c;
	unw_word_t arg, ip, start_ip, off;
	size_t len;
	int i, frame_no, ret;

	printf("Thread %d:\n", lwpid);
	ret = unw_init_remote(&c, as, ui);
	if (ret < 0) {
		if (verbose) {
			warnx("unw_init_remote() failed, %s",
			    unw_strerror(ret));
		}
		return;
	}

	frame_no = 0;
	start_ip = 0; /* shut down compiler */
	do {
		if (frame_count >= 0 && frame_no >= frame_count)
			break;

		ret = unw_get_reg(&c, UNW_REG_IP, &ip);
		if (ret < 0) {
			if (verbose) {
				warnx("unw_get_reg(UNW_REG_IP) failed, %s",
				    unw_strerror(ret));
			}
			return;
		}
		if (frame_no == 0)
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
		printf (" 0x%0lx %s", (long)ip, buf);
		if (show_obj || show_obj_full) {
			if (!get_obj_path(pid, ip, buf, sizeof(buf)))
				strcpy(buf, "????????");
			if (show_obj_full)
				p = buf;
			else {
				p = strrchr(buf, '/');
				if (p == NULL)
					p = buf;
				else
					p++;
			}
			printf(" in %s", p);
		}
		if (arg_count > 0) {
			printf("(");
			for (i = 0; i < arg_count; i++) {
				if (i > 0)
					printf(", ");
				if (pstack_get_arg(as, ui, &c, i, &arg))
					printf("0x%lx", (long)arg);
				else
					printf("??");
			}
			printf(")");
		}
		printf("\n");

		ret = unw_step(&c);
		if (ret < 0) {
			unw_get_reg(&c, UNW_REG_IP, &ip);
			if (ip == 0)
				break;
			if (verbose) {
				warnx(
		    "unw_step() error for ip %0lx/start ip %0lx, %s",
		    (long)ip, (long)start_ip, unw_strerror(ret));
			}
			return;
		}
		frame_no++;
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
detach(pid_t pid)
{

	ptrace(PT_DETACH, pid, (caddr_t)1, 0);
	if (show_susp_time)
		clock_gettime(CLOCK_REALTIME_PRECISE, &susp_end);
}

static void
backtrace_proc(pid_t pid)
{
	lwpid_t *lwpids;
	unw_addr_space_t as;
	struct UPT_info *ui;
	int error, i, lwpnums, status;

	if (show_susp_time)
		clock_gettime(CLOCK_REALTIME_PRECISE, &susp_start);
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
		detach(pid);
		errc(1, error, "Error getting the number of lwps");
	}
	lwpnums = error;
	lwpids = calloc(lwpnums, sizeof(lwpid_t));
	if (lwpids == NULL) {
		error = errno;
		detach(pid);
		errc(1, error, "Error getting the number of lwps");
	}
	error = ptrace(PT_GETLWPLIST, pid, (caddr_t)lwpids, lwpnums *
	    sizeof(lwpid_t));
	if (error == -1) {
		error = errno;
		detach(pid);
		errc(1, error, "Error getting the lwp list");
	}
	assert(lwpnums == error);
	lwpnums = error;
	
	as = unw_create_addr_space(&_UPT_accessors, 0);
	if (as == NULL) {
		detach(pid);
		errx(1, "unw_create_addr_space() failed");
	}

	for (i = 0; i < lwpnums; i++) {
		ui = _UPT_create(lwpids[i]);
		backtrace_lwp(as, ui, pid, lwpids[i]);
		_UPT_destroy(ui);
	}

	unw_destroy_addr_space(as);
	detach(pid);
}

static void
usage(void)
{

	errx(2,
"usage: pstack [-a arg_count] [-f frame_count] [-o] [-O] [-t] [-v] pid");
}

int
main(int argc, char **argv)
{
	int c, target_pid;

	while ((c = getopt(argc, argv, "a:f:oOt")) != -1) {
		switch (c) {
		case 'a':
			arg_count = atoi(optarg);
			if (arg_count < 0 || arg_count > 6)
				errx(1,
				    "Argument count should be between 0 and 6");
			break;
		case 'f':
			frame_count = atoi(optarg);
			break;
		case 'o':
			show_obj = 1;
			show_obj_full = 0;
			break;
		case 'O':
			show_obj = 0;
			show_obj_full = 1;
			break;
		case 't':
			show_susp_time = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();
	target_pid = atoi(argv[0]);
	if (target_pid == 0) {
		/* XXXKIB core support */
		usage();
	}

	backtrace_proc(target_pid);
	if (show_susp_time) {
		timespecsub(&susp_end, &susp_start);
		printf("Target was suspended for %f sec\n",
		    (double)susp_end.tv_sec + susp_end.tv_nsec / 1000000000.);
	}
	return (0);
}
