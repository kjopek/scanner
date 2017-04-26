#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/ptrace.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <kvm.h>
#include <libprocstat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "scanner.h"
#include "scanner_hash.h"
#include "scanner_dump.h"

static struct option opts[] = {
	{"hash", required_argument, NULL, 'h'},
	{"help", no_argument, NULL, 'Z'},
	{"init", required_argument, NULL, 'i'},
	{"output", required_argument, NULL, 'o'},
	{"pid", required_argument, NULL, 'p'},
	{NULL, 0, NULL, 0}
};

void
usage(void)
{

	printf("Usage: scanner [--pid <pid>] [--hash (MD5|SHA256|SHA512)]\n");
	exit(1);
}

void
ptrace_err(int ret)
{

	if (ret != 0 && errno != 0)
		err(1, "ptrace(2) failed");
}

void
scanner_vmregion_hash(pid_t pid, struct kinfo_vmentry *vmentry,
	scanner_hash_func hash_func)
{
	int pagesize, i, error, options, status;
	uint64_t tail;
	void *mem;
	scanner_hash *hash;
	struct ptrace_io_desc io_desc;

	pagesize = sysconf(_SC_PAGESIZE);
	mem = malloc(pagesize);

	if (mem == NULL)
		err(1, "malloc(3) failed");

	scanner_hash_init(&hash, hash_func);

	error = ptrace(PT_ATTACH, pid, NULL, 0);
	//wait(&status);
	wait4(pid, &status, WSTOPPED | WTRAPPED, NULL);
	ptrace_err(error);

	if (!WIFSTOPPED(status))
		err(1, "process is not stopped");

	io_desc.piod_len = pagesize;
	io_desc.piod_offs = (void *)vmentry->kve_start;
	io_desc.piod_addr = mem;
	io_desc.piod_op = PT_READ_I;

	do {
		error = ptrace(PT_IO, pid, (caddr_t)&io_desc, 0);
		ptrace_err(error);
		scanner_hash_update(hash, io_desc.piod_addr, pagesize);
		io_desc.piod_offs += pagesize;
	} while ((uint64_t)io_desc.piod_offs < vmentry->kve_end);

	tail = (vmentry->kve_end - vmentry->kve_start) % pagesize;

	if (tail > 0) {
		io_desc.piod_offs += tail;
		io_desc.piod_len = tail;
		error = ptrace(PT_IO, pid, (caddr_t)&io_desc, 0);
		ptrace_err(error);
		scanner_hash_update(hash, io_desc.piod_addr, tail);
	}

	error = ptrace(PT_DETACH, pid, NULL, 0);
	wait4(pid, &status, WCONTINUED | WUNTRACED | WEXITED, NULL);
	ptrace_err(error);
	scanner_hash_final(hash);

	printf("%-16lx\t%-16lx\t[%8lu]\t0x%x\t%x\t", vmentry->kve_start,
	    vmentry->kve_end, vmentry->kve_end - vmentry->kve_start,
	    vmentry->kve_protection, vmentry->kve_type);

	for (i = 0; i < hash->digest_size; ++i)
		printf("%02x", hash->hash[i]);

	printf(" %s\n", vmentry->kve_path);

	scanner_hash_free(hash);
	free(mem);
}

void
scanner_proc_info(struct procstat *procstat_handler, struct kinfo_proc *kproc,
	scanner_hash_func hash_func)
{
	struct kinfo_vmentry *vmentry;
	unsigned int vmentry_count;
	unsigned int j;
	int check_mask;
	int result_mask;

	vmentry = procstat_getvmmap(procstat_handler, kproc, &vmentry_count);

	if (vmentry == NULL) {
		perror("procstat_getvmmap");
		procstat_freevmmap(procstat_handler, vmentry);
		return;
	}

	printf("Pid: %u | vm_size: %lu | rss_size: %lu | command: %s\n",
	    kproc->ki_pid, kproc->ki_size,
	    kproc->ki_rssize * sysconf(_SC_PAGESIZE), kproc->ki_tdname);

	check_mask = KVME_PROT_READ; //| KVME_PROT_WRITE | KVME_PROT_EXEC;
	result_mask = KVME_PROT_READ; //| KVME_PROT_EXEC;

	for (j = 0; j < vmentry_count; ++j) {
		if ((vmentry[j].kve_protection & check_mask) == result_mask) {
			scanner_vmregion_hash(kproc->ki_pid, &vmentry[j],
			    hash_func);
		}
	}

	procstat_freevmmap(procstat_handler, vmentry);
}

int
main(int argc, char **argv)
{
	pid_t pid;
	int ch;
	unsigned int nprocs;
	unsigned int i;
	scanner_hash_func hash_func;
	struct procstat *procstat_handler;
	struct kinfo_proc *kinfo_proc_handler;
	char *output_file;
	int retval = 0;

	pid = 0;
	procstat_handler = NULL;
	kinfo_proc_handler = NULL;
	nprocs = 0;
	hash_func = SCANNER_HASH_MD5;
	output_file = NULL;

	while ((ch = getopt_long(argc, argv, "h:o:p:Z", opts, NULL)) != -1) {
		switch(ch) {
		case 'h':
			if (strcmp("MD5", optarg) == 0) {
				hash_func = SCANNER_HASH_MD5;
			} else if (strcmp("SHA256", optarg) == 0) {
				hash_func = SCANNER_HASH_SHA256;
			} else if (strcmp("SHA512", optarg) == 0) {
				hash_func = SCANNER_HASH_SHA512;
			} else {
				fprintf(stderr, "Unknown hash function: %s.\n",
					optarg);
				usage();
			}
			break;
		case 'o':
			output_file = optarg;
			break;
		case 'p':
			pid = atoi(optarg);
			break;
		case 'Z':
			usage();
		}
	}

	if (output_file != NULL && pid == 0) {
		fprintf(stderr, "Option output does not work with multiple\
		    processes!\n");
		return (1);
	}

	procstat_handler = procstat_open_sysctl();

	if (procstat_handler == NULL) {
		perror("pstat");
		return (1);
	}

	if (pid == 0) {
		kinfo_proc_handler = procstat_getprocs(procstat_handler,
		    KERN_PROC_PROC, pid, &nprocs);
	} else {
		kinfo_proc_handler = procstat_getprocs(procstat_handler,
		    KERN_PROC_PID, pid, &nprocs);
	}

	if (output_file == NULL) {
		for (i = 0; i<nprocs; ++i) {
			scanner_proc_info(procstat_handler,
			    &kinfo_proc_handler[i], hash_func);
		}
	} else {
		retval = scanner_dump_proc(procstat_handler,
		    &kinfo_proc_handler[0], output_file);
	}

	procstat_freeprocs(procstat_handler, kinfo_proc_handler);
	procstat_close(procstat_handler);

	return (retval);
}
