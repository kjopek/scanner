#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include <unistd.h>
#include <fcntl.h>
#include <libprocstat.h>
#include <kvm.h>
#include "scanner.h"
#include "scanner_hash.h"

void scanner_vmregion_hash(pid_t pid, struct kinfo_vmentry *vmentry, scanner_hash_func hash_func)
{
    int pagesize = sysconf(_SC_PAGESIZE);
    uint64_t tail;
    void *mem;
    scanner_hash *hash;
    struct ptrace_io_desc io_desc;

    mem = malloc(pagesize);

    if (mem == NULL) {
        return ;
    }

    scanner_hash_init(&hash, hash_func);

    io_desc.piod_len = pagesize;
    io_desc.piod_offs = (void*) vmentry->kve_start;
    io_desc.piod_addr = mem;
    io_desc.piod_op = PT_READ_I;

    do {
        ptrace(PT_IO, pid, (caddr_t) &io_desc, 0);
        scanner_hash_update(hash, io_desc.piod_addr, pagesize);
        io_desc.piod_offs += pagesize;
    } while ((uint64_t) io_desc.piod_offs < vmentry->kve_end);

    tail = (vmentry->kve_end - vmentry->kve_start) % pagesize;

    if (tail > 0) {
        io_desc.piod_offs += tail;
        io_desc.piod_len = tail;
        ptrace(PT_IO, pid, (caddr_t) &io_desc, 0);
        scanner_hash_update(hash, io_desc.piod_addr, tail);
    }

    scanner_hash_final(hash);

    printf("%-16lx\t%-16lx\t[%8lu]\t",
           vmentry->kve_start,
           vmentry->kve_end,
           vmentry->kve_end - vmentry->kve_start);

    for (int i=0; i<hash->digest_size; ++i) {
        printf("%02x", hash->hash[i]);
    }

    if (vmentry->kve_path) {
        printf(" %s\n", vmentry->kve_path);
    }
    else
        printf("\n");

    scanner_hash_free(hash);
    free(mem);
}

void scanner_proc_info(struct procstat *procstat_handler, struct kinfo_proc *kproc)
{
    struct kinfo_vmentry *vmentry;
    unsigned int vmentry_count;

    vmentry = procstat_getvmmap(procstat_handler, kproc, &vmentry_count);

    if (vmentry == NULL) {
        perror("procstat_getvmmap");
        procstat_freevmmap(procstat_handler, vmentry);
        return ;
    }

    printf("Pid: %u | vm_size: %lu | rss_size: %lu | command: %s\n", kproc->ki_pid,
           kproc->ki_size, kproc->ki_rssize*sysconf(_SC_PAGESIZE), kproc->ki_tdname);

    int check_mask = KVME_PROT_READ | KVME_PROT_WRITE | KVME_PROT_EXEC;
    int result_mask = KVME_PROT_READ | KVME_PROT_EXEC;

    for (unsigned int j = 0; j<vmentry_count; ++j) {
        if ((vmentry[j].kve_protection & check_mask) == result_mask)
            scanner_vmregion_hash(kproc->ki_pid, &vmentry[j], SCANNER_HASH_SHA256);
    }
    procstat_freevmmap(procstat_handler, vmentry);
}

int main(int argc, char **argv)
{
    pid_t pid = 0;
    struct procstat *procstat_handler = NULL;
    struct kinfo_proc *kinfo_proc_handler = NULL;
    unsigned int nprocs = 0;
    
    if (argc == 2) {
        pid = atol(argv[1]);
    }

    if ((procstat_handler = procstat_open_sysctl()) == NULL) {
        perror("pstat");
    }
    
    if (pid == 0)
        kinfo_proc_handler = procstat_getprocs(procstat_handler, KERN_PROC_PROC, 0, &nprocs);
    else
        kinfo_proc_handler = procstat_getprocs(procstat_handler, KERN_PROC_PID, pid, &nprocs);

    for (unsigned int i = 0; i<nprocs; ++i) {
        scanner_proc_info (procstat_handler, &kinfo_proc_handler[i]);
    }

    procstat_freeprocs(procstat_handler, kinfo_proc_handler);
    procstat_close(procstat_handler);
    
    return 0;
}
