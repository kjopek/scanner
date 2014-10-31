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

void scanner_vmregion_hash(pid_t pid, struct kinfo_vmentry *vmentry)
{
    int data = 0;
    unsigned char digest[32];
    SHA256_CTX context;

    uint64_t ptr = vmentry->kve_start;

    SHA256_Init(&context);

    while (ptr < vmentry->kve_end) {
        data = ptrace(PT_READ_D, pid, (caddr_t) ptr, 0);
        SHA256_Update(&context, (unsigned char*) &data, sizeof(data));
        ptr += sizeof (data);
    }

    SHA256_Final(digest, &context);
    printf("  0x%016lx - 0x%016lx: ", vmentry->kve_start, vmentry->kve_end);

    for (int i=0; i<sizeof(digest); ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

void scanner_proc_info(struct procstat *procstat_handler, struct kinfo_proc *kproc)
{
    struct kinfo_vmentry *vmentry;
    unsigned int vmentry_count;

    vmentry = procstat_getvmmap(procstat_handler, kproc, &vmentry_count);

    if (vmentry == NULL) {
        perror("procstat_getvmmap");
        return ;
    }

    printf("Pid: %u", kproc->ki_pid);
    printf(" vm_size: %lu | rss_size: %lu", kproc->ki_size, kproc->ki_rssize);
    printf(" command: %s\n", kproc->ki_comm);

    for (unsigned int j = 0; j<vmentry_count; ++j) {
        if ((vmentry[j].kve_protection & KVME_PROT_WRITE) == 0 &&
             (vmentry[j].kve_type == KVME_TYPE_DEFAULT ||
              vmentry[j].kve_type == KVME_TYPE_PHYS))
            scanner_vmregion_hash(kproc->ki_pid, &vmentry[j]);
    }
    procstat_freevmmap(procstat_handler, vmentry);
}

int main(int argc, char ** argv)
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
