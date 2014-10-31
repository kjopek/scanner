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

int scanner_hash_init(scanner_hash ** hash, scanner_hash_func func)
{
    *hash = (scanner_hash*) malloc(sizeof(scanner_hash));

    if (*hash == NULL) {
        return -1;
    }

    switch (func) {
    case SCANNER_HASH_MD5:
        MD5Init(&((*hash)->scanner_hash_context.md5_ctx));
        (*hash)->digest_size = MD5_DIGEST_LENGTH;
        break;
    case SCANNER_HASH_SHA256:
        SHA256_Init(&((*hash)->scanner_hash_context.sha256_ctx));
        (*hash)->digest_size = 256/8;
        break;
    case SCANNER_HASH_SHA512:
        SHA512_Init(&((*hash)->scanner_hash_context.sha512_ctx));
        (*hash)->digest_size = 512/8;
        break;
    }

    (*hash)->hash_func = func;
    return 0;
}

void scanner_hash_update(scanner_hash *hash, const char *data, size_t len)
{
    switch (hash->hash_func) {
    case SCANNER_HASH_MD5:
        MD5Update(&hash->scanner_hash_context.md5_ctx, (const void*) data, len);
        break;
    case SCANNER_HASH_SHA256:
        SHA256_Update(&hash->scanner_hash_context.sha256_ctx, (const void*) data, len);
        break;
    case SCANNER_HASH_SHA512:
        SHA512_Update(&hash->scanner_hash_context.sha512_ctx, (const void*) data, len);
        break;
    }
}

void scanner_hash_final(scanner_hash *hash)
{
    hash->hash = (unsigned char*) malloc(hash->digest_size);
    switch (hash->hash_func) {
    case SCANNER_HASH_MD5:
        MD5Final(hash->hash, &hash->scanner_hash_context.md5_ctx);
        break;
    case SCANNER_HASH_SHA256:
        SHA256_Final(hash->hash, &hash->scanner_hash_context.sha256_ctx);
        break;
    case SCANNER_HASH_SHA512:
        SHA512_Final(hash->hash, &hash->scanner_hash_context.sha512_ctx);
        break;
    }
}

void scanner_hash_free(scanner_hash *hash)
{
    free(hash->hash);
    free(hash);
}

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
    printf("%-16lx %-16lx [%-20lu]: ",
           vmentry->kve_start,
           vmentry->kve_end,
           vmentry->kve_end - vmentry->kve_start);

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
        if ((vmentry[j].kve_protection & (KVME_PROT_READ | KVME_PROT_WRITE | KVME_PROT_EXEC))
                == (KVME_PROT_READ | KVME_PROT_EXEC))
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
