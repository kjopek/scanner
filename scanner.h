#ifndef SCANNER_H
#define SCANNER_H

#include "scanner_hash.h"

void scanner_vmregion_hash(pid_t pid, struct kinfo_vmentry *vmentry, scanner_hash_func hash_func);
void scanner_proc_info(struct procstat *procstat_handler, struct kinfo_proc *kproc, scanner_hash_func hash_func);


typedef struct {
    char              initial[64];
    scanner_hash_func func;
} scanner_properties;

#endif /* SCANNER_H */
