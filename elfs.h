#ifndef ELFS_H
#define ELFS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#include <pthread.h>
#include <elf.h>

#include "list.h"

typedef struct self_ctx {
        int loglevel;
        pthread_mutex_t mutex;
        struct stat st;
        char path[PATH_MAX];
        unsigned char *addr;

        unsigned char class;    /* ELFCLASS32 or ELFCLASS64 */
        Elf64_Ehdr *ehdr;       /* elf header */
        Elf64_Shdr *shdr;       /* sections header */
        int n_sections;         /* number of sections */

        Elf64_Sym *symtab;      /* symbol table */
        Elf64_Sym *symtab_end;  /* end of symbol table (symtab + size) */
        int n_syms;
        char *strtab;           /* string table */

        Elf64_Sym *dsymtab;     /* dynamic symbol table */
        Elf64_Sym *dsymtab_end; /* end of dynamic symbol table (dsymtab + size) */
        int n_dsyms;
        char *dstrtab;          /* dynamic string table */

        tlist *root; /* list of symbols */
} telf_ctx;

#endif /* ELFS_H */
