#ifndef ELFS_H
#define ELFS_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/limits.h>

#include <pthread.h>
#include <elf.h>

#include "fs-structs.h"
#include "list.h"

struct self_ctx;


typedef struct {
        char *buf;
        size_t buf_len;
} telf_default_content;


typedef telf_status (* tobj_getsize_func)(void *, size_t *);
typedef telf_status (* tobj_setcontent_func)(void *, char **, size_t *);
typedef void (* tobj_freecontent_func)(void *);


typedef struct self_obj {
        telf_fs_driver *driver;  /* set of fs callbacks */

        tobj_setcontent_func fill_func;
        tobj_freecontent_func free_func;

        struct self_ctx *ctx;    /* global context */
        struct self_obj *parent; /* equivalent to ".." */

        char *name;              /* entry name */
        void *data;              /* a pointer to the symbol for example */
        telf_type type;          /* type of elf object */
        telf_stat st;            /* our own struct stat */
        tlist *entries;          /* if directory: list of entries */

        pthread_mutex_t lock;
} telf_obj;

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
        int n_syms;
        char *strtab;           /* string table */

        Elf64_Sym *dsymtab;     /* dynamic symbol table */
        int n_dsyms;
        char *dstrtab;          /* dynamic string table */

        telf_obj *root;         /* fs entry point: root directory */
} telf_ctx;


telf_obj *elf_obj_new(telf_ctx *, char *, telf_obj *, telf_type, telf_ftype);
void elf_obj_free(telf_obj *obj);
void elf_obj_lock(telf_obj *obj);
void elf_obj_unlock(telf_obj *obj);
#endif /* ELFS_H */
