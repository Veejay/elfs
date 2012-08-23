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

#define MAP(v) X(v, #v)
#define ELF_TYPES_TABLE                                 \
        MAP(ELF_SECTION_NULL)                           \
        MAP(ELF_SECTION_PROGBITS)                       \
        MAP(ELF_SECTION_PROGBITS_CODE)                  \
        MAP(ELF_SECTION_SYMTAB)                         \
        MAP(ELF_SECTION_STRTAB)                         \
        MAP(ELF_SECTION_RELA)                           \
        MAP(ELF_SECTION_HASH)                           \
        MAP(ELF_SECTION_DYNAMIC)                        \
        MAP(ELF_SECTION_NOTE)                           \
        MAP(ELF_SECTION_NOBITS)                         \
        MAP(ELF_SECTION_REL)                            \
        MAP(ELF_SECTION_SHLIB)                          \
        MAP(ELF_SECTION_DYNSYM)                         \
        MAP(ELF_SECTION_INIT_ARRAY)                     \
        MAP(ELF_SECTION_FINI_ARRAY)                     \
        MAP(ELF_SECTION_PREINIT_ARRAY)                  \
        MAP(ELF_SECTION_GROUP)                          \
        MAP(ELF_SECTION_SYMTAB_SHNDX)                   \
        MAP(ELF_SECTION_NUM)                            \
        MAP(ELF_SECTION_LOOS)                           \
        MAP(ELF_SECTION_GNU_ATTRIBUTES)                 \
        MAP(ELF_SECTION_GNU_HASH)                       \
        MAP(ELF_SECTION_GNU_LIBLIST)                    \
        MAP(ELF_SECTION_CHECKSUM)                       \
        MAP(ELF_SECTION_LOSUNW)                         \
        MAP(ELF_SECTION_SUNW_move)                      \
        MAP(ELF_SECTION_SUNW_COMDAT)                    \
        MAP(ELF_SECTION_SUNW_syminfo)                   \
        MAP(ELF_SECTION_GNU_verdef)                     \
        MAP(ELF_SECTION_GNU_verneed)                    \
        MAP(ELF_SECTION_GNU_versym)                     \
        MAP(ELF_SECTION_HISUNW)                         \
        MAP(ELF_SECTION_HIOS)                           \
        MAP(ELF_SECTION_LOPROC)                         \
        MAP(ELF_SECTION_HIPROC)                         \
        MAP(ELF_SECTION_LOUSER)                         \
        MAP(ELF_SECTION_HIUSER)                         \
        MAP(ELF_SECTION_OTHER)                          \
        MAP(ELF_SECTION)                                \
        MAP(ELF_SYMBOL)                                 \
        MAP(ELF_SYMBOL_ENTRY)                           \
        MAP(ELF_ROOTDIR)

#define X(a, b) a,
typedef enum {
        ELF_TYPES_TABLE
} telf_type;
#undef X
#undef MAP

struct self_ctx;


typedef struct {
        char *buf;
        size_t buf_len;
} telf_default_content;

typedef telf_status (* tobj_setcontent_func)(void *, char **, size_t *);


typedef struct self_obj {
        telf_fs_driver *driver;  /* set of fs callbacks */

        tobj_setcontent_func fill;

        struct self_ctx *ctx;    /* global context */
        struct self_obj *parent; /* equivalent to ".." */

        char *name;              /* entry name */
        void *data;              /* a pointer to the symbol for example */
        telf_type type;          /* type of elf object */
        telf_ftype ftype;        /* regular file or directoy? */
        telf_stat st;            /* our own struct stat */
        tlist *entries;          /* if directory: list of entries */
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
        Elf64_Sym *symtab_end;  /* end of symbol table (symtab + size) */
        int n_syms;
        char *strtab;           /* string table */

        Elf64_Sym *dsymtab;     /* dynamic symbol table */
        Elf64_Sym *dsymtab_end; /* end of dynamic symbol table (dsymtab + size) */
        int n_dsyms;
        char *dstrtab;          /* dynamic string table */

        telf_obj *root;         /* fs entry point: root directory */
} telf_ctx;


telf_obj *elf_obj_new(telf_ctx *, char *, telf_obj *, telf_type, telf_ftype);

#endif /* ELFS_H */
