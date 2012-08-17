#include <limits.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sys/statvfs.h>
#include <libgen.h>
#include <sys/mman.h>
#include <stdlib.h>

#include <sys/ptrace.h>

#define SYSLOG_NAMES
#include <syslog.h>

#define FUSE_USE_VERSION 29
#include <fuse.h>

#include "elfs.h"
#include "misc.h"

int loglevel = LOG_ERR;

#if 1
#define LOG(level, err, fmt, ...) do {                                  \
                if (level > loglevel) continue;                         \
                                                                        \
                if (err)                                                \
                        syslog(level, "%s %s:%d "fmt ": %s",            \
                               __FILE__, __func__, __LINE__,            \
                               ##__VA_ARGS__, strerror(errno));         \
                else                                                    \
                        syslog(level, "%s %s:%d "fmt "",                \
                               __FILE__, __func__, __LINE__,            \
                                ##__VA_ARGS__);                         \
                                                                        \
        } while (0)
#else
#define LOG
#endif

#define N_ELEMS(x) (sizeof x / sizeof x[0])

telf_ctx *ctx = NULL;

#define MAP(v) X(v, #v)
#define ELF_TYPES_TABLE                                 \
        MAP(ELF_SECTION_NULL)                           \
        MAP(ELF_SECTION_PROGBITS)                       \
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

#define X(a, b) b,
char *elf_type_names[] = {
        ELF_TYPES_TABLE
};
#undef X
#undef MAP

typedef enum {
        ELF_S_IFDIR,
        ELF_S_IFREG,
} telf_ftype;

#define ELF_S_ISDIR(mode) ((mode) == ELF_S_IFDIR)
#define ELF_S_ISREG(mode) ((mode) == ELF_S_IFREG)

typedef struct {
        size_t st_size;
        telf_ftype st_mode;
} telf_stat;

static char *
elf_type_to_str(telf_type type)
{
        return elf_type_names[type];
}

typedef struct self_obj {
        void *driver;            /* set of callbacks */
        struct self_obj *parent; /* equivalent to ".." */

        char *name;              /* entry name */
        void *data;              /* a pointer to the symbol for example */
        telf_type type;          /* type of elf object */
        telf_stat st;            /* our own struct stat */
        tlist *entries;          /* if directory: list of entries */
} telf_obj;

typedef int (* telf_read_func)(telf_obj *, char *, size_t, off_t);
typedef int (* telf_write_func)(telf_obj *, char *, size_t, off_t);

typedef struct {
        char *content;
        size_t content_len;
        telf_read_func read;
        telf_write_func write;
} telf_filehdl_driver;

static int
elf_obj_read_func(telf_obj *obj,
                  char *buf,
                  size_t len,
                  off_t offset)
{
        telf_filehdl_driver *driver = obj->driver;

        if (len > driver->content_len)
                len = driver->content_len;

        memcpy(buf, driver->content + offset, len);

        return len;
}

static int
elf_obj_write_func(telf_obj *obj,
                   char *buf,
                   size_t buf_len,
                   off_t offset)
{
        return 0;
}

static telf_filehdl_driver obj_driver = {
        .content = NULL,
        .content_len = 0,
        .read = elf_obj_read_func,
        .write = elf_obj_write_func,
};

#define INFO_FMT             \
        "num: %d\n"          \
        "value: 0x%p\n"      \
        "size: %zu\n"        \
        "type: %s\n"         \
        "bind: %s\n"         \
        "vis: %c\n"          \
        "ndx: %s\n"          \
        "name: %s\n"

static int
elf_filehdl_set_content(telf_obj *obj)
{
        telf_filehdl_driver *driver = obj->driver;
        int ret;
        Elf64_Sym *sym = obj->data;

        // sanity check
        if (driver->content) {
                free(driver->content);
                driver->content = NULL;
        }

        driver->content = malloc(1024);
        if (! driver->content) {
                LOG(LOG_CRIT, 1, "malloc");
                ret = -1;
                goto end;
        }

        driver->content_len = sprintf(driver->content, INFO_FMT,
                                      0, // num
                                      sym ? sym : NULL,
                                      sym ? sym->st_size : 0u,
                                      sym_type_to_str(sym),
                                      sym_bind_to_str(sym),
                                      sym ? sym->st_other : 0u,
                                      "none", // ndx
                                      obj->name);

        ret = 0;
  end:
        return ret;
}

static int
elf_obj_set_content_code_func(telf_obj *obj,
                              char **bufp,
                              size_t *buf_lenp)
{
        return 0;
}

static int
elf_obj_set_content_info_func(telf_obj *obj,
                              char **bufp,
                              size_t *buf_lenp)
{
        int ret;
        telf_filehdl_driver *driver = obj->driver;
        char *buf;
        size_t buf_len;
        static const buf_size = 4096;
        Elf64_Sym *sym = obj->data;

        buf = malloc(buf_size);
        if (! buf) {
                LOG(LOG_CRIT, 1, "malloc");
                ret = -1;
                goto end;
        }

        buf_len = snprintf(buf, buf_size, INFO_FMT,
                           0, // num
                           sym ? sym : NULL,
                           sym ? sym->st_size : 0u,
                           sym_type_to_str(sym),
                           sym_bind_to_str(sym),
                           sym ? sym->st_other : 0u,
                           "none", // ndx
                           obj->name);

        ret = 0;
  end:

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

typedef int (* tobj_set_content_func)(telf_obj *, char **, size_t *);

struct {
        char *str;
        tobj_set_content_func set_content_func;
} e_names[] = {
        { .str = "code", .set_content_func = elf_obj_set_content_code_func },
        { .str = "info", .set_content_func = elf_obj_set_content_info_func },
};

elf_obj_free(telf_obj *obj)
{
        if (obj) {
                if (obj->name)
                        free(obj->name);

                if (obj->entries)
                        list_free(obj->entries);

                free(obj);
        }
}

static void
elf_obj_free_func(void *value)
{
        elf_obj_free((telf_obj *) value);
}

static int
elf_obj_cmp_func(void *key_,
                 void *elem_)
{
        char *key = key_;
        telf_obj *elem = elem_;

        LOG(LOG_DEBUG, 0, "compare key=%s to entry->name=%s", key, elem->name);

        return strcmp(key, elem->name);
}

static int
elf_obj_set_content(telf_obj *obj,
                    char **bufp,
                    size_t *buf_lenp)
{
        int i;
        int rc;
        int ret;

        /* for directories, we let their size be 0 */
        if (ELF_S_ISDIR(obj->st.st_mode))
                return;

        for (i = 0; i < N_ELEMS(e_names); i++) {
                if (0 == strcmp(obj->name, e_names[i].str)) {
                        rc = e_names[i].set_content_func(obj, bufp, buf_lenp);
                        if (-1 == rc) {
                                ret = -1;
                                goto end;
                        }

                        break;
                }
        }

        ret = 0;
  end:

        return ret;
}

static telf_obj *
elf_obj_new(char *path,
            telf_obj *parent,
            telf_type type)
{
        telf_obj *obj = NULL;
        Elf64_Sym *sym = NULL;

        LOG(LOG_DEBUG, 0, "build object: path=%s, parent=%p, type=%s",
            path, (void *) parent, elf_type_to_str(type));

        obj = malloc(sizeof *obj);
        if (! obj) {
                LOG(LOG_CRIT, 1, "malloc");
                goto err;
        }

        memset(obj, 0, sizeof *obj);

        obj->name = strdup(path);
        if (! obj->name) {
                LOG(LOG_CRIT, 1, "strdup(%s)", path);
                goto err;
        }

        obj->parent = parent;
        obj->type = type;

        switch (obj->type) {
        case ELF_SYMBOL_ENTRY:
                obj->driver = &obj_driver;
                obj->st.st_mode = ELF_S_IFREG;
                break;
        default:
                obj->st.st_mode = ELF_S_IFDIR;
                break;
        }

        elf_obj_set_content(obj, NULL, &obj->st.st_size);

        return obj;

  err:
        elf_obj_free(obj);
        return NULL;
}

static void
elf_ctx_free(telf_ctx *ctx)
{
        if (ctx) {
                if (ctx->addr)
                        (void) munmap((void *) ctx->addr, ctx->st.st_size);

                if (ctx->root)
                        list_free(ctx->root);

                free(ctx);
        }
}

static int
elf_sanity_check(unsigned char *addr)
{
        int ret;

        if (strncmp(addr, ELFMAG, SELFMAG)) {
                LOG(LOG_ERR, 0, "bad magic: %*s", SELFMAG, addr);
                ret = -1;
                goto end;
        }

        if (ELFCLASSNONE == addr + EI_CLASS) {
                LOG(LOG_ERR, 0, "bad elf class %c", addr[EI_CLASS]);
                ret = -1;
                goto end;
        }

        ret = 0;
  end:
        return ret;
}

static int
elf_mmap_internal(telf_ctx *ctx)
{
        int fd = -1;
        int ret;
        int rc;
        void *addr = NULL;

        fd = open(ctx->path, 0600, O_RDONLY);
        if (-1 == fd) {
                LOG(LOG_ERR, 1, "open '%s' failed", ctx->path);
                ret = -1;
                goto err;
        }

        addr = mmap(NULL, ctx->st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (MAP_FAILED == addr) {
                LOG(LOG_ERR, 1, "mmap");
                ret = -1;
                goto err;
        }

        ctx->addr = (unsigned char *) addr;

        rc = elf_sanity_check(ctx->addr);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "sanity checks failed");
                ret = -1;
                goto err;
        }

        ctx->class = ctx->addr[EI_CLASS];

        LOG(LOG_DEBUG, 0, "class=%s",
            (ELFCLASS32 == ctx->class) ? "ELFCLASS32":"ELFCLASS64");

        ctx->ehdr = (Elf64_Ehdr *) addr;
        ctx->shdr = (Elf64_Shdr *) (ctx->addr + ctx->ehdr->e_shoff);

        LOG(LOG_DEBUG, 0, "elf hdr: %p", addr);

        ret = 0;
  err:

        if (-1 != fd)
                (void) close(fd);

        return ret;
}

static int
elf_namei(telf_ctx *ctx,
          char *path,
          telf_obj **objp)
{
        int ret;
        telf_obj *obj = NULL;
        telf_obj *parent = NULL;
        char *p = NULL;
        char *start = NULL;
        char *current = NULL;

        LOG(LOG_DEBUG, 0, "path=%s", path);

        p = path;

        if (0 == strcmp(path, "/")) {
                obj = list_get(ctx->root, "/");
                if (! obj) {
                        ret = -1;
                        goto end;
                }

                /* success, we got the root dir */
                ret = 0;
                goto end;
        }

        while ('/' == *p)
                p++;

        parent = list_get(ctx->root, "/");
        if (! parent) {
                ret = -1;
                goto end;
        }

        while (p) {

                while ('/' == *p)
                        p++;

                start = p;

                while (p && *p && '/' != *p)
                        p++;

                current = strndupa(start, (size_t) (p - start));
                if (! current) {
                        LOG(LOG_CRIT, 1, "strndupa");
                        ret = -1;
                        goto end;
                }


                if (! parent->entries) {
                        LOG(LOG_DEBUG, 0, "%s not found", current);
                        ret = -1;
                        goto end;
                }

                obj = list_get(parent->entries, current);
                if (! obj) {
                        LOG(LOG_DEBUG, 0, "%s not found", current);
                        ret = -1;
                        goto end;
                }

                /* end of the path */
                if (NULL == p || 0 == *p)
                        break;

                parent = obj;
        }

  end:
        if (objp)
                *objp = obj;

        if (obj)
                LOG(LOG_DEBUG, 0, "file obj name found: %s", obj->name);
        else
                LOG(LOG_DEBUG, 0, "file obj name not found");

        return ret;
}

static int
elf_build_rootdir(telf_ctx *ctx)
{
        int ret;

        telf_obj *root_obj = elf_obj_new("/", NULL, ELF_ROOTDIR);
        if (! root_obj) {
                ret = -1;
                goto end;
        }

        root_obj->entries = list_new();
        list_set_free_func(root_obj->entries, elf_obj_free_func);
        list_set_cmp_func(root_obj->entries, elf_obj_cmp_func);

        telf_obj *sections_obj = elf_obj_new("sections", root_obj, ELF_SECTION);
        if (! sections_obj) {
                ret = -1;
                goto end;
        }

        list_add(root_obj->entries, sections_obj);

        /* and finally, we add the entries in the rootdir */
        list_add(ctx->root, root_obj);

        ret = 0;
  end:
        return ret;
}

static int
elf_build_sections(telf_ctx *ctx)
{
        int ret;
        int rc;
        int i;
        telf_obj *sections_obj = NULL;

        Elf64_Shdr *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        rc = elf_namei(ctx, "/sections", &sections_obj);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "can't find any section entry");
                ret = -1;
                goto end;
        }

        ctx->n_sections = ctx->ehdr->e_shnum;

        if (! ctx->n_sections)
                return 0;

        sections_obj->entries = list_new();
        if (! sections_obj) {
                ret = -1;
                goto end;
        }

        list_set_free_func(sections_obj->entries, elf_obj_free_func);
        list_set_cmp_func(sections_obj->entries, elf_obj_cmp_func);

        for (i = 0; i < ctx->n_sections; ++i) {
                telf_type type;
                char name[128];
                char *s_name = sh_strtab_p + ctx->shdr[i].sh_name;
                telf_obj *obj = NULL;

                if (! *s_name) {
                        /* empty name, use the section address */
                        sprintf(name, "noname.%p", sh_strtab + i);
                } else {
                        /* we want to convert '.bss', etc to 'bss', etc*/
                        sprintf(name, "%s",
                                '.' == *s_name ? s_name + 1 : s_name);
                }

                switch (ctx->shdr[i].sh_type) {
#define MAP(x) case SHT_##x: type = ELF_SECTION_##x; break
                        MAP(NULL);
                        MAP(DYNSYM);
                        MAP(SYMTAB);
                        MAP(NOBITS);
                        MAP(PROGBITS);
                        MAP(DYNAMIC);
                        MAP(HASH);
                        MAP(NOTE);
                        MAP(REL);
                        MAP(RELA);
                        MAP(STRTAB);
#undef MAP
                default:
                        LOG(LOG_ERR, 0, "unknown object type: 0x%x",
                            ctx->shdr[i].sh_type);
                        type = ELF_SECTION_OTHER;
                        break;
                }

                obj = elf_obj_new(name, sections_obj, type);
                if (! obj) {
                        ret = -1;
                        goto end;
                }

                list_add(sections_obj->entries, obj);
        }

        ret = 0;
  end:
        return ret;
}

/**
 * @ctx the global context
 * @obj the symtab object
 */
static int
elf_build_generic_file_entries(telf_ctx *ctx,
                               telf_obj *obj)
{
        int ret;
        telf_obj *entry = NULL;
        int i;

        obj->entries = list_new();
        if (! obj->entries) {
                LOG(LOG_ERR, 0, "consider this directory as empty...");
                ret = -1;
                goto end;
        }

        list_set_cmp_func(obj->entries, elf_obj_cmp_func);
        list_set_free_func(obj->entries, elf_obj_free_func);

        for (i = 0; i < N_ELEMS(e_names); i++) {
                entry = elf_obj_new(e_names[i].str, obj, ELF_SYMBOL_ENTRY);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'",
                            e_names[i].str);
                        continue;
                }

                list_add(obj->entries, entry);
        }


        ret = 0;
  end:
        return ret;
}

static int
elf_build_symtab(telf_ctx *ctx)
{
        int ret;
        int rc;
        int i;
        telf_obj *symtab_obj = NULL;
        telf_obj *obj = NULL;
        char *name = NULL;
        char path[256];

        rc = elf_namei(ctx, "/sections/symtab", &symtab_obj);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "can't find '/sections/symtab'");
                ret = -1;
                goto end;
        }

        for (i = 0; i < ctx->ehdr->e_shnum; i++) {
                if (SHT_SYMTAB != ctx->shdr[i].sh_type)
                        continue;

                ctx->n_syms = ctx->shdr[i].sh_size / sizeof (Elf64_Sym);
                LOG(LOG_DEBUG, 0, "section '%s' found: offset=%"PRIu64", "
                    "size: %d, #entries: %d",
                    ctx->addr + ctx->shdr[ctx->shdr[i].sh_link].sh_name,
                    ctx->shdr[i].sh_offset, (int) ctx->shdr[i].sh_size, ctx->n_syms);
                ctx->symtab = (Elf64_Sym *) (ctx->addr + ctx->shdr[i].sh_offset);
                ctx->symtab_end = (Elf64_Sym *) (ctx->symtab + ctx->shdr[i].sh_size);
                ctx->strtab = ctx->addr + ctx->shdr[ctx->shdr[i].sh_link].sh_offset;
        }

        if (! ctx->n_syms) {
                ret = 0;
                goto end;
        }

        symtab_obj->entries = list_new();
        if (! symtab_obj->entries) {
                ret = -1;
                goto end;
        }

        list_set_free_func(symtab_obj->entries, elf_obj_free_func);
        list_set_cmp_func(symtab_obj->entries, elf_obj_cmp_func);

        Elf64_Sym *sym = NULL;
        for (i = 0; i < ctx->n_syms; i++) {
                sym = elf_getnsym(ctx, i);
                assert(NULL != sym);

                name = elf_symname(ctx, sym);
                assert(NULL != name);

                if ('\0' == *name) {
                        sprintf(path, "noname.%p", (void *) sym);
                } else {
                        sprintf(path, "%s", name);
                }

                obj = elf_obj_new(path, symtab_obj, ELF_SYMBOL);
                if (! obj) {
                        ret = -1;
                        goto end;
                }

                (void) elf_build_generic_file_entries(ctx, obj);
                list_add(symtab_obj->entries, obj);
        }

        for (i = 0; i < ctx->n_syms; i++) {
                sym = elf_getnsym(ctx, i);
                LOG(LOG_DEBUG, 0, "sym: %s (info:%u, other:%u, shndx:%u, "
                    "value:%p, size:%zu)",
                    elf_symname(ctx, sym), sym->st_info, sym->st_other,
                    sym->st_shndx, (void *) sym->st_value, sym->st_size);
        }

        ret = 0;
  end:
        return ret;
}

static int
elf_build_dynsym(telf_ctx *ctx)
{
        int ret;
        int rc;
        int i;
        telf_obj *obj = NULL;
        telf_obj *dynsym_obj = NULL;
        char *name = NULL;
        char path[256];

        rc = elf_namei(ctx, "/sections/dynsym", &dynsym_obj);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "can't find '/sections/dynsym'");
                ret = -1;
                goto end;
        }

        for (i = 0; i < ctx->ehdr->e_shnum; i++) {

                if (SHT_DYNSYM == ctx->shdr[i].sh_type) {   /* dynamic symbol table */
                        ctx->n_dsyms = ctx->shdr[i].sh_size / sizeof (Elf64_Sym);
                        LOG(LOG_DEBUG, 0, "dynamic symbol table found: offset=%"PRIu64", size: %d, #entries: %d",
                            ctx->shdr[i].sh_offset, (int) ctx->shdr[i].sh_size, ctx->n_dsyms);
                        ctx->dsymtab = (Elf64_Sym *) (ctx->addr + ctx->shdr[i].sh_offset);
                        ctx->dsymtab_end = (Elf64_Sym *) (ctx->dsymtab + ctx->shdr[i].sh_size);
                        ctx->dstrtab = ctx->addr + ctx->shdr[ctx->shdr[i].sh_link].sh_offset;
                }
        }

        if (! ctx->n_dsyms) {
                ret = 0;
                goto end;
        }

        dynsym_obj->entries = list_new();
        if (! dynsym_obj->entries) {
                ret = -1;
                goto end;
        }

        list_set_free_func(dynsym_obj->entries, elf_obj_free_func);
        list_set_cmp_func(dynsym_obj->entries, elf_obj_cmp_func);

        Elf64_Sym *sym = NULL;
        for (i = 0; i < ctx->n_dsyms; i++) {
                sym = elf_getndsym(ctx, i);
                assert(NULL != sym);

                name = elf_dsymname(ctx, sym);
                assert(NULL != name);

                if ('\0' == *name) {
                        sprintf(path, "noname.%p", (void *) sym);
                } else {
                        sprintf(path, "%s", name);
                }

                obj = elf_obj_new(path, dynsym_obj, ELF_SYMBOL);
                if (! obj) {
                        ret = -1;
                        goto end;
                }

                (void) elf_build_generic_file_entries(ctx, obj);
                list_add(dynsym_obj->entries, obj);
        }

        for (i = 0; i < ctx->n_dsyms; i++) {
                sym = elf_getndsym(ctx, i);
                LOG(LOG_DEBUG, 0, "dsym: %s (info:%u, other:%u, shndx:%u, "
                    "value:%p, size:%zu)",
                    elf_dsymname(ctx, sym), sym->st_info, sym->st_other,
                    sym->st_shndx, (void *) sym->st_value, sym->st_size);
        }

        ret = 0;
  end:
        return ret;
}

static telf_ctx *
elf_ctx_new(const char * const path)
{
        telf_ctx *ctx = NULL;
        int rc;
        int i;
        Elf64_Sym *sym = NULL;

        ctx = malloc(sizeof *ctx);
        if (! ctx) {
                LOG(LOG_CRIT, 1, "malloc");
                goto err;
        }

        memset(ctx, 0, sizeof *ctx);

        if (NULL == realpath(path, ctx->path)) {
                LOG(LOG_ERR, 1, "realpath(%s)", path);
                goto err;
        }

        rc = stat(path, &ctx->st);
        if (-1 == rc) {
                LOG(LOG_ERR, 1, "stat");
                goto err;
        }

        rc = elf_mmap_internal(ctx);
        if (-1 == rc)
                goto err;

        ctx->root = list_new();
        if (! ctx->root)
                goto err;

        list_set_free_func(ctx->root, elf_obj_free_func);
        list_set_cmp_func(ctx->root, elf_obj_cmp_func);

        rc = elf_build_rootdir(ctx);
        if (-1 == rc)
                goto err;

        rc = elf_build_sections(ctx);
        if (-1 == rc)
                goto err;

        rc = elf_build_symtab(ctx);
        if (-1 == rc)
                goto err;

        rc = elf_build_dynsym(ctx);
        if (-1 == rc)
                goto err;

        LOG(LOG_DEBUG, 0, "ctx successfully created for file %s", path);

        return ctx;

  err:
        elf_ctx_free(ctx);
        return NULL;
}

/* Not implemented yet */

static int
elf_getxattr(const char *path,
             const char *name,
             char *value,
             size_t size)
{
        LOG(LOG_DEBUG, 0, "path=%s, value=%s", path, value);
        return 0;
}

static int
elf_listxattr(const char *path,
              char *list,
              size_t size)
{
        LOG(LOG_DEBUG, 0, "path=%s, list=%s, size=%zu", path, list, size);
        return 0;
}

static int
elf_removexattr(const char *path,
                const char *name)
{
        LOG(LOG_DEBUG, 0, "path=%s, name=%s", path, name);
        return 0;
}

static int
elf_flush(const char *path,
          struct fuse_file_info *info)
{
        (void) info;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_truncate(const char *path,
             off_t offset)
{
        (void) offset;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_utime(const char *path,
          struct utimbuf *times)
{
        (void) times;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_releasedir(const char *path,
               struct fuse_file_info *info)
{
        (void) info;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_fsyncdir(const char *path,
             int datasync,
             struct fuse_file_info *info)
{
        (void) datasync;
        (void) info;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static void *
elf_init(struct fuse_conn_info *conn)
{
        return NULL;
}

static void
elf_destroy(void *arg)
{
        LOG(LOG_DEBUG, 0, "%p", arg);
}

static int
elf_access(const char *path, int perm)
{
        (void) perm;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_ftruncate(const char *path,
              off_t offset,
              struct fuse_file_info *info)
{
        (void) offset;
        (void) info;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_lock(const char *path,
         struct fuse_file_info *info,
         int cmd,
         struct flock *flock)
{
        (void) info;
        (void) cmd;
        (void) flock;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_utimens(const char *path,
            const struct timespec tv[2])
{
        (void) path;
        (void) tv;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_bmap(const char *path,
         size_t blocksize,
         uint64_t *idx)
{
        (void) blocksize;
        (void) idx;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

#if 0
static int
elf_ioctl(const char *path,
          int cmd,
          void *arg,
          struct fuse_file_info *info,
          unsigned int flags,
          void *data)
{
        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

static int
elf_poll(const char *path,
         struct fuse_file_info *info,
         struct fuse_pollhandle *ph,
         unsigned *reventsp)
{
        (void) info;
        (void) ph;
        (void) reventsp;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}
#endif

int
elf_getattr(const char *path,
            struct stat *st)
{
        telf_obj *obj = NULL;
        int ret;
        int rc;

        LOG(LOG_DEBUG, 0, "%s", path);

        st->st_nlink = 1;

        /* rootdir */
        if (0 == strcmp("/", path)) {
                st->st_mode = S_IFDIR|S_IRUSR|S_IXUSR;
                st->st_uid = ctx->st.st_uid;
                st->st_gid = ctx->st.st_gid;
                st->st_atime = ctx->st.st_atime;
                st->st_mtime = ctx->st.st_mtime;
                st->st_ctime = ctx->st.st_ctime;

                /* ok, return */
                ret = 0;
                goto end;
        }

        rc = elf_namei(ctx, (char *) path, &obj);
        if (-1 == rc) {
                ret = -ENOENT;
                goto end;
        }

        LOG(LOG_DEBUG, 0, "path=%s, type=%s", obj->name, elf_type_to_str(obj->type));

        /* for now, all the files are directories */
        switch (obj->st.st_mode) {
        case ELF_S_IFDIR:
                st->st_mode = S_IFDIR|S_IRUSR|S_IXUSR;
                break;
        case ELF_S_IFREG:
                st->st_mode = S_IFREG|S_IRUSR|S_IRGRP|S_IROTH;
                st->st_size = obj->st.st_size;
                break;
        default:
                st->st_mode = S_IFDIR|S_IRUSR|S_IXUSR;
                break;
        }

        st->st_uid = ctx->st.st_uid;
        st->st_gid = ctx->st.st_gid;
        st->st_atime = ctx->st.st_atime;
        st->st_mtime = ctx->st.st_mtime;
        st->st_ctime = ctx->st.st_ctime;

        ret = 0;
  end:
        LOG(LOG_DEBUG, 0, "path=%s, ret=%d", path, ret);
        return ret;
}

int
elf_chmod(const char *path,
          mode_t mode)
{
        (void) mode;
        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

int
elf_chown(const char *path,
          uid_t uid,
          gid_t gid)
{
        LOG(LOG_DEBUG, 0, "%s: uid=%u, gid=%u", path, uid, gid);
        return 0;
}

int
elf_create(const char *path,
           mode_t mode,
           struct fuse_file_info *info)
{
        (void) mode;
        (void) info;

        LOG(LOG_DEBUG, 0, "%s", path);
        return 0;
}

int
elf_fsync(const char *path,
          int issync,
          struct fuse_file_info *info)
{
        return 0;
}

int
elf_mkdir(const char *path,
          mode_t mode)
{
        return 0;
}

int
elf_mknod(const char *path,
          mode_t mode,
          dev_t dev)
{
        return 0;
}

char *
flags_to_str(int flags)
{
        switch (flags & O_ACCMODE) {
        case O_RDONLY:
                return "read only";
        case O_WRONLY:
                return "write only";
        case O_RDWR:
                return "read/write";
        }

        assert(! "impossible");
        return "invalid";
}

int
elf_open(const char *path,
         struct fuse_file_info *info)
{
        telf_obj *obj = NULL;
        int rc;
        int ret;

        LOG(LOG_DEBUG, 0, "path=%s", path);

        rc = elf_namei(ctx, (char *) path, &obj);
        if (-1 == rc) {
                ret = -1;
                goto end;
        }

        assert(ELF_SYMBOL_ENTRY == obj->type);

        switch (obj->parent->parent->type) {
        case ELF_SECTION_SYMTAB:
                obj->data = (void *) elf_getsymbyname(ctx, obj->parent->name);
                break;
        case ELF_SECTION_DYNSYM:
                obj->data = (void *) elf_getdsymbyname(ctx, obj->parent->name);
                break;
        default:
                LOG(LOG_ERR, 0, "%s: do not open object with parent type %s",
                    path, elf_type_to_str(obj->parent->type));
                ret = -1;
                break;
        }

        rc = elf_filehdl_set_content(obj);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "%s: can't set object content", path);
                ret = -1;
                goto end;
        }

        info->fh = (uint64_t) (uintptr_t) obj;

        ret = 0;
  end:
        return ret;
}

int
elf_read(const char *path,
         char *buf,
         size_t size,
         off_t offset,
         struct fuse_file_info *info)
{
        telf_obj *obj = (telf_obj *) info->fh;
        telf_filehdl_driver *driver = obj->driver;
        int ret;
        ssize_t cc;

        LOG(LOG_DEBUG, 0, "path=%s", path);

        if (! obj) {
                ret = -1;
                goto end;
        }

        if (! ELF_S_ISREG(obj->st.st_mode)) {
                LOG(LOG_ERR, 0, "can't read() into a directory");
                ret = -1;
                goto end;
        }

        cc = driver->read(obj, buf, size, offset);
        if (-1 == cc) {
                LOG(LOG_ERR, 0, "%s: can't read %zu bytes @offset: %zd",
                    path, size, offset);
                ret = -1;
                goto end;
        }


        ret = cc;
  end:
        return ret;
}

int
elf_opendir(const char *path,
            struct fuse_file_info *info)
{
        return 0;
}

typedef struct {
        char name[128]; /* section/segment name */
} telf_dirent;

typedef struct elf_dir_hdl {
        void *(*get_entryname_func)(telf_ctx *, struct elf_dir_hdl *, char **);

        telf_obj *obj;
        int cursor;
        int n_entries;
} telf_dir_hdl;

static void *
elf_direntname(telf_ctx *ctx,
               telf_dir_hdl *dir_hdl,
               char **namep)
{
        char *name = NULL;
        telf_obj *entry = NULL;

        entry = list_get_nth(dir_hdl->obj->entries, dir_hdl->cursor);
        if (! entry)
                return NULL;

        if (namep)
                *namep = entry->name;

        return entry;
}

static int
elf_dir_ctor(telf_ctx *ctx,
             telf_obj *obj,
             telf_dir_hdl *dir)
{
        dir->cursor = 0;
        dir->obj = obj;
        dir->n_entries = list_get_size(obj->entries);
        dir->get_entryname_func = elf_direntname;
}

static int
elf_readdir_getdirent(void *hdl,
                      telf_dirent *dirent)
{
        telf_dir_hdl *dir_hdl = hdl;
        char *name = NULL;
        void *addr =  NULL;

        if (dir_hdl->cursor >= dir_hdl->n_entries)
                return -1;

        addr = dir_hdl->get_entryname_func(ctx, dir_hdl, &name);
        if (! addr) {
                LOG(LOG_ERR, 0, "can't get entry name");
                return -1;
        }

        if (*name)
                sprintf(dirent->name, "%s", name);
        else
                sprintf(dirent->name, "noname.%p", addr);

        dir_hdl->cursor++;

        return 0;
}

static int
elf_readdir(const char *path,
            void *data,
            fuse_fill_dir_t fill,
            off_t offset,
            struct fuse_file_info *info)
{
        int ret;
        int rc;
        telf_dir_hdl *dir_hdl = NULL;
        telf_dirent dirent;
        telf_obj *obj;

        LOG(LOG_DEBUG, 0, "path=%s", path);

        rc = elf_namei(ctx, (char *) path, &obj);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "can't find any object with key '%s'", path);
                ret = -1;
                goto err;
        }

        dir_hdl = alloca(sizeof *dir_hdl);
        if (! dir_hdl) {
                LOG(LOG_CRIT, 1, "alloca");
                ret = -1;
                goto err;
        }

        memset(&dirent, 0, sizeof dirent);

        elf_dir_ctor(ctx, obj, dir_hdl);

        while (0 == elf_readdir_getdirent(dir_hdl, &dirent)) {
                if (fill(data, dirent.name, NULL, 0))
                        break;
        }

        ret = 0;
  err:
        return ret;

}

int
elf_readlink(const char *path,
             char *buf,
             size_t bufsiz)
{
        return 0;
}

int
elf_release(const char *path,
            struct fuse_file_info *info)
{
        telf_obj *obj = (telf_obj *) info->fh;
        int ret;

        if (! obj) {
                LOG(LOG_ERR, 0, "can't release an empty object");
                ret = -1;
                goto end;
        }

        telf_filehdl_driver *driver = obj->driver;

        if (driver->content) {
                free(driver->content);
                driver->content = NULL;
        }

        ret = 0;
  end:
        return ret;
}

int
elf_rename(const char *oldpath,
           const char *newpath)
{
        return 0;
}

int
elf_rmdir(const char *path)
{
        return 0;
}

int
elf_setxattr(const char *path,
             const char *name,
             const char *value,
             size_t size,
             int flag)
{
        return 0;
}

int
elf_statfs(const char *path,
           struct statvfs *buf)
{
        LOG(LOG_DEBUG, 0, "path=%s, buf=%p", path, (void *) buf);

        buf->f_flag = ST_RDONLY;
        buf->f_namemax = 255;
        buf->f_bsize = 4096;
        buf->f_frsize = buf->f_bsize;
        buf->f_blocks = buf->f_bfree = buf->f_bavail =
                (1000ULL * 1024) / buf->f_frsize;
        buf->f_files = buf->f_ffree = 1000000000;

        return 0;
}

int
elf_symlink(const char *oldpath,
            const char *newpath)
{
        return 0;
}

int
elf_unlink(const char *path)
{
        return 0;
}

int
elf_write(const char *path,
          const char *buf,
          size_t size,
          off_t offset,
          struct fuse_file_info *info)
{
        return 0;
}


struct fuse_operations elf_ops = {
        /* implemented */

        /* not implemented yet */
        .getattr    = elf_getattr,
        .mkdir      = elf_mkdir,
        .write      = elf_write,
        .readdir    = elf_readdir,
        .opendir    = elf_opendir,
        .unlink     = elf_unlink,
        .rmdir      = elf_rmdir,
        .statfs     = elf_statfs,
        .read       = elf_read,
        .release    = elf_release,
        .open       = elf_open,
        .fsync      = elf_fsync,
        .setxattr   = elf_setxattr,
        .create     = elf_create,
        .chmod      = elf_chmod,
        .chown      = elf_chown,
        .mknod      = elf_mknod,
        .readlink   = elf_readlink,
        .symlink    = elf_symlink,
        .rename     = elf_rename,
        .getxattr   = elf_getxattr,
        .listxattr  = elf_listxattr,
        .removexattr= elf_removexattr,
        .truncate   = elf_truncate,
        .utime      = elf_utime,
        .flush      = elf_flush,
        .fsyncdir   = elf_fsyncdir,
        .init       = elf_init,
        .destroy    = elf_destroy,
        .access     = elf_access,
        .releasedir = elf_releasedir,
        .ftruncate  = elf_ftruncate,
        .lock       = elf_lock,
        .utimens    = elf_utimens,
        .bmap       = elf_bmap,
#if 0
        .iotcl      = elf_ioctl,
        .poll       = elf_poll,
#endif
        .getdir     = NULL, /* deprecated */
        .link       = NULL, /* no support needed */
};

static int
elf_fuse_main(struct fuse_args *args)
{
        return fuse_main(args->argc, args->argv, &elf_ops, NULL);
}

static void
usage(const char * const prog)
{
        printf("Usage: %s <path to elf binary> <mountpoint> [options]\n", prog);
        printf("\t<path to elf binary>\twell...\n");
        printf("\t<mountpoint>\t\tthe directory you want to use as mount point.\n");
        printf("\t\t\t\tThe directory must exist\n");
        printf("\t[options]\tfuse/mount options\n");
}

static int
atopriority(char *str)
{
        int i;

        for (i = 0; NULL != prioritynames[i].c_name; i++) {
                if (! strcasecmp(prioritynames[i].c_name, str))
                        return prioritynames[i].c_val;
        }

        return -1;
}

static const char *
prioritytoa(int priority)
{
        int i;

        for (i = 0; NULL != prioritynames[i].c_name; i++) {
                if (prioritynames[i].c_val == priority)
                        return prioritynames[i].c_name;
        }

        return "unknown priority";
}

int
main(int argc,
     char **argv)
{
        int ret;
        const char * const progname = argv[0];
        char *lvl = NULL;

        if (argc < 2) {
                usage(progname);
                exit(EXIT_FAILURE);
        }

        openlog(basename((char *) progname), LOG_CONS | LOG_NOWAIT | LOG_PID, LOG_USER);

        lvl = getenv("ELFS_LOGLEVEL");
        if (lvl) {
                int rc = atopriority(lvl);
                if (-1 != rc)
                        loglevel = rc;
        }

        LOG(LOG_DEBUG, 0, "loglevel=%s", prioritytoa(loglevel));

        ctx = elf_ctx_new(argv[1]);
        if (! ctx) {
                LOG(LOG_CRIT, 0, "ctx creation failed");
                exit(EXIT_FAILURE);
        }

        argc--;
        argv++;

        struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        ret = fuse_main(args.argc, args.argv, &elf_ops, NULL);

        closelog();

  end:
        if (ctx)
                elf_ctx_free(ctx);

        return ret;
}

