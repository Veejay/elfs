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

#include <signal.h>

#define SYSLOG_NAMES
#include "log.h"

#include "elfs.h"
#include "misc.h"
#include "defaultfs.h"
#include "symbolfs.h"
#include "rootfs.h"
#include "sectionfs.h"
#include "fsapi.h"
#include "libfs.h"

telf_ctx *ctx = NULL;

#define MAP(v) X(v, #v)
#define X(a, b) b,
char *elf_type_names[] = {
        ELF_TYPES_TABLE
};
#undef X
#undef MAP


struct fuse_operations elf_fs_ops = {
        .getattr     = elf_fs_getattr,
        .mkdir       = elf_fs_mkdir,
        .write       = elf_fs_write,
        .readdir     = elf_fs_readdir,
        .opendir     = elf_fs_opendir,
        .unlink      = elf_fs_unlink,
        .rmdir       = elf_fs_rmdir,
        .statfs      = elf_fs_statfs,
        .read        = elf_fs_read,
        .release     = elf_fs_release,
        .open        = elf_fs_open,
        .fsync       = elf_fs_fsync,
        .setxattr    = elf_fs_setxattr,
        .create      = elf_fs_create,
        .chmod       = elf_fs_chmod,
        .chown       = elf_fs_chown,
        .mknod       = elf_fs_mknod,
        .readlink    = elf_fs_readlink,
        .symlink     = elf_fs_symlink,
        .rename      = elf_fs_rename,
        .getxattr    = elf_fs_getxattr,
        .listxattr   = elf_fs_listxattr,
        .removexattr = elf_fs_removexattr,
        .truncate    = elf_fs_truncate,
        .utime       = elf_fs_utime,
        .flush       = elf_fs_flush,
        .fsyncdir    = elf_fs_fsyncdir,
        // .init        = elf_fs_init,
        // .destroy     = elf_fs_destroy,
        .access      = elf_fs_access,
        .releasedir  = elf_fs_releasedir,
        .ftruncate   = elf_fs_ftruncate,
        .lock        = elf_fs_lock,
        .utimens     = elf_fs_utimens,
        .bmap        = elf_fs_bmap,
#if 0
        .iotcl       = elf_fs_ioctl,
        .poll        = elf_fs_poll,
#endif
        .getdir      = NULL, /* deprecated */
        .link        = NULL, /* no support needed */
};


static char *
elf_type_to_str(telf_type type)
{
        return elf_type_names[type];
}

void
elf_obj_free(telf_obj *obj)
{
        LOG(LOG_DEBUG, 0, "free obj @%p, name=%s", (void *) obj, obj->name);

        if (obj->entries)
                list_free(obj->entries);

        if (obj->name)
                free(obj->name);

        if (obj->driver)
                free(obj->driver);

        if (obj->data)
                obj->free_func(obj->data);

        free(obj);
}

void
elf_obj_lock(telf_obj *obj)
{
        pthread_mutex_lock(&obj->lock);
}

void
elf_obj_unlock(telf_obj *obj)
{
        pthread_mutex_unlock(&obj->lock);
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

        return strcmp(key, elem->name);
}

telf_obj *
elf_obj_new(telf_ctx *ctx,
            char *path,
            telf_obj *parent,
            telf_type type, /* from elf pov: SECTION, SYMBOL, ... */
            telf_ftype ftype) /* from fs pov: directory, regular, ... */
{
        telf_obj *obj = NULL;

        LOG(LOG_DEBUG, 0, "build object: path=%s, parent=%p, type=%s",
            path, (void *) parent, elf_type_to_str(type));

        obj = malloc(sizeof *obj);
        if (! obj) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                goto err;
        }

        memset(obj, 0, sizeof *obj);

        obj->name = strdup(path);
        if (! obj->name) {
                LOG(LOG_ERR, 0, "strdup(%s): %s", path, strerror(errno));
                goto err;
        }

        obj->ctx = ctx;
        obj->parent = parent;
        obj->type = type;

        if (ELF_S_ISDIR(ftype)) {
                obj->st.st_mode |= ELF_S_IFDIR;
                obj->entries = list_new();
                if (! obj->entries) {
                        LOG(LOG_ERR, 0, "can't create list entries");
                        goto err;
                }

                list_set_free_func(obj->entries, elf_obj_free_func);
                list_set_cmp_func(obj->entries, elf_obj_cmp_func);
        } else {
                obj->st.st_mode |= ELF_S_IFREG;
        }

        obj->driver = defaultfs_driver_new();
        if (! obj->driver) {
                LOG(LOG_ERR, 0, "can't create defaultfs driver");
                goto err;
        }

        pthread_mutex_init(&obj->lock, NULL);

        return obj;

  err:
        elf_obj_free(obj);

        return NULL;
}

static void
elf_ctx_free(telf_ctx *ctx)
{
        if (ctx) {
                if (-1 == ctx->pid && ctx->addr)
                        (void) munmap((void *) ctx->addr, ctx->st.st_size);

                if (ctx->root)
                        elf_obj_free(ctx->root);

                if (ctx->pid) {
                        if (ptrace(PTRACE_DETACH, ctx->pid, NULL, NULL) < 0) {
                                LOG(LOG_ERR, 0, "ptrace_detach: %s",
                                    strerror(errno));
                        }

                        if (ctx->ehdr)
                                free(ctx->ehdr);

                        if (ctx->shdr)
                                free(ctx->shdr);

                        if (ctx->phdr)
                                free(ctx->phdr);
                }

                free(ctx);
        }
}

static telf_status
elf_sanity_check(unsigned char *addr)
{
        telf_status ret;

        if (strncmp(addr, ELFMAG, SELFMAG)) {
                LOG(LOG_ERR, 0, "bad magic: %*s", SELFMAG, addr);
                ret = ELF_FAILURE;
                goto end;
        }

        if (ELFCLASSNONE == addr + EI_CLASS) {
                LOG(LOG_ERR, 0, "bad elf class %c", addr[EI_CLASS]);
                ret = ELF_FAILURE;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

static void
elf_compute_base_vaddr(telf_ctx *ctx)
{
        /*
         * ELF format, chapter 2, section "program header",
         * subsection "base address"
         *
         * To compute the base address, one determines the
         * memory address associated with the lowest p_vaddr value for a
         * PT_LOAD segment. One then obtains the base address by truncating
         * the memory address to the nearest multiple of the maximum page
         * size.
         */

        int i;
        unsigned long min_vaddr = ~0;

        for (i = 0; i < ctx->ehdr->e_phnum; i++) {
                Elf64_Phdr *phdr = ctx->phdr + i;

                if (PT_LOAD != phdr->p_type)
                        continue;

                if (phdr->p_vaddr < min_vaddr)
                        min_vaddr = phdr->p_vaddr;
        }

        ctx->base_vaddr = (min_vaddr & ~(sysconf(_SC_PAGESIZE) -1));

        LOG(LOG_DEBUG, 0, "base virtual address: %p", (void *) ctx->base_vaddr);
}

static telf_status
elf_set_headers(telf_ctx *ctx)
{
        telf_status ret;

        ctx->ehdr = (Elf64_Ehdr *) ctx->addr;
        ctx->shdr = (Elf64_Shdr *) (ctx->addr + ctx->ehdr->e_shoff);
        ctx->phdr = (Elf64_Phdr *) (ctx->addr + ctx->ehdr->e_phoff);

        ret = ELF_SUCCESS;
  end:
        return ret;
}

static telf_status
elf_mmap_internal(telf_ctx *ctx)
{
        int fd = -1;
        telf_status ret;
        telf_status rc;
        void *addr = NULL;

        fd = open(ctx->binpath, 0600, O_RDONLY);
        if (-1 == fd) {
                LOG(LOG_ERR, 0, "open '%s': %s", ctx->binpath, strerror(errno));
                ret = ELF_FAILURE;
                goto err;
        }

        addr = mmap(NULL, ctx->st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (MAP_FAILED == addr) {
                LOG(LOG_ERR, 0, "mmap: %s", strerror(errno));
                ret = ELF_FAILURE;
                goto err;
        }

        ctx->addr = (unsigned char *) addr;

        rc = elf_sanity_check(ctx->addr);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "sanity checks failed: %s",
                    elf_status_to_str(rc));
                ret = ELF_FAILURE;
                goto err;
        }

        LOG(LOG_DEBUG, 0, "elf header: %p", addr);

        ret = ELF_SUCCESS;
  err:

        if (-1 != fd)
                (void) close(fd);

        return ret;
}

static telf_ctx *
elf_ctx_new(const char * const path,
            int pid,
            const char * const mountpoint)
{
        telf_ctx *ctx = NULL;
        telf_status rc;
        int iret;

        LOG(LOG_DEBUG, 0, "mount file '%s' on '%s'", path, mountpoint);

        ctx = malloc(sizeof *ctx);
        if (! ctx) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                goto err;
        }

        memset(ctx, 0, sizeof *ctx);

        iret = mkdir(mountpoint, 0755);
        if (-1 == iret && EEXIST != errno) {
                LOG(LOG_ERR, 0, "mkdir(%s): %s", mountpoint, strerror(errno));
                goto err;
        }

        if (-1 != pid) {
                char pidpath[PATH_MAX];
                ssize_t len;

                sprintf(pidpath, "/proc/%d/exe", pid);

                len = readlink(pidpath, ctx->binpath, sizeof ctx->binpath -1);
                if (-1 == len) {
                        LOG(LOG_ERR, 0, "readlink: %s", strerror(errno));
                        goto err;
                }

                ctx->binpath[len] = 0;

                ctx->pid = pid;

                iret = ptrace(PTRACE_ATTACH, ctx->pid, NULL, NULL);
                if (-1 == iret) {
                        LOG(LOG_ERR, 0, "ptrace: %s", strerror(errno));
                        goto err;
                }

                LOG(LOG_DEBUG, 0, "pid %d attached", ctx->pid);
                waitpid(ctx->pid, NULL, WUNTRACED);

        } else {
                if (NULL == realpath(path, ctx->binpath)) {
                        LOG(LOG_ERR, 0, "realpath(%s): %s",
                            path, strerror(errno));
                        goto err;
                }
        }

        iret = stat(ctx->binpath, &ctx->st);
        if (-1 == iret) {
                LOG(LOG_ERR, 0, "stat(%s): %s", path, strerror(errno));
                goto err;
        }

        rc = elf_mmap_internal(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can't mmap() file in memory");
                goto err;
        }

        rc = elf_set_headers(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can't set elf header structures: %s",
                    elf_status_to_str(rc));
                goto err;
        }

        elf_compute_base_vaddr(ctx);

        rc = rootfs_build(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "rootfs build failed");
                goto err;
        }

        rc = sectionfs_build(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "sections build failed");
                goto err;
        }

        /* now that 'generic' sections are built, initialize
         * specific ones */
        rc = symbolfs_build(ctx);
        if (ELF_SUCCESS != rc)
                LOG(LOG_ERR, 0, "binary is stripped?");

        rc = programfs_build(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "programfs build failed");
                goto err;
        }

        rc = libfs_build(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "libfs build failed");
                goto err;
        }

        return ctx;

  err:
        elf_ctx_free(ctx);
        return NULL;
}

static int
elf_fuse_main(struct fuse_args *args)
{
        return fuse_main(args->argc, args->argv, &elf_fs_ops, NULL);
}

static void
usage(const char * const prog)
{
        printf("Usage: %s [path to elf binary | -p pid] [-d] <mountpoint>\n", prog);
        printf("\t<path to elf binary>\twell...\n");
        printf("\t<-p pid>\trunning process we want to inspect\n");
        printf("\t<mountpoint>\t\tthe directory you want to use as mount point.\n");
        printf("\t\t\t\tThe directory must exist\n");
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
        long pid = -1;
        char *elf_file = NULL;
        char *mountpoint = NULL;

        if (argc < 3) {
                usage(progname);
                exit(EXIT_FAILURE);
        }

        openlog(basename((char *) progname), LOG_CONS | LOG_NOWAIT | LOG_PID, LOG_USER);

        // default value
        loglevel = LOG_ERR;

        lvl = getenv("ELFS_LOGLEVEL");
        if (lvl) {
                int rc = atopriority(lvl);
                if (-1 != rc)
                        loglevel = rc;
        }

        if (0 == strcmp("-p", argv[1])) {

                if (! argc)  {
                        usage(progname);
                        ret = EXIT_FAILURE;
                        goto end;
                }

                pid = strtoul(argv[2], NULL, 0);

                argc--;
                argv++;
        } else {
                elf_file = argv[1];
        }

        mountpoint = argv[argc - 1];

        LOG(LOG_DEBUG, 0, "loglevel=%s", prioritytoa(loglevel));
        LOG(LOG_DEBUG, 0, "mountpoint=%s", mountpoint);

        signal(SIGHUP, SIG_IGN);
        signal(SIGURG, SIG_IGN);

        ctx = elf_ctx_new(elf_file, pid, mountpoint);
        if (! ctx) {
                LOG(LOG_ERR, 0, "ctx creation failed");
                exit(EXIT_FAILURE);
        }

        argc--;
        argv++;

        struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
        ret = fuse_main(args.argc, args.argv, &elf_fs_ops, NULL);

        closelog();

  end:
        if (ctx)
                elf_ctx_free(ctx);

        return ret;
}

