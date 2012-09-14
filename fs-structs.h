
#ifndef FS_STRUCTS_H
#define FS_STRUCTS_H

#define FUSE_USE_VERSION 29
#include <fuse.h>

typedef enum {
        ELF_S_IFDIR = (1u << 0),
        ELF_S_IFREG = (1u << 1),
        ELF_S_IFLNK = (1u << 2),

        ELF_S_IRWXU = (1u << 12), // 00700 user
        ELF_S_IRUSR = (1u << 13), // 00400 user has read permission
        ELF_S_IWUSR = (1u << 14), // 00200 user has write permission
        ELF_S_IXUSR = (1u << 15), // 00100 user has execute permission
        ELF_S_IRWXG = (1u << 16), // 00070 group has read, write and execute
        ELF_S_IRGRP = (1u << 17), // 00040 group has read permission
        ELF_S_IWGRP = (1u << 18), // 00020 group has write permission
        ELF_S_IXGRP = (1u << 19), // 00010 group has execute permission
        ELF_S_IRWXO = (1u << 20), // 00007 others have read, write and execute
        ELF_S_IROTH = (1u << 21), // 00004 others have read permission
        ELF_S_IWOTH = (1u << 22), // 00002 others have write permission
        ELF_S_IXOTH = (1u << 23), // 00001 others have execute permission
} telf_ftype;

#define ELF_S_ISDIR(mode) ((mode) & ELF_S_IFDIR)
#define ELF_S_ISREG(mode) ((mode) & ELF_S_IFREG)
#define ELF_S_ISLNK(mode) ((mode) & ELF_S_IFLNK)

typedef struct {
        size_t st_size;
        size_t st_nlink;
        telf_ftype st_mode;
} telf_stat;

typedef enum {
        ELF_O_RDONLY = (1u << 0),
        ELF_O_RDWR   = (1u << 1),
        ELF_O_WRONLY = (1u << 2),
        ELF_O_TRUNC  = (1u << 3),
        ELF_O_CREAT  = (1u << 4),
} telf_open_flags;

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
        MAP(ELF_LIBS)                                   \
        MAP(ELF_LIBS_ENTRY)                             \
        MAP(ELF_ROOTDIR)                                \
        MAP(ELF_ROOTDIR_ENTRY)

#define X(a, b) a,
typedef enum {
        ELF_TYPES_TABLE
} telf_type;
#undef X
#undef MAP

#define MAP(v) X(v, #v)
#define ELF_STATUS_TABLE                        \
        MAP(ELF_SUCCESS)                        \
        MAP(ELF_FAILURE)                        \
        MAP(ELF_ENOENT)                         \
        MAP(ELF_EIO)                            \
        MAP(ELF_ENOMEM)                         \
        MAP(ELF_EPERM)

#define X(a, b) a,
typedef enum {
        ELF_STATUS_TABLE
} telf_status;
#undef X
#undef MAP

typedef enum {
        ELF_ST_SIZE  = (1u << 0),
        ELF_ST_MODE  = (1u << 1),
        ELF_ST_ATIME = (1u << 2),
        ELF_ST_MTIME = (1u << 3),
        ELF_ST_CTIME = (1u << 4),
        ELF_ST_NLINK = (1u << 5),
} telf_st_flags;

/* file */
typedef telf_status (* telf_fs_getattr)(void *obj, telf_stat *st);
typedef telf_status (* telf_fs_open)(char *name, telf_open_flags flags, void **objp);
typedef telf_status (* telf_fs_release)(void *obj);
typedef telf_status (* telf_fs_read)(void *obj, char *buf, size_t size, off_t offset, ssize_t *sizep);
typedef telf_status (* telf_fs_write)(void *obj, const char *buf, size_t size, off_t offset, ssize_t *sizep);
/* directory */
typedef telf_status (* telf_fs_opendir)(char *name, void **objp);
typedef telf_status (* telf_fs_readdir)(void *obj, void *data, fuse_fill_dir_t fill);
typedef telf_status (* telf_fs_releasedir)(void *obj);
/* links */
typedef telf_status (* telf_fs_readlink)(void *obj, char **bufp, size_t *buf_lenp);

typedef struct {
        void *data;
        telf_fs_getattr getattr;
        telf_fs_open open;
        telf_fs_release release;
        telf_fs_read read;
        telf_fs_write write;
        telf_fs_opendir opendir;
        telf_fs_readdir readdir;
        telf_fs_releasedir releasedir;
        telf_fs_readlink readlink;
} telf_fs_driver;

#include "utils.h"

#endif /* FS_STRUCTS_H */
