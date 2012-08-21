
#ifndef FS_STRUCTS_H
#define FS_STRUCTS_H

#define FUSE_USE_VERSION 29
#include <fuse.h>

typedef enum {
        ELF_S_IFDIR = (1u << 0),
        ELF_S_IFREG = (1u << 1),

        ELF_S_IRWXU = (1u << 2), // 00700 user
        ELF_S_IRUSR = (1u << 3), // 00400 user has read permission
        ELF_S_IWUSR = (1u << 4), // 00200 user has write permission
        ELF_S_IXUSR = (1u << 5), // 00100 user has execute permission
        ELF_S_IRWXG = (1u << 6), // 00070 group has read, write and execute
        ELF_S_IRGRP = (1u << 7), // 00040 group has read permission
        ELF_S_IWGRP = (1u << 8), // 00020 group has write permission
        ELF_S_IXGRP = (1u << 9), // 00010 group has execute permission
        ELF_S_IRWXO = (1u << 10), // 00007 others have read, write and execute
        ELF_S_IROTH = (1u << 11), // 00004 others have read permission
        ELF_S_IWOTH = (1u << 12), // 00002 others have write permission
        ELF_S_IXOTH = (1u << 13), // 00001 others have execute permission
} telf_ftype;

#define ELF_S_ISDIR(mode) ((mode) & ELF_S_IFDIR)
#define ELF_S_ISREG(mode) ((mode) & ELF_S_IFREG)

typedef struct {
        size_t st_size;
        size_t st_nlink;
        unsigned int st_mode;
} telf_stat;

typedef enum {
        ELF_O_RDONLY = (1u<<0),
        ELF_O_RDWR   = (1u<<1),
        ELF_O_WRONLY = (1u<<2),
        ELF_O_TRUNC  = (1u<<3),
        ELF_O_CREAT  = (1u<<4),
} telf_open_flags;

typedef enum {
        ELF_SUCCESS =  0,
        ELF_FAILURE = -1,
        ELF_ENOENT  = -2,
        ELF_EIO     = -3,
        ELF_ENOMEM  = -4,
} telf_status;

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
} telf_fs_driver;

#include "utils.h"

#endif /* FS_STRUCTS_H */
