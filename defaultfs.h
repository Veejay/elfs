#ifndef DEFAULTFS_H
#define DEFAULTFS_H

#include "fs-structs.h"

/* file */
telf_status defaultfs_getattr(void *obj, telf_stat *st);
telf_status defaultfs_open(char *path, telf_open_flags flags, void **objp);
telf_status defaultfs_release(void *obj);
telf_status defaultfs_read(void *obj, char *buf, size_t size, off_t offset, size_t *);
telf_status defaultfs_write(void *obj, const char *buf, size_t size, off_t offset, size_t *);
/* directory */
telf_status defaultfs_opendir(char *path, void **objp);
telf_status defaultfs_readdir(void *obj, void *data, fuse_fill_dir_t fill);
telf_status defaultfs_releasedir(void *obj);

telf_fs_driver *defaultfs_driver_new(void);

#endif /* DEFAULTFS_H */
