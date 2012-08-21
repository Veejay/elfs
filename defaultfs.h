#ifndef DEFAULTFS_H
#define DEFAULTFS_H

#include "fs-structs.h"

/* file */
int defaultfs_getattr(void *obj, telf_stat *st);
int defaultfs_open(char *path, telf_open_flags flags, void **objp);
int defaultfs_release(void *obj);
int defaultfs_read(void *obj, char *buf, size_t size, off_t offset);
int defaultfs_write(void *obj, const char *buf, size_t size, off_t offset);
/* directory */
int defaultfs_opendir(char *path, void **objp);
int defaultfs_readdir(void *obj, void *data, fuse_fill_dir_t fill);
int defaultfs_releasedir(void *obj);

telf_fs_driver *defaultfs_driver_new(void);

#endif /* DEFAULTFS_H */
