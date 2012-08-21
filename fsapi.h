#ifndef FSAPI_H
#define FSAPI_H

#include "fs-structs.h"

int elf_fs_getxattr(const char *, const char *, char *, size_t);
int elf_fs_listxattr(const char *, char *, size_t);
int elf_fs_removexattr(const char *, const char *);
int elf_fs_flush(const char *, struct fuse_file_info *);
int elf_fs_truncate(const char *, off_t);
int elf_fs_utime(const char *, struct utimbuf *);
int elf_fs_releasedir(const char *, struct fuse_file_info *);
int elf_fs_fsyncdir(const char *, int, struct fuse_file_info *);
int elf_fs_access(const char *, int);
int elf_fs_ftruncate(const char *, off_t, struct fuse_file_info *);
int elf_fs_lock(const char *, struct fuse_file_info *, int, struct flock *);
int elf_fs_utimens(const char *, const struct timespec[2]);
int elf_fs_bmap(const char *, size_t, uint64_t *);

#if 0
int elf_fs_ioctl(const char *, int, void *, struct fuse_file_info *, unsigned int, void *);
int elf_fs_poll(const char *, struct fuse_file_info *, struct fuse_pollhandle *, unsigned *);
#endif

int elf_fs_getattr(const char *, struct stat *);
int elf_fs_chmod(const char *, mode_t);
int elf_fs_chown(const char *, uid_t, gid_t);
int elf_fs_create(const char *, mode_t, struct fuse_file_info *);
int elf_fs_fsync(const char *, int, struct fuse_file_info *);
int elf_fs_mkdir(const char *, mode_t);
int elf_fs_mknod(const char *, mode_t, dev_t);
int elf_fs_open(const char *, struct fuse_file_info *);
int elf_fs_read(const char *, char *, size_t, off_t, struct fuse_file_info *);
int elf_fs_opendir(const char *, struct fuse_file_info *);
int elf_fs_readdir(const char *, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);
int elf_fs_readlink(const char *, char *, size_t);
int elf_fs_release(const char *, struct fuse_file_info *);
int elf_fs_rename(const char *, const char *);
int elf_fs_rmdir(const char *);
int elf_fs_setxattr(const char *, const char *, const char *, size_t, int);
int elf_fs_statfs(const char *, struct statvfs *);
int elf_fs_symlink(const char *, const char *);
int elf_fs_unlink(const char *);
int elf_fs_write(const char *, const char *, size_t, off_t, struct fuse_file_info *);

// void *elfs_fs_init(struct fuse_conn_info *);
// void elfs_fs_destroy(void *);

int elf_namei(telf_ctx *, const char *, telf_obj **objp);


#endif /* FSAPI_H */
