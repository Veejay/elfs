#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "elfs.h"
#include "fsapi.h"
#include "log.h"

extern telf_ctx *ctx;

static void
elf_est_to_st(telf_stat *est,
              struct stat *st)
{
        assert(NULL != st);
        assert(NULL != est);

        st->st_nlink = est->st_nlink;

        if (ELF_S_ISDIR(est->st_mode))
                st->st_mode |= S_IFDIR;

        if (ELF_S_ISREG(est->st_mode))
                st->st_mode |= S_IFREG;

        if (ELF_S_ISLNK(est->st_mode))
                st->st_mode |= S_IFLNK;

#define X(f) if (ELF_S_##f & est->st_mode) st->st_mode |= S_##f
        X(IRWXU); // 00700 user
        X(IRUSR); // 00400 user has read permission
        X(IWUSR); // 00200 user has write permission
        X(IXUSR); // 00100 user has execute permission
        X(IRWXG); // 00070 group has read, write and execute permission
        X(IRGRP); // 00040 group has read permission
        X(IWGRP); // 00020 group has write permission
        X(IXGRP); // 00010 group has execute permission
        X(IRWXO); // 00007 others have read, write and execute permission
        X(IROTH); // 00004 others have read permission
        X(IWOTH); // 00002 others have write permission
        X(IXOTH); // 00001 others have execute permission

        st->st_size = est->st_size;
}

telf_status
elf_namei(telf_ctx *ctx,
          const char *path_,
          telf_obj **objp)
{
        telf_status ret;
        telf_obj *obj = NULL;
        telf_obj *parent = NULL;
        char *p = NULL;
        char *start = NULL;
        char *current = NULL;
        char *path = NULL;

        path = (char *) path_;

        p = path;

        if (0 == strcmp(path, "/")) {
                obj = ctx->root;
                assert(NULL != obj);

                /* success, we got the root dir */
                ret = ELF_SUCCESS;
                goto end;
        }

        while ('/' == *p)
                p++;

        parent = ctx->root;

        while (p) {

                start = p;

                while (p && *p && '/' != *p)
                        p++;

                current = strndup(start, (size_t) (p - start));
                if (! current) {
                        ERR("strndupa: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }


                if (! parent->entries) {
                        ERR("no entries for parent '%s'",
                            parent->name);
                        ret = ELF_ENOENT;
                        goto end;
                }

                obj = list_get(parent->entries, current);
                if (! obj) {
                        ERR("can't get entry '%s'", current);
                        ret = ELF_ENOENT;
                        goto end;
                }

                free(current);

                while ('/' == *p)
                        p++;

                /* end of the path */
                if (NULL == p || 0 == *p)
                        break;

                parent = obj;
        }

        ret = ELF_SUCCESS;
  end:
        if (objp)
                *objp = obj;

        return ret;
}

int
elf_fs_getxattr(const char *path,
                const char *name,
                char *value,
                size_t size)
{
        DEBUG("path=%s, value=%s", path, value);
        return 0;
}

int
elf_fs_listxattr(const char *path,
                 char *list,
                 size_t size)
{
        DEBUG("path=%s, list=%s, size=%zu", path, list, size);
        return 0;
}

int
elf_fs_removexattr(const char *path,
                   const char *name)
{
        DEBUG("path=%s, name=%s", path, name);
        return 0;
}

int
elf_fs_flush(const char *path,
             struct fuse_file_info *info)
{
        (void) info;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_truncate(const char *path,
                off_t offset)
{
        (void) offset;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_utime(const char *path,
             struct utimbuf *times)
{
        (void) times;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_releasedir(const char *path,
                  struct fuse_file_info *info)
{
        telf_obj *obj = (telf_obj *) info->fh;
        int ret;
        telf_status rc;

        DEBUG("%s", path);

        if (! obj) {
                rc = elf_namei(ctx, path, &obj);
                if (ELF_SUCCESS != rc) {
                        ERR("can't find object with key '%s': %s",
                            path, elf_status_to_str(rc));
                        ret = -1;
                        goto end;
                }
        }

        rc = obj->driver->releasedir(obj);
        if (ELF_SUCCESS != rc) {
                ERR("releasedir failed: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        ret = 0;
  end:
        return ret;
}

int
elf_fs_fsyncdir(const char *path,
                int datasync,
                struct fuse_file_info *info)
{
        (void) datasync;
        (void) info;

        DEBUG("%s", path);
        return 0;
}

void *
elf_fs_init(struct fuse_conn_info *conn)
{
        return NULL;
}

void
elf_fs_destroy(void *arg)
{
        DEBUG("%p", arg);
}

int
elf_fs_access(const char *path, int perm)
{
        (void) perm;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_ftruncate(const char *path,
                 off_t offset,
                 struct fuse_file_info *info)
{
        (void) offset;
        (void) info;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_lock(const char *path,
            struct fuse_file_info *info,
            int cmd,
            struct flock *flock)
{
        (void) info;
        (void) cmd;
        (void) flock;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_utimens(const char *path,
               const struct timespec tv[2])
{
        (void) path;
        (void) tv;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_bmap(const char *path,
            size_t blocksize,
            uint64_t *idx)
{
        (void) blocksize;
        (void) idx;

        DEBUG("%s", path);
        return 0;
}

#if 0
int
elf_fs_ioctl(const char *path,
             int cmd,
             void *arg,
             struct fuse_file_info *info,
             unsigned int flags,
             void *data)
{
        DEBUG("%s", path);
        return 0;
}

int
elf_fs_poll(const char *path,
            struct fuse_file_info *info,
            struct fuse_pollhandle *ph,
            unsigned *reventsp)
{
        (void) info;
        (void) ph;
        (void) reventsp;

        DEBUG("%s", path);
        return 0;
}
#endif

int
elf_fs_getattr(const char *path,
               struct stat *st)
{
        telf_fs_driver *driver;
        telf_stat est;
        telf_obj *obj = NULL;
        telf_status rc;
        int ret;

        DEBUG("%s", path);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ret = -ENOENT;
                goto end;
        }

        rc = obj->driver->getattr(obj, &est);
        if (ELF_SUCCESS != rc) {
                ERR("getattr failed: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        elf_est_to_st(&est, st);

        ret = 0;
  end:
        DEBUG("path=%s, ret=%d", path, ret);
        return ret;
}

int
elf_fs_chmod(const char *path,
             mode_t mode)
{
        (void) mode;
        DEBUG("%s", path);
        return 0;
}

int
elf_fs_chown(const char *path,
             uid_t uid,
             gid_t gid)
{
        DEBUG("%s: uid=%u, gid=%u", path, uid, gid);
        return 0;
}

int
elf_fs_create(const char *path,
              mode_t mode,
              struct fuse_file_info *info)
{
        (void) mode;
        (void) info;

        DEBUG("%s", path);
        return 0;
}

int
elf_fs_fsync(const char *path,
             int issync,
             struct fuse_file_info *info)
{
        return 0;
}

int
elf_fs_mkdir(const char *path,
             mode_t mode)
{
        return 0;
}

int
elf_fs_mknod(const char *path,
             mode_t mode,
             dev_t dev)
{
        return 0;
}

int
elf_fs_open(const char *path,
            struct fuse_file_info *info)
{
        telf_obj *obj = NULL;
        telf_status rc;
        int ret;

        DEBUG("path=%s", path);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("namei(%s) failed: %d", path, rc);
                ret = -ENOENT;
                goto end;
        }

        /*XXX weirdo... we should not have drivers alongside the obj...
         *
         * the open() callback is more like a constructor here, it fills
         * the chunk associated to 'obj' with appropriate data
         *
         * from an API point of view it kind of sucks -- maybe I should
         * rework the whole API and use a per-obj file handler, with
         * global contextes, each one embedding its fs driver
         */
        rc = obj->driver->open((char *) path, 0u /* XXX */, (void **) &obj);
        if (ELF_SUCCESS != rc) {
                ERR("open failed: %s", elf_status_to_str(rc));
                ret = -EIO;
                goto end;
        }

        info->fh = (uint64_t) (uintptr_t) obj;

        ret = 0;
  end:
        return ret;
}

int
elf_fs_read(const char *path,
            char *buf,
            size_t size,
            off_t offset,
            struct fuse_file_info *info)
{
        telf_obj *obj = (telf_obj *) info->fh;
        telf_status ret;
        telf_status rc;
        ssize_t cc;

        DEBUG("path=%s", path);

        if (! obj) {
                ret = -ENOENT;
                goto end;
        }

        rc = obj->driver->read(obj, buf, size, offset, &cc);
        if (rc != ELF_SUCCESS) {
                ERR("%s: can't read %zu bytes @offset: %zd: %s",
                    path, size, offset, elf_status_to_str(rc));
                ret = -EIO;
                goto end;
        }

        ret = cc;
  end:
        return ret;
}

int
elf_fs_write(const char *path,
             const char *buf,
             size_t size,
             off_t offset,
             struct fuse_file_info *info)
{
        telf_obj *obj = (telf_obj *) info->fh;
        telf_status ret;
        telf_status rc;
        ssize_t cc;

        DEBUG("path=%s", path);

        if (! obj) {
                rc = elf_namei(ctx, path, &obj);
                if (ELF_SUCCESS != rc) {
                        ERR("can't find object with key '%s': %s",
                            path, elf_status_to_str(rc));
                        ret = -ENOENT;
                        goto end;
                }
        }

        rc = obj->driver->write(obj, buf, size, offset, &cc);
        if (ELF_SUCCESS != rc) {
                ERR("%s: can't write %zu bytes @offset: %zd: %s",
                    path, size, offset, elf_status_to_str(rc));
                ret = -EIO;
                goto end;
        }

        ret = cc;
  end:
        return ret;
}

int
elf_fs_opendir(const char *path,
               struct fuse_file_info *info)
{
        return 0;
}

int
elf_fs_readdir(const char *path,
               void *data,
               fuse_fill_dir_t fill,
               off_t offset,
               struct fuse_file_info *info)
{
        int ret;
        telf_status rc;
        telf_obj *obj;

        DEBUG("path=%s", path);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("can't find object with key '%s': %s",
                    path, elf_status_to_str(rc));
                ret = -ENOENT;
                goto end;
        }

        rc = obj->driver->readdir(obj, data, fill);
        if (ELF_SUCCESS != rc) {
                ERR("readdir failed: %s", elf_status_to_str(rc));
                ret = -EIO;
                goto end;
        }

        ret = 0;
  end:
        return ret;

}

int
elf_fs_readlink(const char *path,
                char *buf,
                size_t bufsiz)
{
        telf_fs_driver *driver;
        telf_stat est;
        telf_obj *obj = NULL;
        telf_status rc;
        int ret;

        DEBUG("%s", path);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ret = -ENOENT;
                goto end;
        }

        rc = obj->driver->readlink(obj, &buf, &bufsiz);
        if (ELF_SUCCESS != rc) {
                ERR("getattr failed: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        ret = 0;
  end:
        DEBUG("path=%s, ret=%d", path, ret);
        return ret;
}

int
elf_fs_release(const char *path,
               struct fuse_file_info *info)
{
        telf_obj *obj = (telf_obj *) info->fh;
        int ret;
        telf_status rc;

        if (! obj) {
                rc = elf_namei(ctx, path, &obj);
                if (ELF_SUCCESS != rc) {
                        ERR("can't find object with key '%s': %s",
                            path, elf_status_to_str(rc));
                        ret = -ENOENT;
                        goto end;
                }
        }

        rc = obj->driver->release(obj);
        if (ELF_SUCCESS != rc) {
                ERR("release failed: %s", elf_status_to_str(rc));
                ret = -EIO;
                goto end;
        }

        ret = 0;
  end:
        return ret;
}

int
elf_fs_rename(const char *oldpath,
              const char *newpath)
{
        return 0;
}

int
elf_fs_rmdir(const char *path)
{
        return 0;
}

int
elf_fs_setxattr(const char *path,
                const char *name,
                const char *value,
                size_t size,
                int flag)
{
        return 0;
}

int
elf_fs_statfs(const char *path,
              struct statvfs *buf)
{
        DEBUG("path=%s, buf=%p", path, (void *) buf);

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
elf_fs_symlink(const char *oldpath,
               const char *newpath)
{
        return 0;
}

int
elf_fs_unlink(const char *path)
{
        return 0;
}


