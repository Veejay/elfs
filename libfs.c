#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "elfs.h"
#include "log.h"
#include "misc.h"
#include "libfs.h"


#define ELF_DEFAULT_LIBPATH "/usr/lib/"
#define LD_SO_CONF "/etc/ld.so.conf"

static telf_status
libfs_open(char *path,
           telf_open_flags flags,
           void **objp)
{
        return ELF_FAILURE;
}


static telf_status
libfs_getattr(void *obj_hdl,
              telf_stat *stp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        telf_stat st;
        int i;

        elf_obj_lock(obj);

        memset(&st, 0, sizeof st);
        st.st_mode |= ELF_S_IFLNK;
        st.st_mode |= ELF_S_IRWXU|ELF_S_IRWXG|ELF_S_IRWXO;
        st.st_size = 0;

        ret = ELF_SUCCESS;
  end:

        elf_obj_unlock(obj);

        if (stp)
                *stp = st;
        return ret;
}

telf_status
libfs_readlink(void *obj_hdl,
               char **bufp,
               size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        Elf64_Shdr *shdr = NULL;
        char path[PATH_MAX];
        char *buf = NULL;
        size_t buf_len = 0;
        int i;

        elf_obj_lock(obj);

        for (i = 0; i < list_get_size(obj->ctx->libpath); i++) {
                char *lp = list_get_nth(obj->ctx->libpath, i);
                char path[PATH_MAX] = "";

                snprintf(path, sizeof path, "%s/%s", lp, obj->name);

                if (-1 == access(path, R_OK)) {
                        if (ENOENT != errno)
                                ERR("access: %s", strerror(errno));

                        continue;
                }

                buf = strdup(path);
                if (! buf) {
                        ERR("malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                buf_len = strlen(buf);
                break;
        }

        ret = ELF_SUCCESS;
  end:

        elf_obj_unlock(obj);

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

static void
libfs_override_driver(telf_fs_driver *driver)
{
        driver->getattr  = libfs_getattr;
        driver->open     = libfs_open;
        driver->readlink = libfs_readlink;
}


static telf_status
elf_set_default_libpath(telf_ctx *ctx)
{
        telf_status ret;
        char path[PATH_MAX];
        FILE *fp;
        char *line = NULL;
        size_t len = 0;
        ssize_t read;
        char inc[128] = "";
        FILE *cat = NULL;
        char *default_libpath = NULL;

        ctx->libpath = list_new();
        if (! ctx->libpath) {
                ERR("can't create libpath list");
                ret = ELF_FAILURE;
                goto end;
        }

        default_libpath = strdup(ELF_DEFAULT_LIBPATH);
        if (! default_libpath) {
                ERR("strdup: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        list_add(ctx->libpath, default_libpath);

        fp = fopen(LD_SO_CONF, "r");
        if (! fp) {
                ERR("fopen(%s): %s", LD_SO_CONF, strerror(errno));
                ret = ELF_FAILURE;
                goto end;
        }

        /* XXX/TODO: this is so ugly I can't even look at this code..
         *   1. respect all the possible formats for ld.so.conf (not only the
         *      'include' stuff)
         *   2. real error handling, please :/
         **/
        while ((read = getline(&line, &len, fp)) != -1) {
                if (strstr(line, "include ")) {
                        char cmd[1024] = "";
                        char out[1024] = "";
                        sscanf(line, "include %1024s", out);
                        snprintf(cmd, sizeof cmd, "cat %s", out);

                        cat = popen(cmd, "r");
                        if (! cat) {
                                ERR("popen: %s", strerror(errno));
                                ret = ELF_FAILURE;
                                goto end;
                        }

                        while (fgets(cmd, sizeof cmd - 1, cat)) {
                                char *libpath = NULL;

                                /* remove trailing EOL */
                                cmd[strlen(cmd) - 1] = 0;

                                libpath = strdup(cmd);
                                if (! libpath) {
                                        ERR("malloc: %s", strerror(errno));
                                        ret = ELF_ENOMEM;
                                        goto end;
                                }

                                list_add(ctx->libpath, libpath);
                        }
                }
        }

        ret = 0;
  end:
        if (fp)
                fclose(fp);

        if (line)
                free(line);

        if (cat)
                pclose(cat);

        return ret;
}

telf_status
libfs_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;
        telf_obj *libfs_obj = NULL;
        telf_obj *entry = NULL;
        int i;
        Elf64_Shdr *shdr = NULL;
        Elf64_Dyn *dyn = NULL;

        /* sanity check */
        rc = elf_namei(ctx, "/libs", &libfs_obj);
        if (ELF_SUCCESS != rc) {
                ERR("can't find '/libfs' object: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        shdr = elf_getsectionbytype(ctx, SHT_DYNAMIC);
        if (! shdr) {
                ERR("can't find any SHT_DYNAMIC section");
                ret = ELF_ENOENT;
                goto end;
        }

        /* get all DT_NEEDED strings. */
        for (i = 0; i < shdr->sh_size / sizeof(Elf64_Dyn); i++) {
                telf_obj *entry = NULL;
                char *libname = NULL;

                dyn = (Elf64_Dyn *) (ctx->addr + shdr->sh_offset) + i;

                if (DT_NEEDED != dyn->d_tag)
                        continue;

                libname = strdup(ctx->dstrtab + dyn->d_un.d_val);
                if (! libname) {
                        ERR("strdup(%s): %s", libname, strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                entry = elf_obj_new(ctx, libname, libfs_obj,
                                    ELF_LIBS_ENTRY,
                                    ELF_S_IFLNK);
                if (! entry) {
                        ERR("can't build entry '%s'", libname);
                        continue;
                }

                libfs_override_driver(entry->driver);
                list_add(libfs_obj->entries, entry);
        }

        rc = elf_set_default_libpath(ctx);
        if (ELF_SUCCESS != rc) {
                ERR("Can't set libpath list");
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}
