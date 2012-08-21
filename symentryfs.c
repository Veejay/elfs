#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "log.h"
#include "symentryfs.h"
#include "misc.h"
#include "elfs.h"
#include "defaultfs.h"
#include "misc.h"

telf_ctx *ctx;

typedef struct {
        char *buf;
        size_t buf_len;
} telf_symentry_content;


#define CHUNK_SIZE 4096

static telf_status
elf_obj_set_content_code_func(telf_obj *obj,
                              char **bufp,
                              size_t *buf_lenp)
{
        int ret;
        telf_symentry_content *content = obj->data;
        Elf64_Sym *sym = obj->parent->data;
        Elf64_Shdr *shdr = obj->ctx->shdr + sym->st_shndx;
        char *symname = NULL;

        // sanity check
        if (content->buf) {
                free(content->buf);
                content->buf = NULL;
        }

        ret = ELF_SUCCESS;
        return ret;
}

static telf_status
elf_obj_set_content_info_func(telf_obj *obj,
                              char **bufp,
                              size_t *buf_lenp)
{
        telf_status ret;
        telf_symentry_content *content = obj->data;
        Elf64_Sym *sym = obj->parent->data;
        char *symname = NULL;

        // sanity check
        if (content->buf) {
                free(content->buf);
                content->buf = NULL;
        }

        content->buf = malloc(CHUNK_SIZE);
        if (! content->buf) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        symname = ((ELF_SECTION_SYMTAB == obj->parent->type) ?
                   elf_symname :
                   elf_dsymname)(ctx, sym);

        if (! *symname)
                symname = "UNRESOLVED";

        content->buf_len = sprintf(content->buf,
                                   "num: %d\n"
                                   "value: %p\n"
                                   "size: %zu\n"
                                   "type: %s\n"
                                   "bind: %s\n"
                                   "vis: %c\n"
                                   "ndx: %s\n"
                                   "name: %s\n",
                                   0, // num
                                   sym ? sym : NULL,
                                   sym ? sym->st_size : 0u,
                                   sym_type_to_str(sym),
                                   sym_bind_to_str(sym),
                                   sym ? sym->st_other : 0u,
                                   "none", // ndx
                                   symname);


        LOG(LOG_DEBUG, 0, "buf: %s, @buf: %p", content->buf, (void *) content->buf);

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = content->buf;
        else {
                free(content->buf);
                content->buf = NULL;
        }

        if (buf_lenp)
                *buf_lenp = content->buf_len;

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

static telf_status
elf_obj_set_content(telf_obj *obj,
                    char **bufp,
                    size_t *buf_lenp)
{
        int i;
        telf_status rc;
        telf_status ret;

        for (i = 0; i < N_ELEMS(e_names); i++) {
                if (0 == strcmp(obj->name, e_names[i].str)) {
                        rc = e_names[i].set_content_func(obj, bufp, buf_lenp);
                        if (ELF_SUCCESS != rc) {
                                ret = rc;
                                goto end;
                        }

                        break;
                }
        }

        ret = ELF_SUCCESS;
  end:

        return ret;
}





/* file */

telf_status
symentryfs_getattr(void *obj_hdl,
                   telf_stat *st)
{
        telf_status ret;
        telf_status rc;
        telf_obj *obj = obj_hdl;
        size_t size;
        telf_symentry_content *content;

        content = malloc(sizeof *content);
        assert(NULL != content);

        memset(content, 0, sizeof *content);

        obj->data = content;

        /* we compute the content on-the-fly, in order to set the
         * correct file size: not very efficient but who care? */
        rc = elf_obj_set_content(obj, NULL, &size);
        if (ELF_SUCCESS != rc) {
                ret = rc;
                goto end;
        }

        st->st_nlink = 1;
        st->st_mode = ELF_S_IFREG | ELF_S_IRUSR;
        st->st_size = size;

        ret = ELF_SUCCESS;
  end:
        return ret;
}

telf_status
symentryfs_open(char *path,
                telf_open_flags flags,
                void **objp)
{
        telf_status ret;
        telf_status rc;
        telf_obj *obj;
        char *buf;
        size_t buf_len;
        telf_symentry_content *content;

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ret = rc;
                goto end;
        }

        content = malloc(sizeof *content);
        if (! content) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        rc = elf_obj_set_content(obj, &content->buf, &content->buf_len);
        if (ELF_SUCCESS != rc) {
                ret = rc;
                goto end;
        }

        if (obj->data)
                free(obj->data);

        obj->data = content;

        ret = ELF_SUCCESS;
  end:

        if (objp)
                *objp = obj;

        return ret;
}

telf_status
symentryfs_release(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;

        if (obj->data) {
                free(obj->data);
                obj->data = NULL;
        }

        return ELF_SUCCESS;
}

telf_status
symentryfs_read(void *obj_hdl,
                char *buf,
                size_t size,
                off_t offset,
                size_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_symentry_content *content = obj->data;

        if (size > content->buf_len)
                size = content->buf_len;

        memcpy(buf, content->buf + offset, size);

        LOG(LOG_DEBUG, 0, "read: %s, return %zu", buf, size);

        if (sizep)
                *sizep = size;

        return ELF_SUCCESS;
}

telf_status
symentryfs_write(void *obj,
                 const char *buf,
                 size_t size,
                 off_t offset,
                 size_t *sizep)
{
        return ELF_SUCCESS;
}



/* directory */


telf_status
symentryfs_opendir(char *path,
                   void **objp)
{
        return ELF_SUCCESS;
}

telf_status
symentryfs_readdir(void *obj,
                   void *data,
                   fuse_fill_dir_t fill)
{
        return ELF_SUCCESS;
}

telf_status
symentryfs_releasedir(void *obj)
{
        return ELF_SUCCESS;
}


telf_fs_driver symentryfs_driver = {
        .getattr    = symentryfs_getattr,
        .open       = symentryfs_open,
        .release    = symentryfs_release,
        .read       = symentryfs_read,
        .write      = symentryfs_write,
        .opendir    = symentryfs_opendir,
        .readdir    = symentryfs_readdir,
        .releasedir = symentryfs_releasedir,
};


/**
 * @ctx the global context
 * @obj the symtab object
 */
telf_status
symentryfs_build(telf_ctx *ctx,
                 telf_obj *parent)
{
        telf_status ret;
        telf_status rc;
        telf_obj *entry = NULL;
        int i;

        /* parent->driver = symentryfs_driver; */
        parent->driver = *defaultfs_driver_new();

        rc = elf_obj_list_new(parent);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "consider this directory as empty...");
                ret = rc;
                goto end;
        }

        for (i = 0; i < N_ELEMS(e_names); i++) {
                entry = elf_obj_new(ctx, e_names[i].str, parent, ELF_SYMBOL_ENTRY);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'",
                        e_names[i].str);
                        continue;
                }

                entry->driver = symentryfs_driver;
                list_add(parent->entries, entry);
        }


        ret = ELF_SUCCESS;
  end:
        return ret;
}
