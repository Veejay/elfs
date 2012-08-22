#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "log.h"
#include "misc.h"
#include "elfs.h"
#include "defaultfs.h"
#include "programfs.h"


telf_ctx *ctx;

typedef struct {
        char *buf;
        size_t buf_len;
} telf_program_content;


#define CHUNK_SIZE 4096

static telf_status
elf_obj_set_content_code_func(telf_obj *obj,
                              char **bufp,
                              size_t *buf_lenp)
{
        telf_status ret;
        telf_program_content *content = obj->data;
        char realname[128];
        Elf64_Shdr *shdr = NULL;

        sprintf(realname, ".%s", obj->parent->name);
        shdr = elf_getsectionbyname(ctx, realname);

        // sanity check
        if (content->buf) {
                free(content->buf);
                content->buf = NULL;
        }

        content->buf_len = shdr->sh_size;

        if (content->buf_len) {
                content->buf = malloc(content->buf_len);
                if (! content->buf) {
                        LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                memcpy(content->buf,
                       obj->ctx->addr + shdr->sh_offset,
                       content->buf_len);
        }

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = content->buf;

        if (buf_lenp)
                *buf_lenp = content->buf_len;

        return ret;
}

typedef telf_status (* tobj_set_content_func)(telf_obj *, char **, size_t *);

static struct {
        char *str;
        tobj_set_content_func set_content_func;
} e_names[] = {
        { .str = "code", .set_content_func = elf_obj_set_content_code_func },
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
programfs_getattr(void *obj_hdl,
                  telf_stat *st)
{
        telf_status ret;
        telf_status rc;
        telf_obj *obj = obj_hdl;
        size_t size;
        telf_program_content *content;

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
programfs_open(char *path,
               telf_open_flags flags,
               void **objp)
{
        telf_status ret;
        telf_status rc;
        telf_obj *obj;
        char *buf;
        size_t buf_len;
        telf_program_content *content;

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
programfs_release(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;

        if (obj->data) {
                free(obj->data);
                obj->data = NULL;
        }

        return ELF_SUCCESS;
}

telf_status
programfs_read(void *obj_hdl,
               char *buf,
               size_t size,
               off_t offset,
               ssize_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_program_content *content = obj->data;
        telf_status ret;

        if (size > content->buf_len)
                size = content->buf_len;

        memcpy(buf, content->buf + offset, size);

        if (sizep)
                *sizep = size;

        return ELF_SUCCESS;
}

telf_status
programfs_write(void *obj,
                const char *buf,
                size_t size,
                off_t offset,
                ssize_t *sizep)
{
        return ELF_SUCCESS;
}



static void
programfs_driver_update(telf_fs_driver *driver)
{
        driver->getattr    = programfs_getattr;
        driver->open       = programfs_open;
        driver->release    = programfs_release;
        driver->read       = programfs_read;
}

static void
section_ctor_cb(void *obj_hdl,
                void *to_ignore)
{
        int i;
        telf_obj *obj = obj_hdl;
        telf_obj *entry = NULL;
        telf_status rc;

        if (ELF_SECTION_PROGBITS != obj->type)
                return;

        LOG(LOG_ERR, 0, "name=%s", obj->name);

        for (i = 0; i < N_ELEMS(e_names); i++) {
                entry = elf_obj_new(obj->ctx, e_names[i].str, obj,
                                    ELF_SECTION_PROGBITS_CODE);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'",
                            e_names[i].str);
                        continue;
                }

                programfs_driver_update(entry->driver);
                list_add(obj->entries, entry);
        }

}

telf_status
programfs_build(telf_ctx *ctx)
{
        telf_obj *obj_sections = NULL;
        telf_obj *section = NULL;
        telf_status ret;
        int rc;
        int i;

        rc = elf_namei(ctx, "/sections", &obj_sections);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can't find '/sections' object: %s",
                    elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        list_map(obj_sections->entries, section_ctor_cb, NULL);

        ret = ELF_SUCCESS;
  end:
        return ret;

}
