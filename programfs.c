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

static void
programfs_freecontent(void *data)
{
        telf_default_content *content = data;

        if (! content)
                return;

        if (content->buf)
                free(content->buf);

        free(content);
}

static telf_status
programfs_code_getsize(void *obj_hdl,
                       size_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        char realname[128];
        Elf64_Shdr *shdr = NULL;
        size_t size;

        sprintf(realname, ".%s", obj->parent->name);
        shdr = elf_getsectionbyname(ctx, realname);

        size = shdr->sh_size;

        ret = ELF_SUCCESS;
  end:
        if (sizep)
                *sizep = size;

        return ret;
}

static telf_status
programfs_code_setcontent(void *obj_hdl,
                          char **bufp,
                          size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        char realname[128];
        Elf64_Shdr *shdr = NULL;
        char *buf = NULL;
        size_t buf_len = 0;

        sprintf(realname, ".%s", obj->parent->name);
        shdr = elf_getsectionbyname(ctx, realname);

        buf_len = shdr->sh_size;

        if (buf_len) {
                buf = malloc(buf_len);
                if (! buf) {
                        LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                memcpy(buf, obj->ctx->addr + shdr->sh_offset, buf_len);
        }

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

typedef struct {
        char *str;
        tobj_getsize_func getsize_func;
        tobj_setcontent_func setcontent_func;
        tobj_freecontent_func freecontent_func;
} telf_fcb;

static telf_fcb programfs_fcb[] = {
        {
                "code",
                programfs_code_getsize,
                programfs_code_setcontent,
                programfs_freecontent
        },
};



static telf_status
programfs_getattr(void *obj_hdl,
                  telf_stat *stp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        telf_stat st;
        int i;

        elf_obj_lock(obj);

        memset(&st, 0, sizeof st);
        st.st_mode |= ELF_S_IFREG;

        for (i = 0; i < N_ELEMS(programfs_fcb); i++) {
                telf_fcb *fcb = programfs_fcb + i;

                if (0 == strcmp(obj->name, fcb->str)) {
                        rc = fcb->getsize_func(obj, &st.st_size);
                        if (ELF_SUCCESS != rc) {
                                LOG(LOG_ERR, 0, "can't get size of '%s'",
                                    obj->name);
                                ret = rc;
                                goto end;
                        }
                        break;
                }
        }

        ret = ELF_SUCCESS;
  end:
        elf_obj_unlock(obj);

        if (stp)
                *stp = st;

        return ret;
}

static void
programfs_override_driver(telf_fs_driver *driver)
{
        driver->getattr = programfs_getattr;
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

        for (i = 0; i < N_ELEMS(programfs_fcb); i++) {

                telf_fcb *fcb = programfs_fcb + i;
                entry = elf_obj_new(obj->ctx, fcb->str, obj,
                                    ELF_SECTION_PROGBITS_CODE,
                                    ELF_S_IFREG);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'", fcb->str);
                        continue;
                }

                entry->free_func = fcb->freecontent_func;
                entry->fill_func = fcb->setcontent_func;

                programfs_override_driver(entry->driver);
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
