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

static telf_status
programfs_setcontent_code(void *obj_hdl,
                          char **bufp,
                          size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_default_content *content = obj->data;
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

static struct {
        char *str;
        tobj_setcontent_func setcontent_func;
} programfs_fcb[] = {
        { .str = "code", .setcontent_func = programfs_setcontent_code },
};


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

        for (i = 0; i < N_ELEMS(programfs_fcb); i++) {

                entry = elf_obj_new(obj->ctx, programfs_fcb[i].str, obj,
                                    ELF_SECTION_PROGBITS_CODE,
                                    ELF_S_IFREG);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'",
                            programfs_fcb[i].str);
                        continue;
                }

                entry->fill = programfs_fcb[i].setcontent_func;
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
