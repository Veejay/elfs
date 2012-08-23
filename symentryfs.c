#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "log.h"
#include "symentryfs.h"
#include "misc.h"
#include "elfs.h"
#include "defaultfs.h"

telf_ctx *ctx;


#define CHUNK_SIZE 4096

static telf_status
symentryfs_setcontent_code(void *obj_hdl,
                           char **bufp,
                           size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_default_content *content = obj->data;
        Elf64_Sym *sym = obj->parent->data;
        Elf64_Shdr *shdr = obj->ctx->shdr + sym->st_shndx;

        // sanity check
        if (content->buf) {
                free(content->buf);
                content->buf = NULL;
        }

        content->buf_len = sym->st_size;

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

static telf_status
symentryfs_setcontent_info(void *obj_hdl,
                           char **bufp,
                           size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_default_content *content = obj->data;
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
                   elf_dsymname)(obj->ctx, sym);

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

static struct {
        char *str;
        tobj_setcontent_func setcontent_func;
}  symentryfs_fcb[] = {
        { .str = "code", .setcontent_func = symentryfs_setcontent_code },
        { .str = "info", .setcontent_func = symentryfs_setcontent_info },
};

telf_status
symentryfs_build(telf_ctx *ctx,
                 telf_obj *parent)
{
        telf_status ret;
        telf_status rc;
        telf_obj *entry = NULL;
        int i;

        for (i = 0; i < N_ELEMS(symentryfs_fcb); i++) {
                entry = elf_obj_new(ctx, symentryfs_fcb[i].str,
                                    parent,
                                    ELF_SYMBOL_ENTRY,
                                    ELF_S_IFREG);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'",
                            symentryfs_fcb[i].str);
                        continue;
                }

                entry->fill = symentryfs_fcb[i].setcontent_func;
                list_add(parent->entries, entry);
        }


        ret = ELF_SUCCESS;
  end:
        return ret;
}
