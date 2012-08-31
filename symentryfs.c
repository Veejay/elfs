#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include <udis86.h>

#include "log.h"
#include "symentryfs.h"
#include "misc.h"
#include "elfs.h"
#include "defaultfs.h"

telf_ctx *ctx;


#define CHUNK_SIZE 4096

static void
symentryfs_freecontent(void *data)
{
        telf_default_content *content = data;

        if (! content)
                return;

        if (content->buf)
                free(content->buf);

        free(content);
}

static telf_status
symentryfs_setcontent_asmcode(void *obj_hdl,
                              char **bufp,
                              size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_default_content *content = obj->data;
        Elf64_Sym *sym = obj->parent->data;
        Elf64_Shdr *shdr = obj->ctx->shdr + sym->st_shndx;
        ud_t ud_obj;

        // sanity check
        if (content->buf) {
                free(content->buf);
                content->buf = NULL;
                content->buf_len = 0;
        }


        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size) {

                ud_init(&ud_obj);
                ud_set_input_buffer(&ud_obj,
                                    (char *) obj->ctx->addr + sym->st_value,
                                    sym->st_size);
                ud_set_mode(&ud_obj, 64);
                ud_set_syntax(&ud_obj, UD_SYN_INTEL);

                while (ud_disassemble(&ud_obj)) {
                        char line[64];
                        size_t len;
                        char *tmp;

                        len = sprintf(line, "%s\n", ud_insn_asm(&ud_obj));
                        tmp = realloc(content->buf, content->buf_len + len);
                        if (! tmp) {
                                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                                free(content->buf);
                                content->buf_len = 0;
                                content->buf = NULL;
                                ret = ELF_ENOMEM;
                                goto end;
                        }

                        content->buf = tmp;
                        memmove(content->buf + content->buf_len, line, len);
                        content->buf_len += len;
                }
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
symentryfs_setcontent_bincode(void *obj_hdl,
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
                content->buf_len = 0;
        }

        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size) {
                content->buf_len = sym->st_size;
                content->buf = malloc(content->buf_len);
                if (! content->buf) {
                        LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                memcpy(content->buf,
                       obj->ctx->addr + shdr->sh_offset,
                       sym->st_size);
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
        char tmpbuf[256];

        if (! content) {
                content = malloc(sizeof *content);
                if (! content) {
                        LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                memset(content, 0, sizeof *content);
        }

        // sanity check
        if (content->buf)
                free(content->buf);

        /* default value */
        symname = "NONAME";

        if (sym->st_name) {
                symname = ((ELF_SECTION_SYMTAB == obj->parent->type) ?
                           elf_getsymname :
                           elf_getdsymname)(obj->ctx, sym);

                if (! symname || ! *symname)
                        symname = "UNRESOLVED";
        }

        content->buf_len = sprintf(tmpbuf,
                                   "value: %p\n"
                                   "size: %zu\n"
                                   "type: %s\n"
                                   "bind: %s\n"
                                   "name: %s\n",
                                   sym ? (void *) sym->st_value : NULL,
                                   sym ? sym->st_size : 0u,
                                   sym_type_to_str(sym),
                                   sym_bind_to_str(sym),
                                   symname);

        content->buf = malloc(content->buf_len + 1);
        if (! content->buf) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        strncpy(content->buf, tmpbuf, content->buf_len);


        LOG(LOG_DEBUG, 0, "buf: %s, @buf: %p", content->buf, (void *) content->buf);

        ret = ELF_SUCCESS;
  end:
        if (bufp) {
                *bufp = content->buf;
        } else {
                free(content->buf);
                content->buf = NULL;
        }

        if (buf_lenp)
                *buf_lenp = content->buf_len;

        return ret;
}

typedef struct {
        char *str;
        tobj_setcontent_func setcontent_func;
        tobj_freecontent_func freecontent_func;
} telf_fcb;

static telf_fcb symentryfs_fcb[] = {
        { "code.bin", symentryfs_setcontent_bincode, symentryfs_freecontent },
        /* { "code.asm", symentryfs_setcontent_asmcode, symentryfs_freecontent }, */
        { "info", symentryfs_setcontent_info, symentryfs_freecontent },
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
                telf_fcb *fcb = symentryfs_fcb + i;

                entry = elf_obj_new(ctx, fcb->str, parent,
                                    ELF_SYMBOL_ENTRY,
                                    ELF_S_IFREG);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'",
                            fcb->str);
                        continue;
                }

                entry->free_func = fcb->freecontent_func;
                entry->fill_func = fcb->setcontent_func;
                list_add(parent->entries, entry);
        }


        ret = ELF_SUCCESS;
  end:
        return ret;
}
