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
#define LINUX64_BASE_ADDR 0x400000

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
symentryfs_asmcode_getsize(void *obj_hdl,
                           size_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        Elf64_Sym *sym = obj->parent->data;
        Elf64_Shdr *shdr = obj->ctx->shdr + sym->st_shndx;
        ud_t ud_obj;
        char *buf = NULL;
        size_t size = 0;
        size_t offset;

        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size) {
                offset = sym->st_value - LINUX64_BASE_ADDR;
                rc = binary_to_asm(obj->ctx->addr + offset,
                                   sym->st_size,
                                   NULL,
                                   &size);
                if (ELF_SUCCESS != rc) {
                        LOG(LOG_ERR, 0, "can't extract asm code from binary");
                        ret = rc;
                        goto end;
                }
        }

        ret = ELF_SUCCESS;
  end:
        if (buf)
                free(buf);

        if (sizep)
                *sizep = size;

        return ret;
}

static telf_status
symentryfs_asmcode_setcontent(void *obj_hdl,
                              char **bufp,
                              size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        Elf64_Sym *sym = obj->parent->data;
        Elf64_Shdr *shdr = obj->ctx->shdr + sym->st_shndx;
        char *buf = NULL;
        size_t buf_len = 0;
        size_t offset;

        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size) {
                offset = sym->st_value - LINUX64_BASE_ADDR;
                rc = binary_to_asm(obj->ctx->addr + offset,
                                   sym->st_size,
                                   &buf,
                                   &buf_len);
                if (ELF_SUCCESS != rc) {
                        LOG(LOG_ERR, 0, "can't extract asm code from binary");
                        ret = rc;
                        goto end;
                }
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

static telf_status
symentryfs_bincode_getsize(void *obj_hdl,
                           size_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        Elf64_Sym *sym = obj->parent->data;
        size_t size = 0;

        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size)
                size = sym->st_size;

        ret = ELF_SUCCESS;
  end:

        if (sizep)
                *sizep = size;

        return ret;
}

static telf_status
symentryfs_bincode_setcontent(void *obj_hdl,
                              char **bufp,
                              size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        Elf64_Sym *sym = obj->parent->data;
        Elf64_Shdr *shdr = obj->ctx->shdr + sym->st_shndx;
        char *buf = NULL;
        size_t buf_len = 0;
        size_t offset;

        if (STT_FUNC == ELF32_ST_TYPE(sym->st_info) && sym->st_size) {
                buf_len = sym->st_size;
                offset = sym->st_value - LINUX64_BASE_ADDR;
                buf = malloc(buf_len);
                if (! buf) {
                        LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }
                memcpy(buf, obj->ctx->addr + offset, sym->st_size);
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

static telf_status
symentryfs_info_getsize(void *obj_hdl,
                        size_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        Elf64_Sym *sym = obj->parent->data;
        char *symname = NULL;
        char tmpbuf[256];
        size_t size;

        /* default value */
        symname = "NONAME";

        if (sym->st_name) {
                symname = ((ELF_SECTION_SYMTAB == obj->parent->type) ?
                           elf_getsymname :
                           elf_getdsymname)(obj->ctx, sym);

                if (! symname || ! *symname)
                        symname = "UNRESOLVED";
        }

        size = sprintf(tmpbuf,
                       "value: %p\n"
                       "size: %zu\n"
                       "type: %s\n"
                       "bind: %s\n"
                       "name: %s\n",
                       (void *) sym->st_value,
                       sym->st_size,
                       sym_type_to_str(sym),
                       sym_bind_to_str(sym),
                       symname);

        ret = ELF_SUCCESS;
  end:

        if (sizep)
                *sizep = size;

        return ret;
}

static telf_status
symentryfs_info_setcontent(void *obj_hdl,
                           char **bufp,
                           size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        Elf64_Sym *sym = obj->parent->data;
        char *symname = NULL;
        char tmpbuf[256];
        char *buf = NULL;
        size_t buf_len;

        /* default value */
        symname = "NONAME";

        if (sym->st_name) {
                symname = ((ELF_SECTION_SYMTAB == obj->parent->type) ?
                           elf_getsymname :
                           elf_getdsymname)(obj->ctx, sym);

                if (! symname || ! *symname)
                        symname = "UNRESOLVED";
        }

        buf_len = sprintf(tmpbuf,
                          "value: %p\n"
                          "size: %zu\n"
                          "type: %s\n"
                          "bind: %s\n"
                          "name: %s\n",
                          (void *) sym->st_value,
                          sym->st_size,
                          sym_type_to_str(sym),
                          sym_bind_to_str(sym),
                          symname);

        buf = malloc(buf_len + 1);
        if (! buf) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        strncpy(buf, tmpbuf, buf_len);

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        LOG(LOG_DEBUG, 0, "ret=%s (%d)", elf_status_to_str(ret), ret);
        return ret;
}


typedef struct {
        char *str;
        tobj_getsize_func getsize_func;
        tobj_setcontent_func setcontent_func;
        tobj_freecontent_func freecontent_func;
} telf_fcb;

static telf_fcb symentryfs_fcb[] = {
        {
                "code.bin",
                symentryfs_bincode_getsize,
                symentryfs_bincode_setcontent,
                symentryfs_freecontent
        },

        {
                "code.asm",
                symentryfs_asmcode_getsize,
                symentryfs_asmcode_setcontent,
                symentryfs_freecontent
        },

        {
                "info",
                symentryfs_info_getsize,
                symentryfs_info_setcontent,
                symentryfs_freecontent
        },
};

static telf_status
symentryfs_getattr(void *obj_hdl,
                   telf_stat *stp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        telf_stat st;
        int i;

        elf_obj_lock(obj);

        LOG(LOG_DEBUG, 0, "name:%s data=%p", obj->name, obj->data);

        memset(&st, 0, sizeof st);
        st.st_mode |= ELF_S_IFREG;

        for (i = 0; i < N_ELEMS(symentryfs_fcb); i++) {
                telf_fcb *fcb = symentryfs_fcb + i;

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

        LOG(LOG_DEBUG, 0, "ret=%s (%d)", elf_status_to_str(ret), ret);
        return ret;
}

static void
symentryfs_override_driver(telf_fs_driver *driver)
{
        driver->getattr = symentryfs_getattr;
}


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

                symentryfs_override_driver(entry->driver);
                list_add(parent->entries, entry);
        }


        ret = ELF_SUCCESS;
  end:
        return ret;
}
