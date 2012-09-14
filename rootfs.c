#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "rootfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "defaultfs.h"
#include "misc.h"

extern telf_ctx *ctx;


static void
rootfs_freecontent(void *data)
{
        telf_default_content *content = data;

        if (! content)
                return;

        if (content->buf)
                free(content->buf);

        free(content);
}

static char *
rootfs_type_to_str(unsigned type)
{
        switch (type) {
        case ET_NONE:   return "NONE (No file type)";
        case ET_REL:    return "REL (Relocatable file)";
        case ET_EXEC:   return "EXEC (Executable file)";
        case ET_DYN:    return "DYN (Shared object file)";
        case ET_CORE:   return "CORE (Core file)";
        case ET_LOPROC: return "LOPROC (Processor-specific)";
        case ET_HIPROC: return "HIPROC (Processor-specific)";
        default:        return "Unknown type";
        }
}

static telf_status
rootfs_gen_info(Elf64_Ehdr *ehdr,
                char **bufp,
                size_t *buf_lenp)
{
        size_t size;
        size_t off = 0;
        int i;
        char ident_str[128] = "";
        char tmpbuf[1024];
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;

        for (i = 0; i < EI_NIDENT; i++)
                off += sprintf(ident_str + off, "%.2x ", ehdr->e_ident[i]);

        buf_len = sprintf(tmpbuf,
                          "Ident:                             %s\n"
                          "Version:                           %d\n"
                          "Class:                             %d\n"
                          "Type:                              %s\n"
                          "Version:                           %d\n"
                          "ELF Header size:                   %d bytes\n"
                          "Entry point:                       %p\n"
                          "Program Header offset:             %lu bytes\n"
                          "Program Header entry size:         %d bytes\n"
                          "Number of Program Header entries:  %d\n"
                          "Section Header offset:             %lu bytes\n"
                          "Section Header entry size:         %d bytes\n"
                          "Number of Section Header entries:  %d\n"
                          "SH string table index:             %d\n",
                          ident_str,
                          ehdr->e_ident[EI_VERSION],
                          ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? 64 : 32,
                          rootfs_type_to_str(ehdr->e_type),
                          ehdr->e_version,
                          ehdr->e_ehsize,
                          (void *) ehdr->e_entry,
                          ehdr->e_phoff,
                          ehdr->e_phentsize,
                          ehdr->e_phnum,
                          ehdr->e_shoff,
                          ehdr->e_shentsize,
                          ehdr->e_shnum,
                          ehdr->e_shstrndx);

        if (bufp) {
                buf = malloc(buf_len + 1);
                if (! buf) {
                        LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                strncpy(buf, tmpbuf, buf_len);
                buf[buf_len] = 0;
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
rootfs_info_getsize(void *obj_hdl,
                    size_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;

        rc = rootfs_gen_info(obj->ctx->ehdr, NULL, sizep);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "Can't generate header info");
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

static telf_status
rootfs_info_setcontent(void *obj_hdl,
                           char **bufp,
                           size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;

        rc = rootfs_gen_info(obj->ctx->ehdr, bufp, buf_lenp);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "Can't generate header info");
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        LOG(LOG_DEBUG, 0, "ret=%s (%d)", elf_status_to_str(ret), ret);
        return ret;
}


typedef struct {
        char *str;
        tobj_getsize_func getsize_func;
        tobj_setcontent_func setcontent_func;
        tobj_freecontent_func freecontent_func;
} telf_fcb;

static telf_fcb rootfs_fcb[] = {
        {
                "info",
                rootfs_info_getsize,
                rootfs_info_setcontent,
                rootfs_freecontent
        },
};

static telf_status
rootfs_getattr(void *obj_hdl,
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

        for (i = 0; i < N_ELEMS(rootfs_fcb); i++) {
                telf_fcb *fcb = rootfs_fcb + i;

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
rootfs_override_driver(telf_fs_driver *driver)
{
        driver->getattr = rootfs_getattr;
}



/* root directory object creation */

telf_status
rootfs_build(telf_ctx *ctx)
{
        telf_status rc;
        telf_status ret;
        telf_obj *root_obj = NULL;
        telf_obj *sections_obj = NULL;
        telf_obj *libs_obj = NULL;
        telf_obj *entry = NULL;
        int i;

        root_obj = elf_obj_new(ctx, "/", NULL,
                               ELF_ROOTDIR,
                               ELF_S_IFDIR);
        if (! root_obj) {
                LOG(LOG_ERR, 0, "root obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        sections_obj = elf_obj_new(ctx, "sections", root_obj,
                                   ELF_SECTION,
                                   ELF_S_IFDIR);
        if (! sections_obj) {
                LOG(LOG_ERR, 0, "section obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        libs_obj = elf_obj_new(ctx, "libs", root_obj,
                               ELF_LIBS,
                               ELF_S_IFDIR);
        if (! libs_obj) {
                LOG(LOG_ERR, 0, "libs obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        list_add(root_obj->entries, sections_obj);
        list_add(root_obj->entries, libs_obj);

        /* now add the pseudo files */
        for (i = 0; i < N_ELEMS(rootfs_fcb); i++) {
                telf_fcb *fcb = rootfs_fcb + i;

                entry = elf_obj_new(ctx, fcb->str, root_obj,
                                    ELF_ROOTDIR_ENTRY,
                                    ELF_S_IFREG);
                if (! entry) {
                        LOG(LOG_ERR, 0, "can't build entry '%s'",
                            fcb->str);
                        continue;
                }

                entry->free_func = fcb->freecontent_func;
                entry->fill_func = fcb->setcontent_func;

                rootfs_override_driver(entry->driver);
                list_add(root_obj->entries, entry);
        }


        /* and finally... */
        ctx->root = root_obj;

        ret = ELF_SUCCESS;
  err:
        return ret;
}

