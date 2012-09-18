#include <string.h>
#include <stdlib.h>

#include "elfs.h"
#include "log.h"
#include "misc.h"
#include "libfs.h"


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
        st.st_mode |= ELF_S_IFREG;
        st.st_mode |= ELF_S_IRWXU|ELF_S_IRWXG|ELF_S_IRWXO;
        st.st_size = 0;

        ret = ELF_SUCCESS;
  end:

        elf_obj_unlock(obj);

        if (stp)
                *stp = st;
        return ret;
}

static void
libfs_override_driver(telf_fs_driver *driver)
{
        driver->getattr  = libfs_getattr;
        driver->open     = libfs_open;
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
        int found = 0;

        rc = elf_namei(ctx, "/libs", &libfs_obj);
        if (ELF_SUCCESS != rc) {
                ERR("can't find '/libfs' object: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        shdr = elf_getsectionbyname(ctx, ".dynsym");
        if (! shdr) {
                ERR("no SHT_DYNAMIC section");
                ret = ELF_SUCCESS;
                goto end;
        }

        /* Load its data and print all DT_NEEDED strings. */
        for (i = 0; i < ctx->ehdr->e_shnum && 0 == found; i++) {
                shdr = elf_getnsection(ctx, i);

                if (SHT_DYNAMIC == shdr->sh_type)
                        found = 1;
        }

        if (! found) {
                ERR("can't find any SHT_DYNAMIC section");
                ret = ELF_ENOENT;
                goto end;
        }

        for (i = 0; i < shdr->sh_size / sizeof(Elf64_Dyn); i++) {
                telf_obj *entry = NULL;
                char *libname = NULL;

                dyn = (Elf64_Dyn *)(ctx->addr + shdr->sh_offset) + i;

                if (DT_NEEDED != dyn->d_tag)
                        continue;

                DEBUG(" -> %s", ctx->dstrtab + dyn->d_un.d_val);

                libname = ctx->dstrtab + dyn->d_un.d_val;

                entry = elf_obj_new(ctx, libname, libfs_obj,
                                    ELF_LIBS_ENTRY,
                                    ELF_S_IFREG);
                if (! entry) {
                        ERR("can't build entry '%s'", libname);
                        continue;
                }

                libfs_override_driver(entry->driver);
                list_add(libfs_obj->entries, entry);
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}
