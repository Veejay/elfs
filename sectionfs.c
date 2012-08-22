#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sectionfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "sectionfs.h"
#include "defaultfs.h"
#include "symbolfs.h"

extern telf_ctx *ctx;


/* section directory object creation */

telf_status
sectionfs_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;
        int i;
        telf_obj *sections_obj = NULL;

        Elf64_Shdr *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        rc = elf_namei(ctx, "/sections", &sections_obj);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can't find any section entry: %s",
                    elf_status_to_str(rc));
                ret = ELF_ENOENT;
                goto end;
        }

        ctx->n_sections = ctx->ehdr->e_shnum;

        if (! ctx->n_sections)
                return ELF_SUCCESS;

        sections_obj->driver = defaultfs_driver_new();
        if (! sections_obj->driver) {
                LOG(LOG_ERR, 0, "can't create sectionfs driver");
                ret = ELF_FAILURE;
                goto end;
        }

        for (i = 0; i < ctx->n_sections; ++i) {
                telf_type type;
                char name[128];
                char *s_name = sh_strtab_p + ctx->shdr[i].sh_name;
                telf_obj *obj = NULL;

                if (! *s_name)
                        /* empty name, use the section address */
                        sprintf(name, "noname.%p", sh_strtab + i);
                else
                        /* we want to convert '.bss', etc to 'bss', etc*/
                        sprintf(name, "%s",
                                '.' == *s_name ? s_name + 1 : s_name);

                switch (ctx->shdr[i].sh_type) {
#define MAP(x) case SHT_##x: type = ELF_SECTION_##x; break
                        MAP(NULL);
                        MAP(DYNSYM);
                        MAP(SYMTAB);
                        MAP(NOBITS);
                        MAP(PROGBITS);
                        MAP(DYNAMIC);
                        MAP(HASH);
                        MAP(NOTE);
                        MAP(REL);
                        MAP(RELA);
                        MAP(STRTAB);
#undef MAP
                default:
                        LOG(LOG_ERR, 0, "unknown object type: 0x%x",
                            ctx->shdr[i].sh_type);
                        type = ELF_SECTION_OTHER;
                        break;
                }

                obj = elf_obj_new(ctx, name, sections_obj, type);
                if (! obj) {
                        LOG(LOG_ERR, 0, "obj '%s' creation failed", name);
                        ret = ELF_FAILURE;
                        goto end;
                }

                list_add(sections_obj->entries, obj);
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}
