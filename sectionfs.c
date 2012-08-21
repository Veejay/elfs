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

int
sectionfs_build(telf_ctx *ctx)
{
        int ret;
        int rc;
        int i;
        telf_obj *sections_obj = NULL;

        Elf64_Shdr *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        rc = elf_namei(ctx, "/sections", &sections_obj);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "can't find any section entry");
                ret = -1;
                goto end;
        }

        ctx->n_sections = ctx->ehdr->e_shnum;

        if (! ctx->n_sections)
                return 0;

        rc = elf_obj_list_new(sections_obj);
        if (-1 == rc) {
                LOG(LOG_ERR, 0, "section entries creation failed");
                ret = -1;
                goto end;
        }

        sections_obj->driver = *defaultfs_driver_new();

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
                        ret = -1;
                        goto end;
                }

                switch (type) {
                case ELF_SECTION_DYNSYM:
                case ELF_SECTION_SYMTAB:
                        obj->driver = symbolfs_driver;
                        break;
                default:
                        break;
                }

                list_add(sections_obj->entries, obj);
        }

        ret = 0;
  end:
        return ret;
}
