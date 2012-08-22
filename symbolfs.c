#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include "symbolfs.h"
#include "symentryfs.h"
#include "misc.h"
#include "log.h"
#include "defaultfs.h"

telf_ctx *ctx;


static telf_status
symbolfs_symtab_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;
        int i;
        telf_obj *symtab_obj = NULL;
        telf_obj *obj = NULL;
        char *name = NULL;
        char path[256];

        rc = elf_namei(ctx, "/sections/symtab", &symtab_obj);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can't find '/section/symtab': %s",
                    elf_status_to_str(rc));
                ret = ELF_ENOENT;
                goto end;
        }

        symtab_obj->driver = defaultfs_driver_new();
        if (! symtab_obj->driver) {
                LOG(LOG_ERR, 0, "can't create symbolfs driver");
                ret = ELF_FAILURE;
                goto end;
        }

        for (i = 0; i < ctx->ehdr->e_shnum; i++) {
                Elf64_Shdr *shdr = ctx->shdr + i;

                if (SHT_SYMTAB != shdr->sh_type)
                        continue;

                ctx->n_syms = shdr->sh_size / sizeof (Elf64_Sym);
                ctx->symtab = (Elf64_Sym *) (ctx->addr + shdr->sh_offset);
                ctx->symtab_end = ctx->symtab + shdr->sh_size;
                ctx->strtab = ctx->addr + ctx->shdr[shdr->sh_link].sh_offset;
                break;
        }

        if (! ctx->n_syms) {
                ret = ELF_SUCCESS;
                goto end;
        }

        rc = elf_obj_list_new(symtab_obj);
        if (ELF_SUCCESS != rc) {
                ret = rc;
                goto end;
        }

        Elf64_Sym *sym = NULL;
        for (i = 0; i < ctx->n_syms; i++) {
                sym = elf_getnsym(ctx, i);
                assert(NULL != sym);

                name = elf_symname(ctx, sym);
                assert(NULL != name);

                if ('\0' == *name) {
                        sprintf(path, "noname.%p", (void *) sym);
                } else {
                        sprintf(path, "%s", name);
                }

                obj = elf_obj_new(ctx, path, symtab_obj, ELF_SYMBOL);
                if (! obj) {
                        LOG(LOG_ERR, 0, "object creation '%s' failed", path);
                        ret = ELF_FAILURE;
                        goto end;
                }

                rc = symentryfs_build(ctx, obj);
                if (ELF_SUCCESS != rc) {
                        LOG(LOG_ERR, 0, "symentryfs creation failed: %s",
                            elf_status_to_str(rc));
                        ret = rc;
                        goto end;
                }

                obj->data = sym;

                LOG(LOG_DEBUG, 0, "adding to symtab: %s", path);
                list_add(symtab_obj->entries, obj);
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

static telf_status
symbolfs_dynsym_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;
        int i;
        telf_obj *obj = NULL;
        telf_obj *dynsym_obj = NULL;
        char *name = NULL;
        char path[256];

        rc = elf_namei(ctx, "/sections/dynsym", &dynsym_obj);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can not find '/sections/dynsym': %s",
                    elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        dynsym_obj->driver = defaultfs_driver_new();
        if (! dynsym_obj->driver) {
                LOG(LOG_ERR, 0, "can't create symbolfs driver");
                ret = ELF_FAILURE;
                goto end;
        }

        for (i = 0; i < ctx->ehdr->e_shnum; i++) {
                Elf64_Shdr *shdr = ctx->shdr + i;

                /* dynamic symbol table */
                if (SHT_DYNSYM != shdr->sh_type)
                        continue;

                ctx->n_dsyms = shdr->sh_size / sizeof (Elf64_Sym);
                ctx->dsymtab = (Elf64_Sym *) (ctx->addr + shdr->sh_offset);
                ctx->dsymtab_end = ctx->dsymtab + shdr->sh_size;
                ctx->dstrtab = ctx->addr + ctx->shdr[shdr->sh_link].sh_offset;
                break;
        }

        if (! ctx->n_dsyms) {
                ret = ELF_SUCCESS;
                goto end;
        }

        rc = elf_obj_list_new(dynsym_obj);
        if (ELF_SUCCESS != rc) {
                ret = rc;
                goto end;
        }

        Elf64_Sym *sym = NULL;
        for (i = 0; i < ctx->n_dsyms; i++) {
                sym = elf_getndsym(ctx, i);
                assert(NULL != sym);

                name = elf_dsymname(ctx, sym);
                assert(NULL != name);

                if ('\0' == *name) {
                        sprintf(path, "noname.%p", (void *) sym);
                } else {
                        sprintf(path, "%s", name);
                }

                obj = elf_obj_new(ctx, path, dynsym_obj, ELF_SYMBOL);
                if (! obj) {
                        LOG(LOG_ERR, 0, "object creation '%s' failed", path);
                        ret = ELF_FAILURE;
                        goto end;
                }

                rc = symentryfs_build(ctx, obj);
                if (ELF_SUCCESS != rc) {
                        LOG(LOG_ERR, 0, "symentryfs creation failed: %s",
                            elf_status_to_str(rc));
                        ret = rc;
                        goto end;
                }

                obj->data = sym;

                list_add(dynsym_obj->entries, obj);
                LOG(LOG_DEBUG, 0, "adding to dynsym: %s", path);
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

telf_status
symbolfs_build(telf_ctx *ctx)
{
        telf_status rc;
        telf_status ret;

        rc = symbolfs_dynsym_build(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can't build dynsym driver: %s",
                    elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        rc = symbolfs_symtab_build(ctx);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "can't build symtab driver: %s",
                    elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}
