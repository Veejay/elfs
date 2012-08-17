#include "misc.h"

Elf64_Shdr *
elf_getnsection(telf_ctx *ctx,
                int n)
{
        if (n < 0 || n >= ctx->n_sections)
                return NULL;

        return ctx->shdr + n;
}

char *
elf_getsectionname(telf_ctx *ctx,
                   Elf64_Shdr *shdr)
{
        Elf64_Shdr *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        return sh_strtab_p + shdr->sh_name;
}

char *
elf_getnsectionname(telf_ctx *ctx,
                    int n)
{
        if (n < 0 || n >= ctx->n_sections)
                return NULL;

        Elf64_Shdr *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        return sh_strtab_p + ctx->shdr[n].sh_name;
}

Elf64_Shdr *
elf_getsectionbyname(telf_ctx *ctx,
                     char *name)
{
        int i;
        Elf64_Shdr *shdr = NULL;

        for (i = 0; i < ctx->n_sections; i++) {
                char *i_name = elf_getnsectionname(ctx, i);

                if (0 == strcmp(i_name, name))
                        return elf_getnsection(ctx, i);
        }

        return NULL;
}

/** return the name of a given symbol */
char *
elf_symname(telf_ctx *ctx,
            Elf64_Sym *sym)
{
        return &ctx->strtab[sym->st_name];
}

/** return the name of a given dynamic symbol */
char *
elf_dsymname(telf_ctx *ctx,
             Elf64_Sym *sym)
{
        return &ctx->dstrtab[sym->st_name];
}

/**  get the n-th symbol (start at 0) */
Elf64_Sym *
elf_getnsym(telf_ctx *ctx,
            int n)
{
        if (n < 0 || n >= ctx->n_syms)
                return NULL;

        return ctx->symtab + n;
}

/**  get the n-th dynamic symbol (start at 0) */
Elf64_Sym *
elf_getndsym(telf_ctx *ctx,
             int n)
{
        if (n < 0 || n >= ctx->n_dsyms)
                return NULL;

        return ctx->dsymtab + n;
}

Elf64_Sym *
elf_getsymbyname(telf_ctx *ctx,
                 char *name)
{
        int i;
        Elf64_Sym *sym = NULL;

        for (i = 0; i < ctx->n_syms; i++) {
                sym = elf_getnsym(ctx, i);
                if (0 == strcmp(name, elf_symname(ctx, sym)))
                        goto end;
        }

        sym = NULL;
  end:
        return sym;
}

Elf64_Sym *
elf_getdsymbyname(telf_ctx *ctx,
                  char *name)
{
        int i;

        for (i = 0; i < ctx->n_dsyms; i++) {
                Elf64_Sym *sym = elf_getndsym(ctx, i);
                if (0 == strcmp(name, elf_dsymname(ctx, sym)))
                        return sym;
        }

        return NULL;
}

char *
sym_bind_to_str(Elf64_Sym *sym)
{
        if (! sym)
                return "unknown";

        unsigned char b = ELF64_ST_BIND(sym->st_info);

        switch (b) {
#define MAP(x) case STB_##x: return #x
                MAP(LOCAL);
                MAP(GLOBAL);
                MAP(WEAK);
                MAP(LOPROC);
                MAP(HIPROC);
#undef MAP
        }

        return "impossible";
}

char *
sym_type_to_str(Elf64_Sym *sym)
{
        if (! sym)
                return "unknown";

        unsigned char t = ELF64_ST_TYPE(sym->st_info);

        switch (t) {
#define MAP(x) case STT_##x: return #x
                MAP(NOTYPE);
                MAP(OBJECT);
                MAP(FUNC);
                MAP(SECTION);
                MAP(FILE);
                MAP(LOPROC);
                MAP(HIPROC);
#undef MAP
        }

        return "impossible";
}
