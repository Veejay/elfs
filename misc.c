#include <errno.h>
#include <stdlib.h>

#include "misc.h"


/* read data from location addr */
int
memread(pid_t pid,
        unsigned long addr,
        void *outp,
        size_t len)
{
	int i, count;
	long word;
	unsigned long *ptr =  outp;
        int ret;

	count = i = 0;
	while (count < len) {
                errno = 0;
		word = ptrace(PTRACE_PEEKDATA, pid, addr + count);
                if (-1 == word && errno) {
                        ret = -1;
                        goto end;
                }

		count += sizeof word;
		ptr[i++] = word;
	}

        ret = 0;
  end:
        return ret;
}


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

        for (i = 0; i < ctx->n_sections; i++) {
                Elf64_Shdr *shdr = ctx->shdr + i;
                char *i_name = elf_getsectionname(ctx, shdr);

                if (0 == strcmp(i_name, name))
                        return shdr;
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

int
elf_getshstrtab(telf_ctx *ctx,
                char **strtabp)
{
        Elf64_Shdr shdr;
        int rc;
        size_t to_read;
        unsigned long addr;
        char *strtab = NULL;

        to_read = sizeof shdr;
        addr = (unsigned long) (uintptr_t) ctx->addr + ctx->ehdr->e_shstrndx;

        rc = memread(ctx->pid, addr, (void *) &shdr, to_read);
        if (-1 == rc)
                goto err;

        to_read = shdr.sh_size;
        addr = (unsigned long) (uintptr_t) ctx->addr + shdr.sh_offset;

        strtab = malloc(to_read);
        if (! strtab)
                goto err;

        rc = memread(ctx->pid, addr, (void *) &strtab, to_read);
        if (-1 == rc)
                goto err;

        if (strtabp)
                *strtabp = strtab;

        return 0;
  err:
        if (strtab)
                free(strtab);

        return -1;
}
