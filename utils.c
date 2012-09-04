#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <udis86.h>

#include "log.h"
#include "utils.h"


#define MAP(v) X(v, #v)
#define X(a, b) b,
char *elf_status_names[] = {
        ELF_STATUS_TABLE
};
#undef X
#undef MAP


char *
elf_status_to_str(telf_status status)
{
        return elf_status_names[status];
}


telf_status
binary_to_asm(char *bin,
              size_t bin_len,
              char **bufp,
              size_t *buf_lenp)
{
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        ud_t ud_obj;
        char *tmpbuf = NULL;

        ud_init(&ud_obj);
        ud_set_input_buffer(&ud_obj, bin, bin_len);
        ud_set_mode(&ud_obj, 64);
        ud_set_syntax(&ud_obj, UD_SYN_INTEL);

        if (! bin_len || ! bin) {
                ret = ELF_SUCCESS;
                goto end;
        }

        while (ud_disassemble(&ud_obj)) {
                char line[64] = "";
                size_t len;

                len = sprintf(line, "%s\n", ud_insn_asm(&ud_obj));

                tmpbuf = realloc(buf, buf_len + len);
                if (! tmpbuf) {
                        LOG(LOG_ERR, 0, "realloc: %s", strerror(errno));
                        free(buf);
                        buf = NULL;
                        ret = ELF_ENOMEM;
                        goto end;
                }

                buf = tmpbuf;
                memmove(buf + buf_len, line, len);
                buf_len += len;
        }

        /* we didn't reserve any room for the nul-terminaison char */
        if (buf) {
                tmpbuf = realloc(buf, buf_len + 1);
                if (! tmpbuf) {
                        LOG(LOG_ERR, 0, "realloc: %s", strerror(errno));
                        free(buf);
                        buf = NULL;
                        ret = ELF_ENOMEM;
                        goto end;
                }

                tmpbuf[buf_len] = 0;
                buf_len++;
                buf = tmpbuf;
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
