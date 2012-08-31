#include <assert.h>


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
