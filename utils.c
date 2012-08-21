#include <assert.h>

#include "utils.h"

char *
elf_status_to_str(telf_status st)
{
#define MAP(x) case ##x: return #x

        switch (st) {
                MAP(SUCCESS);
                MAP(FAILURE);
                MAP(ENOENT);
                MAP(ENOMEM);
                MAP(EIO);
        }

        assert("impossible");
        return "impossible";

#undef MAP
}
