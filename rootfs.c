#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "rootfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "defaultfs.h"

extern telf_ctx *ctx;


/* root directory object creation */

telf_status
rootfs_build(telf_ctx *ctx)
{
        telf_status rc;
        telf_status ret;
        telf_obj *root_obj = NULL;
        telf_obj *sections_obj = NULL;

        root_obj = elf_obj_new(ctx, "/", NULL, ELF_ROOTDIR);
        if (! root_obj) {
                LOG(LOG_ERR, 0, "root obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        rc = elf_obj_list_new(root_obj);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "entries creation failed: %s",
                    elf_status_to_str(rc));
                ret = rc;
                goto err;
        }

        sections_obj = elf_obj_new(ctx, "sections", root_obj, ELF_SECTION);
        if (! sections_obj) {
                LOG(LOG_ERR, 0, "section obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        list_add(root_obj->entries, sections_obj);

        /* set the fs callbacks related to the root directory */
        root_obj->driver = *defaultfs_driver_new();


        /* and finally... */
        ctx->root = root_obj;

        ret = ELF_SUCCESS;
  err:
        return ret;
}

