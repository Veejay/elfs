#ifndef SYMBOLFS_H
#define SYMBOLFS_H

#include "fs-structs.h"
#include "elfs.h"

int symbolfs_build(telf_ctx *ctx);

telf_fs_driver symbolfs_driver;

#endif /* SYMBOLFS_H */
