A FUSE filesystem on top of ELF files!

This tool is mostly for educational purposes and allows the user to easily visualize
the structure of an ELF object.

0. INSTALLATION
===============

    $ git clone git://github.com/pozdnychev/elfs
    $ cd elfs

Then on Linux platforms:

    $ make 

or 

    $ make -f Makefile 

or on BSD platforms:

    $ make -f BSDMakefile

And now, with root privileges:

    $ make install

1. USAGE
========

If you want to inspect the fdup(1) program, and mount its image into /tmp/elf:

    $ elfs /tmp/elf /usr/local/bin/fdup

    $ ls -l /tmp/elf/
    total 0
    ---------- 0 root root 634 1970-01-01 01:00 info
    d--------- 1 root root   0 1970-01-01 01:00 libs
    d--------- 1 root root   0 1970-01-01 01:00 sections

The 'info' file contains ELF header information (pretty much the same format provided by readelf -h):

    $ cat /tmp/elf/info
    Ident:                             7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
    Version:                           1
    Class:                             64
    Type:                              EXEC (Executable file)
    Version:                           1
    ELF Header size:                   64 bytes
    Entry point:                       0x400f70
    Program Header offset:             64 bytes
    Program Header entry size:         56 bytes
    Number of Program Header entries:  9
    Section Header offset:             17352 bytes
    Section Header entry size:         64 bytes
    Number of Section Header entries:  30
    SH string table index:             27

Check the libraries: display the list and their path on the file system

    $ ls -l /tmp/elf/libs
    total 0
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libc.so.6 -> /lib/x86_64-linux-gnu/libc.so.6
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libm.so.6 -> /lib/x86_64-linux-gnu/libm.so.6
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libX11.so.6 -> /usr/lib/x86_64-linux-gnu/libX11.so.6
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libXaw.so.7 -> /usr/lib32/libXaw.so.7
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libXft.so.2 -> /usr/lib/x86_64-linux-gnu/libXft.so.2
    [...]


If you want to inspect the sections:

    $ ls -l /tmp/elf/sections/
    total 0
    drw------- 1 root root 0 1970-01-01 01:00 bss
    d--------- 1 root root 0 1970-01-01 01:00 comment
    drw------- 1 root root 0 1970-01-01 01:00 ctors
    drw------- 1 root root 0 1970-01-01 01:00 data
    d--------- 1 root root 0 1970-01-01 01:00 debug_abbrev
    d--------- 1 root root 0 1970-01-01 01:00 debug_aranges
    d--------- 1 root root 0 1970-01-01 01:00 debug_info
    d--------- 1 root root 0 1970-01-01 01:00 debug_line
    d--------- 1 root root 0 1970-01-01 01:00 debug_loc
    d--------- 1 root root 0 1970-01-01 01:00 debug_macinfo
    d--------- 1 root root 0 1970-01-01 01:00 debug_pubnames
    d--------- 1 root root 0 1970-01-01 01:00 debug_pubtypes
    d--------- 1 root root 0 1970-01-01 01:00 debug_ranges
    d--------- 1 root root 0 1970-01-01 01:00 debug_str
    drw------- 1 root root 0 1970-01-01 01:00 dtors
    drw------- 1 root root 0 1970-01-01 01:00 dynamic
    dr-------- 1 root root 0 1970-01-01 01:00 dynstr
    dr-------- 1 root root 0 1970-01-01 01:00 dynsym
    dr-------- 1 root root 0 1970-01-01 01:00 eh_frame
    dr-------- 1 root root 0 1970-01-01 01:00 eh_frame_hdr
    dr-x------ 1 root root 0 1970-01-01 01:00 fini
    dr-------- 1 root root 0 1970-01-01 01:00 gnu.hash
    dr-------- 1 root root 0 1970-01-01 01:00 gnu.version
    dr-------- 1 root root 0 1970-01-01 01:00 gnu.version_r
    drw------- 1 root root 0 1970-01-01 01:00 got
    drw------- 1 root root 0 1970-01-01 01:00 got.plt
    dr-x------ 1 root root 0 1970-01-01 01:00 init
    dr-------- 1 root root 0 1970-01-01 01:00 interp
    drw------- 1 root root 0 1970-01-01 01:00 jcr
    d--------- 1 root root 0 1970-01-01 01:00 noname.0x7f14e3a863c0
    dr-------- 1 root root 0 1970-01-01 01:00 note.ABI-tag
    dr-------- 1 root root 0 1970-01-01 01:00 note.gnu.build-id
    dr-x------ 1 root root 0 1970-01-01 01:00 plt
    dr-------- 1 root root 0 1970-01-01 01:00 rela.dyn
    dr-------- 1 root root 0 1970-01-01 01:00 rela.plt
    dr-------- 1 root root 0 1970-01-01 01:00 rodata
    d--------- 1 root root 0 1970-01-01 01:00 shstrtab
    d--------- 1 root root 0 1970-01-01 01:00 strtab
    d--------- 1 root root 0 1970-01-01 01:00 symtab
    dr-x------ 1 root root 0 1970-01-01 01:00 text

We set the rwx bits, according to the Section Header flags:

    SHR_WRITE     -> w bit
    SHR_ALLOC     -> r bit
    SHR_EXECINSTR -> x bits

    $ ll /tmp/elf/sections/symtab/dup_cmp_gid/
    total 0
    ---------- 0 root root 217 1970-01-01 01:00 code.asm
    ---------- 0 root root  44 1970-01-01 01:00 code.bin
    ---------- 0 root root  74 1970-01-01 01:00 info

    $ cat /tmp/elf/sections/symtab/dup_cmp_gid/info
    value: 0x401b00
    size: 44
    type: STT_FUNC
    bind: STB_LOCAL
    name: GLIBC_2.3.4

    $ od -t x1 /tmp/elf/sections/symtab/dup_cmp_gid/code.bin
    0000000 55 48 89 e5 48 89 7d f8 48 89 75 f0 48 8b 45 f8
    0000020 8b 50 20 48 8b 45 f0 8b 40 20 39 c2 75 07 b8 00
    0000040 00 00 00 eb 05 b8 ff ff ff ff c9 c3


Let's see the code associated with this symbol (it's ok, since it's a function,
type STT_FUNC):

    $ cat /tmp/elf/sections/symtab/dup_cmp_gid/code.asm
    push rbp
    mov rbp, rsp
    mov [rbp-0x8], rdi
    mov [rbp-0x10], rsi
    mov rax, [rbp-0x8]
    mov edx, [rax+0x20]
    mov rax, [rbp-0x10]
    mov eax, [rax+0x20]
    cmp edx, eax
    jnz 0x25
    mov eax, 0x0
    jmp 0x2a
    mov eax, 0xffffffff
    leave
    ret

We can check that the code is correct just by taking a look at the binary:

    $ readelf -s /usr/local/bin/fdup | grep dup_cmp_gid
    62: 0000000000401b00    44 FUNC    LOCAL  DEFAULT   13 dup_cmp_gid

We know that for Intel 64-bit architectures on Linux, binaries are loaded 
at virtual memory address 0x400000 (0x804800 for 32-bit architectures):

    $ echo 'ibase=16;401B00-400000' | bc
    6912

    $ od -t x1 -j6912 -N44 /usr/local/bin/fdup
    0015400 55 48 89 e5 48 89 7d f8 48 89 75 f0 48 8b 45 f8
    0015420 8b 50 20 48 8b 45 f0 8b 40 20 39 c2 75 07 b8 00
    0015440 00 00 00 eb 05 b8 ff ff ff ff c9 c3
    0015454


You can also attach a running process but the feature being pretty experimental,
use at your own risk as you might encounter strange/wrong behavior.  Here is a simple example:

    $ sudo elfs -p `pidof xclock` /tmp/elf
    $ sudo ls -l /tmp/elf/libs
    total 0
    -rwxrwxrwx 0 root root  9 1970-01-01 01:00 libc.so.6
    -rwxrwxrwx 0 root root  9 1970-01-01 01:00 libm.so.6
    -rwxrwxrwx 0 root root 11 1970-01-01 01:00 libX11.so.6
    -rwxrwxrwx 0 root root 11 1970-01-01 01:00 libXaw.so.7
    -rwxrwxrwx 0 root root 11 1970-01-01 01:00 libXft.so.2
    -rwxrwxrwx 0 root root 15 1970-01-01 01:00 libxkbfile.so.1
    -rwxrwxrwx 0 root root 11 1970-01-01 01:00 libXmu.so.6
    -rwxrwxrwx 0 root root 15 1970-01-01 01:00 libXrender.so.1
    -rwxrwxrwx 0 root root 10 1970-01-01 01:00 libXt.so.6


For more information, just type:

    $ elfs -h


2. UNINSTALL
============

With root privileges, in elfs source directory:

    $ make uninstall

3. ISSUES
=========

Please report bugs and comments to:

https://github.com/pozdnychev/elfs/issues
