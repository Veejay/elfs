PROGNAME=elfs
MANFILE=${PROGNAME}.1
MANDIR=/usr/local/man/man1

CC=gcc

DESTDIR=/usr/local
BINDIR=${DESTDIR}/bin

SRC=$(wildcard *.c)
OBJS=$(SRC:.c=.o)

COMMON_CFLAGS=-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I/usr/local/include
COMMON_LDFLAGS=-lfuse -L /usr/local/lib  -ludis86

PROD_CFLAGS=-O3 $(COMMON_CFLAGS)
PROD_LDFLAGS=$(COMMON_LDFLAGS)

DEBUG_CFLAGS=-ggdb -g3 -O0 $(COMMON_CFLAGS)
DEBUG_LDFLAGS=$(COMMON_LDFLAGS)


prod: CFLAGS=$(PROD_CFLAGS)
prod: LDFLAGS=$(PROD_LDFLAGS)
prod: compile

debug: CFLAGS=$(DEBUG_CFLAGS)
debug: LDFLAGS=$(DEBUG_LDFLAGS)
debug: compile


compile: $(PROGNAME)

elfs: $(OBJS)
	$(CC) -o $(PROGNAME) $(CFLAGS) $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $<

install:
	install -m755 $(PROGNAME) $(BINDIR)
	install -m644 ${MANFILE} ${MANDIR}

uninstall:
	rm -f $(BINDIR)/$(PROGNAME)
	rm -f ${MANDIR}/${MANFILE}

clean:
	rm -f *.o $(PROGNAME)