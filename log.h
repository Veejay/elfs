#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <errno.h>
#include <stdio.h>

#include <syslog.h>

int loglevel;

#define LOG(level, err, fmt, ...) do {                                  \
                if (level > loglevel) continue;                         \
                                                                        \
                syslog(level, "%s:%s %d: "fmt,                          \
                       __FILE__, __func__, __LINE__, ##__VA_ARGS__);    \
        } while (0)

#endif /* LOG_H */
