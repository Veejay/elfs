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

#define ERR(fmt, ...) LOG(LOG_ERR, 0, fmt, ##__VA_ARGS__)
#define DEBUG(fmt, ...) LOG(LOG_DEBUG, 0, fmt, ##__VA_ARGS__)
#define WARN(fmt, ...) LOG(LOG_WARN, 0, fmt, ##__VA_ARGS__)

#endif /* LOG_H */
