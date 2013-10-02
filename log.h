#ifndef LOG_H
#define LOG_H
#include <stdio.h>

typedef struct
{
  FILE *log_file;
} log_t;

log_t *log_init (const char *log_file_path);

void _log (log_t *handle, const char *level, const char *fmt, ...)
  __attribute__ ((format (printf, 3, 4)));

#define log(handle, level, fmt, ...) _log(handle, level, fmt, ##__VA_ARGS__)

void log_exit (log_t *logger);


#endif
