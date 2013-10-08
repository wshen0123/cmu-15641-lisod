#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define LOG_MSG_MAXLEN 0x4000
#define LOG_TIMESTAMP_MAXLEN 100
#define LOG_TIME_BUF_SIZE 30

static char LOG_MSG_BUF[LOG_MSG_MAXLEN];
static char LOG_TIMESTAMP_BUF[LOG_TIMESTAMP_MAXLEN];

void
_log (log_t * logger, const char *level, const char *fmt, ...)
{
  va_list va_arg;
  time_t now = time (0);

  if (logger)
    {
      va_start (va_arg, fmt);
      strftime (LOG_TIMESTAMP_BUF, LOG_TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S",
		localtime (&now));
      vsnprintf (LOG_MSG_BUF, LOG_MSG_MAXLEN, fmt, va_arg);
      fprintf (logger->log_file, "[%s] %-5s %s\n", LOG_TIMESTAMP_BUF, level,
	       LOG_MSG_BUF);
      va_end (va_arg);
    }
}


log_t *
log_init (const char *log_file_path)
{
  log_t *logger;

  if (!(logger = malloc (sizeof (log_t))))
    {
      fprintf (stderr, "malloc:%s\n", strerror (errno));
      return NULL;
    }

#ifdef DEBUG
  logger->log_file = stderr;
#else
  if (!(logger->log_file = fopen (log_file_path, "w+")))
    {
      fprintf (stderr, "log_file: %s", strerror (errno));
      free (logger->log_file);
      return NULL;
    }
#endif

  return logger;
}


void
log_exit (log_t * logger)
{
  if (logger)
    {
      fflush (logger->log_file);
      fclose (logger->log_file);
      free (logger);
    }
}
