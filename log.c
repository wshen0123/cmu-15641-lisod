#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define LOG_MSG_BUF_SIZE 4096
#define LOG_TIME_BUF_SIZE 30

void
_log (log_t * logger, const char *level, const char *fmt, ...)
{
  va_list va_arg;
  char log_msg[LOG_MSG_BUF_SIZE], time_string[LOG_TIME_BUF_SIZE];
  time_t now = time (0);

  if (logger)
    {
      va_start (va_arg, fmt);
      strftime(time_string, LOG_TIME_BUF_SIZE, "%Y-%m-%d %H:%M:%S", localtime (&now));
      vsnprintf (log_msg, LOG_MSG_BUF_SIZE, fmt, va_arg);
      fprintf (logger->log_file, "[%s] %-5s %s\n", time_string, level,
	       log_msg);
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
