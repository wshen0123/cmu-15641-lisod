#ifndef __LISOD_H__
#define __LISOD_H__
#include <signal.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>

#include "fifo.h"
#include "log.h"
#include "http.h"

#ifdef DEBUG
#define TIMEOUT 1000
#else
#define TIMEOUT 5
#endif

#define INET_IPLEN INET6_ADDRSTRLEN
#define INET_PORTLEN 10
#define LISOD_MAXLEN 0x1000
#define BACKLOG 50

typedef struct
{
  int sock_fd;
  SSL *ssl_context;

  /* ensure next job won't run until current finishes: pipelining order */
  bool has_job_undone;			
  int cgi_pipe;
  int cgi_pid;

  char ip[INET_IPLEN];
  unsigned short port;

  http_handle_t *http_handle;

  fifo_t *recv_buf;		/* buffer pipelined request for sequential parse */
  fifo_t *pipe_buf;		/* buffer cgi output to parse CGI Status -> HTTP Status */
  fifo_t *send_buf;             /* buffer lisod response */

  bool shut_down;		/* not read any more as bad requst but send error msg */

  /* backup internal error static buf in case of system resource falure */
  bool use_internal_error_buf;
  const char *internal_error_buf_ptr;
  ssize_t internal_error_buf_to_write_len;

  time_t last_activity;		/* used for conn time out auto close */
} client_t;

struct global_var
{
  /* command line argument */
  char *lock_file_path;
  char *www_folder;
  char *cgi_path;

  /* lisod system var */
  unsigned short http_port;
  unsigned short https_port;
  int http_sock;
  int https_sock;
  SSL_CTX *ssl_context;

  log_t *log;
  int lock_file_fd;

  /* lisod client var */
  ssize_t max_fd;
  fd_set read_set;		/* set of all active read descriptors */
  fd_set read_ready_set;	/* set of descriptors ready to read */
  fd_set write_set;		/* set of all active write descriptors */
  fd_set write_ready_set;	/* set of descriptors ready for write */
  int num_ready;		/* number of descriptors ready */

  client_t *client_curr;
  client_t *clients[FD_SETSIZE];
  int maxi;			/* highwater index into client array */
} G;

#endif
