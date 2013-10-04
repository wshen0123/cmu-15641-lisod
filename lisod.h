#ifndef __LISOD_H__
#define __LISOD_H__
#include <signal.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include "fifo.h"
#include "log.h"
#include "http.h"

#ifdef DEBUG
  #define TIMEOUT 100
#else
  #define TIMEOUT 5
#endif

#define INET_IPLEN INET6_ADDRSTRLEN
#define INET_PORTLEN 10
#define LISOD_MAXLEN 0x1000

typedef struct
{
  int sock_fd;
  SSL *ssl_context;

  int has_job;        /* ensure next job won't run until current finishes */
  int pipe_fd;
  int cgi_pid;

  char ip[INET_IPLEN];
  unsigned short port;

  http_handle_t *http_handle;

  fifo_t *recv_buf;
  fifo_t *send_buf;
  int flush_close;      /* not read any more as bad requst but send error msg */

  time_t last_activity;	/* used for conn time out auto close */
} client_t;

struct global_var
{
  /* command line argument */
  char *lock_file_path;
  char *www_folder_path;
  char *cgi_folder_path;

  /* lisod system var */
  unsigned short http_port;
  unsigned short https_port;
  int http_sock;
  int https_sock;
  SSL_CTX *ssl_context;

  log_t *log;
  int lock_file;

  /* lisod client var */
  ssize_t maxfd;
  fd_set read_set;		/* set of all active read descriptors */
  fd_set read_ready_set;	/* set of descriptors ready to read */
  fd_set write_set;		/* set of all active write descriptors */
  fd_set write_ready_set;	/* set of descriptors ready for write */
  int n_ready;			/* number of descriptors ready */

  client_t *client_curr;
  client_t *clients[FD_SETSIZE];
  int maxi;		        /* highwater index into client array */
  ssize_t nclients;             /* max number of concurrent cliens */
  ssize_t maxclients;
} G;

#endif
