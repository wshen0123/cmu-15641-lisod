#include "lisod.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <openssl/ssl.h>

#define BACKLOG 10
#define MAXCLIENTS 100

static int lisod_setup (char *cmd, char *http_port, char *https_port,
			char *log_file_path, char *lock_file_fd_path,
			char *www_folder_path, char *cgi_folder_path,
			char *private_key_path, char *certificate_path,
			ssize_t max_num_client);
static int lisod_run ();
static void lisod_signal_handler (int sig);

static client_t *client_new (int client_sock, const char *client_ip,
			     unsigned short client_port,
			     unsigned short server_port);
static int client_add (int client_sock, const char *client_ip,
		       unsigned short client_port,
		       unsigned short server_port);
static void client_close (client_t * client);

static void on_accept ();
static void onum_ready ();
static int on_read_sock ();
static int on_read_pipe ();
static int on_write ();

static void *get_in_addr (struct sockaddr *sa);
static in_port_t get_in_port (struct sockaddr *sa);
typedef void handler_t (int);
static handler_t *Signal (int signum, handler_t * handler);

static int open_sock (char *port);
static int close_sock (int sock);

static void daemonize (const char *cmd);
static int already_running ();
static void check_timeout (int sig);

static int
lisod_setup (char *cmd, char *http_port, char *https_port,
	     char *log_file_path, char *lock_file_path, char *www_folder_path,
	     char *cgi_folder_path, char *private_key_path,
	     char *certificate_path, ssize_t max_num_client)
{
  int i;

  G.lock_file_path = lock_file_path;
  G.www_folder_path = www_folder_path;
  G.cgi_folder_path = cgi_folder_path;
  G.max_num_client = max_num_client;

  if (already_running (cmd))
    {
      fprintf (stderr, "Error: already running\n");
      return EXIT_FAILURE;
    }

  daemonize (cmd);

  G.log = log_init (log_file_path);
  if (!G.log)
    {
      fprintf (stderr, "Error: init log\n");
      return EXIT_FAILURE;
    }

  /* init http sock */
  G.http_sock = open_sock (http_port);
  if (G.http_sock < 0)
    {
      log (G.log, "ERROR", "open_sock(%s): %s", http_port, strerror (errno));
      lisod_signal_handler (0);
    }
  G.http_port = atoi (http_port);

  /* init TLS sock */
  SSL_load_error_strings ();
  SSL_library_init ();

  G.ssl_context = SSL_CTX_new (TLSv1_server_method ());
  if (!G.ssl_context)
    {
      log (G.log, "ERROR", "SSL_CTX_new: Error creating SSL context");
      lisod_signal_handler (0);
    }
  if (SSL_CTX_use_PrivateKey_file (G.ssl_context, private_key_path,
				   SSL_FILETYPE_PEM) == 0)
    {
      log (G.log, "ERROR",
	   "SSL_CTX_use_PrivateKey_file: Error associating private key");
      lisod_signal_handler (0);
    }
  if (SSL_CTX_use_certificate_file (G.ssl_context, certificate_path,
				    SSL_FILETYPE_PEM) == 0)
    {
      log (G.log, "ERROR",
	   "SSL_CTX_use_certificate_file: Error associating certificate");
      lisod_signal_handler (SIGTERM);
    }
  G.https_sock = open_sock (https_port);
  if (G.https_sock < 0)
    {
      log (G.log, "ERROR", "open_sock(%s): %s", https_port, strerror (errno));
      lisod_signal_handler (SIGTERM);
    }
  G.https_port = atoi (https_port);

  FD_ZERO (&G.read_set);
  FD_SET (G.http_sock, &G.read_set);
  FD_SET (G.https_sock, &G.read_set);
  FD_ZERO (&G.write_set);

  G.max_fd = (G.http_sock > G.https_sock ? G.http_sock : G.https_sock);
  G.num_ready = 0;
  G.maxi = -1;
  for (i = 0; i < FD_SETSIZE; i++)
    {
      G.clients[i] = NULL;
    }

  log (G.log, "INFO", "[lisod pid:%5ld] SETUP", (long) getpid ());

  Signal (SIGALRM, check_timeout);
  alarm (TIMEOUT);

  return 0;
}				/* end of lisod_init */

int
lisod_run ()
{
  while (1)
    {
      G.read_ready_set = G.read_set;
      G.write_ready_set = G.write_set;
      G.num_ready =
	select (G.max_fd + 1, &G.read_ready_set,
		&G.write_ready_set, NULL, NULL);
      if (G.num_ready > 0)
	{
	  if (FD_ISSET (G.http_sock, &G.read_ready_set))
	    on_accept (G.http_sock);
	  if (FD_ISSET (G.https_sock, &G.read_ready_set))
	    on_accept (G.https_sock);
	  onum_ready ();
	}
      else if (errno == EINTR)
	{
	  continue;
	}
      else
	{
	  log (G.log, "ERROR", "select: %s", strerror (errno));
	  break;
	}
    }
  lisod_signal_handler (SIGTERM);
  return EXIT_SUCCESS;
}				/* end of lisod_run */

void
lisod_signal_handler (int sig)
{
  int i;
  pid_t pid;

  if (sig == SIGTERM || sig == SIGINT)
    {
      if (G.http_sock >= 0)
	close_sock (G.http_sock);
      if (G.https_sock >= 0)
	close_sock (G.https_sock);

      if (G.ssl_context)
	SSL_CTX_free (G.ssl_context);
      log (G.log, "INFO", "[lisod pid:%5ld] SHUTDOWN", (long) getpid ());
      log_exit (G.log);
      remove (G.lock_file_path);

      for (i = 0; i < FD_SETSIZE; i++)
	client_close (G.clients[i]);

      exit (EXIT_SUCCESS);
    }
  else if (sig == SIGCHLD)
    {
      do
	{
	  pid = waitpid (-1, NULL, 0);
	}
      while (pid > 0);

      if (errno != ECHILD)
	log (G.log, "ERROR", "waitpid error");
    }
} /* end of lisod_signal_handler */

void
on_accept (int server_sock)
{
  int client_sock;
  struct sockaddr_storage client_addr;
  socklen_t cli_size = sizeof (client_addr);
  char client_ip[INET_IPLEN];
  unsigned short client_port, server_port;

  /* accept client conncetion */

  G.num_ready--;
  if (G.num_client >= G.max_num_client)
    return;
  client_sock = accept (server_sock, (struct sockaddr *) &client_addr,
                        &cli_size);

  if (client_sock < 0)
    {
      log (G.log, "ERROR", "accept: %s", strerror (errno));
      return;
    }
  inet_ntop (client_addr.ss_family,
	     get_in_addr ((struct sockaddr *) &client_addr),
	     client_ip, sizeof (client_ip));

  client_port = ntohs (get_in_port ((struct sockaddr *) &client_addr));
  log (G.log, "INFO", "%s:%-5d - connected", client_ip, client_port);

  /* add client(fd) to pool */
  server_port = (server_sock == G.http_sock ? G.http_port : G.https_port);

  if (client_add (client_sock, client_ip, client_port, server_port) < 0)
    {
      log (G.log, "ERROR", "client_add: client pool full");
      close_sock (client_sock);
    }
}				/* end of on_accept */

void
onum_ready ()
{
  int i, client_sock, client_pipe;

  for (i = 0; (i <= G.maxi) && (G.num_ready > 0); i++)
    {
      if (!G.clients[i])
	continue;

      G.client_curr = G.clients[i];

      client_sock = G.client_curr->sock_fd;
      client_pipe = G.client_curr->pipe_fd;

      if (FD_ISSET (client_sock, &G.read_ready_set))
	{
	  G.num_ready--;
	  if (on_read_sock () < 0)
	    {
	      G.clients[i] = NULL;
	      continue;
	    }
	}
      if (client_pipe >= 0)
	{
	  if (FD_ISSET (client_pipe, &G.read_ready_set))
	    G.num_ready--;
	  if (on_read_pipe () < 0)
	    {
	      G.clients[i] = NULL;
	      continue;
	    }
	}
      if (FD_ISSET (client_sock, &G.write_ready_set))
	{
	  G.num_ready--;
	  if (on_write () < 0)
	    {
	      G.clients[i] = NULL;
	      continue;
	    }
	}
      continue;
    }
}				/*  end of onum_ready */

int
on_read_sock ()
{
  int cgi_pipe_fd, cgi_pid;
  char buf[LISOD_MAXLEN];
  ssize_t readret, nparsed;
  client_t *client;

  if (G.client_curr->has_job)
    return 0;

  client = G.client_curr;
  time (&client->last_activity);

  if (client->ssl_context)
    readret = SSL_read (client->ssl_context, buf, LISOD_MAXLEN);
  else
    readret = recv (client->sock_fd, buf, LISOD_MAXLEN, 0);

  if (readret > 0)
    {
      cgi_pipe_fd = -1;
      nparsed = http_handle_execute (client->http_handle,
				     buf, readret,
                                     client->send_buf,
				     &cgi_pipe_fd, &cgi_pid);
      if (nparsed < 0)
	{
	  log (G.log, "INFO", "%s:%-5d - bad reqeust -> flush_close",
	       client->ip, client->port);
	  client->flush_close = 1;
	  FD_CLR (client->sock_fd, &G.read_set);	/* no recv but write to */
	}
      else			/* buffer unparsed request bytes */
	{
	  if (fifo_in (client->recv_buf, buf + nparsed, readret - nparsed) <
	      0)
	    {
	      log (G.log, "ERROR", "fifo_in error");
	      client_close (client);
	      return -1;
	    }
	}
      if (cgi_pipe_fd >= 0)	/* got cgi pipe as response: dynamic content */
	{
	  client->has_job = 1;
	  client->pipe_fd = cgi_pipe_fd;
	  client->cgi_pid = cgi_pid;
	  FD_SET (cgi_pipe_fd, &G.read_set);
	}
      return 0;
    }
  else if (errno == EINTR)
    {
      return 0;
    }
  else if (readret == 0)
    {
      log (G.log, "INFO", "%s:%-5d - closed", client->ip, client->port);
      client_close (client);
      return -1;
    }
  else
    {
      log (G.log, "INFO", "%s:%-5d - read error %s", client->ip, client->port,
	   strerror (errno));
      client_close (client);
      return -1;
    }
}				/* end of on_read_sock */

int
on_read_pipe ()
{
  char buf[LISOD_MAXLEN];
  ssize_t readret;
  client_t *client;

  client = G.client_curr;

  readret = read (client->pipe_fd, buf, LISOD_MAXLEN);

  if (readret > 0)
    {
      if (fifo_in (client->send_buf, buf, readret) < 0)
	{
	  client_close (client);
	  log (G.log, "ERROR", "fifo_in error");
	  return -1;
	}
      return 0;
    }
  else if (readret == 0)	/* job finished */
    {
      FD_CLR (client->pipe_fd, &G.read_set);
      close (client->pipe_fd);
      client->pipe_fd = -1;
      client->has_job = 0;
      return 0;
    }
  else if (errno == EINTR)
    {
      return 0;
    }
  else
    {
      log (G.log, "INFO", "[pipe] read error %s", strerror (errno));
      client_close (client);
      return -1;
    }
}


int
on_write ()
{
  ssize_t writeret;
  client_t *client;

  client = G.client_curr;

  /* for TCP only, ssl need other recv method */

  if (fifo_len (client->send_buf) == 0)
    return 0;

  time (&client->last_activity);

  if (client->ssl_context)
    writeret = SSL_write (client->ssl_context, fifo_head (client->send_buf),
			  fifo_len (client->send_buf));
  else
    writeret =
      send (client->sock_fd, fifo_head (client->send_buf),
	    fifo_len (client->send_buf), MSG_NOSIGNAL);

  if (writeret >= 0)
    {
      if (client->flush_close && writeret == fifo_len (client->send_buf))
	{
	  client_close (client);
	  return -1;
	}
      else
	{
	  fifo_out (client->send_buf, writeret);
	  return 0;
	}
    }
  else if (errno == EINTR)
    {
      return 0;
    }
  else
    {
      log (G.log, "INFO", "%s:%-5d - write error %s", client->ip, client->port,
	   strerror (errno));
      client_close (client);
      return -1;
    }
}				/* end of on_write */

int
client_add (int client_sock, const char *client_ip,
	    unsigned short client_port, unsigned short server_port)
{
  int i;

  for (i = 0; i < FD_SETSIZE; i++)
    {
      if (!G.clients[i])
	{
	  G.clients[i] =
	    client_new (client_sock, client_ip, client_port, server_port);
	  if (!G.clients[i])
	    {
	      log (G.log, "ERROR", "client_new:%s", strerror (errno));
	      return -1;
	    }
	  FD_SET (client_sock, &G.read_set);
	  FD_SET (client_sock, &G.write_set);
	  if (client_sock > G.max_fd)
	    G.max_fd = client_sock;
	  if (i > G.maxi)
	    G.maxi = i;
	  G.num_client++;
	  break;
	}
    }
  if (i == FD_SETSIZE)
    return -1;
  return 0;
}

client_t *
client_new (int client_sock, const char *client_ip,
	    unsigned short client_port, unsigned short server_port)
{
  client_t *client;
  http_setting_t hh;

  client = malloc (sizeof (client_t));
  if (!client)
    return NULL;

  client->sock_fd = client_sock;
  if (server_port == G.https_port)
    {
      client->ssl_context = SSL_new (G.ssl_context);
      if (!client->ssl_context)
	{
	  log (G.log, "ERROR", "SSL_new: Error creating client SSL context");
	  goto ssl_error;
	}
      if (SSL_set_fd (client->ssl_context, client_sock) == 0)
	{
	  SSL_free (client->ssl_context);
	  log (G.log, "ERROR",
	       "SSL_set_fd: Error creating client SSL context");
	  goto ssl_error;
	}
      if (SSL_accept (client->ssl_context) <= 0)
	{
	  SSL_free (client->ssl_context);
	  log (G.log, "ERROR",
	       "SSL_accept: Error accepting (handshake) client SSL context");
	  goto ssl_error;
	}
    }
  else
    {
      client->ssl_context = NULL;
    }
  client->has_job = 0;
  client->pipe_fd = -1;
  client->cgi_pid = -1;

  strcpy (client->ip, client_ip);
  client->port = client_port;

  client->recv_buf = fifo_init (0);
  if (!client->recv_buf)
    {
      log (G.log, "ERROR", "fifo_init error");
      free (client);
      return NULL;
    }
  client->send_buf = fifo_init (0);
  if (!client->send_buf)
    {
      log (G.log, "ERROR", "fifo_init error");
      free (client);
      return NULL;
    }

  client->flush_close = 0;
  time (&client->last_activity);

  hh.www_folder_path = G.www_folder_path;
  hh.cgi_folder_path = G.cgi_folder_path;
  hh.client_ip = client->ip;
  hh.client_port = client_port;
  hh.server_port = server_port;
  hh.log = G.log;

  client->http_handle = http_handle_new (&hh);

  return client;

ssl_error:
  free (client);
  return NULL;
}


void
client_close (client_t * client)
{
  if (!client)
    return;

  if (client->ssl_context)
    {
      SSL_shutdown (client->ssl_context);
      SSL_free (client->ssl_context);
    }
  if (client->sock_fd >= 0)
    {
      FD_CLR (client->sock_fd, &G.read_set);
      FD_CLR (client->sock_fd, &G.write_set);
      close_sock (client->sock_fd);
    }
  if (client->pipe_fd >= 0)
    close (client->pipe_fd);


  fifo_free (client->recv_buf);
  fifo_free (client->send_buf);
  http_handle_free (client->http_handle);
  free (client);
  G.num_client--;
}				/* end of client_new & client_exit */

void
daemonize (const char *cmd)
{
  Signal (SIGHUP, SIG_IGN);
  Signal (SIGPIPE, SIG_IGN);
  Signal (SIGINT, lisod_signal_handler);
  Signal (SIGTERM, lisod_signal_handler);
  Signal (SIGCHLD, lisod_signal_handler);

#ifdef DEBUG
  return;
#else
  int i, fd0, fd1, fd2;
  pid_t pid;
  struct rlimit rl;
  char buf[LISOD_MAXLEN];

  /* Clear file creation mask. */
  umask (0);

  /* Get maximum number of file descriptors. */
  if (getrlimit (RLIMIT_NOFILE, &rl) < 0)
    fprintf (stderr, "Error: can't get file limit");

  /* Become a session leader to lose controlling TTY. */
  if ((pid = fork ()) < 0)
    fprintf (stderr, "Error: can't fork");
  else if (pid != 0)		/* parent */
    exit (EXIT_SUCCESS);
  setsid ();

  if ((pid = fork ()) < 0)
    fprintf (stderr, "Error: can't fork");
  else if (pid != 0)		/* parent */
    exit (0);

  ftruncate (G.lock_file_fd, 0);
  sprintf (buf, "%ld", (long) getpid ());
  write (G.lock_file_fd, buf, strlen (buf) + 1);

  /*
   * Change the current working directory to the root so
   * we won't prevent file systems from being unmounted.
   */
  if (chdir ("/") < 0)
    fprintf (stderr, "Error: can't change directory to /");

  /*
   * Close all open file descriptors.
   */
  if (rl.rlim_max == RLIM_INFINITY)
    rl.rlim_max = 1024;
  for (i = 0; i < rl.rlim_max; i++)
    close (i);

  /* Attach file descriptors 0, 1, and 2 to /dev/null. */
  fd0 = open ("/dev/null", O_RDWR);
  fd1 = dup (0);
  fd2 = dup (0);

  /* Initialize the log file. */
  openlog (cmd, LOG_CONS, LOG_DAEMON);
  if (fd0 != 0 || fd1 != 1 || fd2 != 2)
    {
      syslog (LOG_ERR, "unexpected file descriptors %d %d %d", fd0, fd1, fd2);
      exit (EXIT_FAILURE);
    }
#endif
}				/* end of daemonize */

int
already_running ()
{
#define LOCKMODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH)

#ifndef DEBUG
  G.lock_file_fd = open (G.lock_file_fd_path, O_RDWR | O_CREAT | O_EXCL, LOCKMODE);
  if (G.lock_file_fd < 0)
    {
      fprintf (stderr, "Error: cannot create lock file\n");
      return -1;
    }
#endif

  return 0;
}				/* end of already_running */

/**
 * @brief       wrapper for signal function
 *
 * @param       signum
 * @param       handler
 *
 * @return      
 */
handler_t *
Signal (int signum, handler_t * handler)
{
  struct sigaction action, old_action;

  action.sa_handler = handler;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_RESTART;

  if (sigaction (signum, &action, &old_action) < 0)
    {
      log (G.log, "ERROR", "Signal: %s", strerror (errno));
      exit (EXIT_FAILURE);
    }
  return (old_action.sa_handler);
}				/* end of Signal */

void
check_timeout (int sig)
{
  int i;
  double time_gone;
  client_t *client;

  for (i = 0; i <= G.maxi; i++)
    {
      if (!G.clients[i])
	continue;

      client = G.clients[i];

      time_gone = difftime (time (NULL), G.clients[i]->last_activity);

      if (time_gone > TIMEOUT)
	{
	  log (G.log, "INFO", "%s:%-5d] timed out and force closed",
	       client->ip, client->port);
	  client_close (client);
	  G.clients[i] = NULL;
	}
    }
  alarm (TIMEOUT);
}


/**
 * @brief       open server socket, bind to @port and listen 
 *
 * @param       port
 *
 * @return      server socket file descriptor
 */
int
open_sock (char *port)
{
  int yes = 1, sock;
  struct addrinfo hints, *servinfo, *p;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;

  if (getaddrinfo (NULL, port, &hints, &servinfo) != 0)
    return -1;

  for (p = servinfo; p != NULL; p = p->ai_next)
    {
      sock = socket (p->ai_family, p->ai_socktype, p->ai_protocol);
      if (sock < 0)
	continue;

      if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &yes,
		      sizeof (int)) < 0)
	return -1;

      if (bind (sock, p->ai_addr, p->ai_addrlen) < 0)
	{
	  close (sock);
	  continue;
	}
      break;
    }

  freeaddrinfo (servinfo);

  if (p == NULL)
    return -1;

  if (listen (sock, BACKLOG) < 0)
    {
      close (sock);
      return -1;
    }
  return sock;
}				/* end of open_sock */

int
close_sock (int sock)
{
  if (close (sock))
    {
      log (G.log, "ERROR", "close: %s", strerror (errno));
      return 1;
    }
  return 0;
}				/* end of close_sock */


void *
get_in_addr (struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
    {
      return &(((struct sockaddr_in *) sa)->sin_addr);
    }
  return &(((struct sockaddr_in6 *) sa)->sin6_addr);
}

in_port_t
get_in_port (struct sockaddr *sa)
{
  if (sa->sa_family == AF_INET)
    {
      return (((struct sockaddr_in *) sa)->sin_port);
    }
  return (((struct sockaddr_in6 *) sa)->sin6_port);
}

int
main (int argc, char *argv[])
{
  if (argc != 9)
    {
      fprintf (stderr,
	       "Usage: ./lisod < HTTP port > < HTTPS port > < log ﬁle > <"
	       "lock ﬁle > < www folder > < CGI folder or script name > <"
	       "private key ﬁle > < certiﬁcate ﬁle >\n");
      return -1;
    }

  if (lisod_setup
      (argv[0], argv[1], argv[2], argv[3], argv[4], argv[5], argv[6], argv[7],
       argv[8], MAXCLIENTS))
    return -1;


  lisod_run ();

  return EXIT_FAILURE;
}
