#include "lisod.h"
#include "log.h"

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

#ifdef DEBUG
static char DEBUG_BUF[LISOD_MAXLEN];
#endif
static const char SERVER_ERROR_MSG[] =
  "HTTP/1.1 500 Internal Server Error\r\n"
  "Server: Lisod 1.0\r\n" "Vary: Accept-Encoding\r\n"
  "Content-Length: 479\r\n"
  "Connection: close\r\n"
  "Content-Type: text/html; charset=iso-8859-1\r\n\r\n"
  "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
  "<html>"
  "<head><title>500 Internal Server Error</title></head>"
  "<body>"
  "<h1>Internal Server Error</h1>"
  "<p>The server encountered an internal error or misconfiguration "
  "and was unable to complete your request.</p><p>Please contact the "
  "server administrator, webmaster@localhost and inform them of the "
  "time the error occurred, and anything you might have done that may "
  "have caused the error.</p><hr><address>Lisod 1.0</address></body></html>";
static const ssize_t SERVER_ERROR_MSG_LEN = sizeof (SERVER_ERROR_MSG) - 1;

/* We can pass G around but since there is only single instance I made it gloabl */
static struct global_var G;


static int lisod_setup (char *cmd, char *http_port, char *https_port,
			char *log_file_path, char *lock_file_fd_path,
			char *www_folder, char *cgi_path,
			char *private_key_path, char *certificate_path);
static int lisod_run ();
static void lisod_signal_handler (int sig);
static void lisod_exit ();

static void on_SIGCHLD ();
static void on_accept ();
static void on_ready ();
static int on_read_sock ();
static int on_read_pipe ();
static int on_write ();
static int on_http_execute ();
static int on_cgi_job_done (client_t * client);

static client_t *client_init (int client_sock, const char *client_ip,
			      unsigned short client_port,
			      unsigned short server_port);
static int client_add (client_t * client);
static client_t *client_find_by_cgi_pid (pid_t pid);
static void client_close (client_t * client);

static void *get_in_addr (struct sockaddr *sa);
static in_port_t get_in_port (struct sockaddr *sa);
typedef void handler_t (int);
static handler_t *Signal (int signum, handler_t * handler);

static int open_listen_sock (char *port);
static int close_sock (int sock);

static void daemonize (const char *cmd);
static bool already_running ();
static bool check_flushed (client_t * client);
static void check_timeout (int sig);

static int
lisod_setup (char *cmd,
	     char *http_port, char *https_port,
	     char *log_file_path, char *lock_file_path,
	     char *www_folder, char *cgi_path,
	     char *private_key_path, char *certificate_path)
{
  int i;

  G.lock_file_path = lock_file_path;
  G.www_folder = www_folder;
  G.cgi_path = cgi_path;

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
  G.http_sock = open_listen_sock (http_port);
  if (G.http_sock < 0)
    {
      log (G.log, LL_ERROR, "open_listen_sock(%s): %s", http_port, strerror (errno));
      lisod_signal_handler (0);
    }
  G.http_port = atoi (http_port);

  /* init TLS sock */
  SSL_load_error_strings ();
  SSL_library_init ();

  G.ssl_context = SSL_CTX_new (TLSv1_server_method ());
  if (!G.ssl_context)
    {
      log (G.log, LL_ERROR, "SSL_CTX_new: Error creating SSL context");
      lisod_signal_handler (0);
    }
  if (SSL_CTX_use_PrivateKey_file (G.ssl_context, private_key_path,
				   SSL_FILETYPE_PEM) == 0)
    {
      log (G.log, LL_ERROR,
	   "SSL_CTX_use_PrivateKey_file: Error associating private key");
      lisod_signal_handler (0);
    }
  if (SSL_CTX_use_certificate_file (G.ssl_context, certificate_path,
				    SSL_FILETYPE_PEM) == 0)
    {
      log (G.log, LL_ERROR,
	   "SSL_CTX_use_certificate_file: Error associating certificate");
      lisod_signal_handler (SIGTERM);
    }
  G.https_sock = open_listen_sock (https_port);
  if (G.https_sock < 0)
    {
      log (G.log, LL_ERROR, "open_listen_sock(%s): %s", https_port,
	   strerror (errno));
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

  log (G.log, LL_INFO, "[lisod pid:%5ld] SETUP", (long) getpid ());

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
	  on_ready ();
	}
      else if (errno == EINTR)
	{
	  continue;
	}
      else
	{
	  log (G.log, LL_ERROR, "select: %s", strerror (errno));
	  break;
	}
    }
  lisod_signal_handler (SIGTERM);
  return EXIT_SUCCESS;
}				/* end of lisod_run */

void
lisod_signal_handler (int sig)
{
  if (sig == SIGTERM || sig == SIGINT)
    {
      lisod_exit ();
    }
  else if (sig == SIGCHLD)
    {
      on_SIGCHLD ();
    }
}				/* end of lisod_signal_handler */

void
lisod_exit ()
{
  int i;

  if (G.http_sock >= 0)
    close_sock (G.http_sock);
  if (G.https_sock >= 0)
    close_sock (G.https_sock);

  if (G.ssl_context)
    SSL_CTX_free (G.ssl_context);

  for (i = 0; i < FD_SETSIZE; i++)
    client_close (G.clients[i]);

  remove (G.lock_file_path);

  log (G.log, LL_INFO, "[lisod pid:%5ld] Remove Lock file", (long) getpid ());
  log (G.log, LL_INFO, "[lisod pid:%5ld] SHUTDOWN", (long) getpid ());

  log_exit (G.log);

  exit (EXIT_SUCCESS);
}

/* reap child process and check their exit status */
void
on_SIGCHLD ()
{
  int status = 0;
  pid_t pid;
  client_t *client;
  do
    {
      pid = waitpid (-1, &status, 0);
      if (WIFEXITED (status) && (WEXITSTATUS (status) == EXIT_SUCCESS))
	continue;
      
      /* if CGI exited abnormally, echo error msg, close connection */

      client = client_find_by_cgi_pid (pid);
      if (client)
	{
	  log (G.log, LL_INFO, "cgi(pid:%ld) exit(%d)", (long) getpid (),
	       WEXITSTATUS (status));

	  if (fifo_in
	      (client->send_buf, SERVER_ERROR_MSG,
	       strlen (SERVER_ERROR_MSG)) < 0)
	    {
	      log (G.log, LL_ERROR, "fifo_in error");
	      client_close (client);
	    }
	  log (G.log, LL_INFO, "%s:%-5d - cgi error, will shutdown",
	       client->ip, client->port);
	  client->shut_down = true;
	  FD_CLR (client->sock_fd, &G.read_set);
	}
    }
  while (pid > 0);

  if (errno != ECHILD)
    log (G.log, LL_ERROR, "waitpid error");
}

void
on_accept (int server_sock)
{
  int client_sock;
  struct sockaddr_storage client_addr;
  socklen_t cli_size = sizeof (client_addr);
  char client_ip[INET_IPLEN];
  unsigned short client_port, server_port;
  client_t *client;

  /* accept client conncetion */
  G.num_ready--;

  client_sock = accept (server_sock, (struct sockaddr *) &client_addr,
			&cli_size);
  if (client_sock < 0)
    {
      log (G.log, LL_ERROR, "accept: %s", strerror (errno));
      return;
    }
  inet_ntop (client_addr.ss_family,
	     get_in_addr ((struct sockaddr *) &client_addr),
	     client_ip, sizeof (client_ip));
  client_port = ntohs (get_in_port ((struct sockaddr *) &client_addr));
  log (G.log, LL_INFO, "%s:%-5d + connected", client_ip, client_port);

  /* add client(fd) to pool */
  server_port = (server_sock == G.http_sock ? G.http_port : G.https_port);

  client = client_init (client_sock, client_ip, client_port, server_port);
  if (!client)
    {
      log (G.log, LL_ERROR, "client_new:%s", strerror (errno));
      close_sock (client_sock);
      return;
    }
  if (client_add (client))
    {
      log (G.log, LL_ERROR, "client_add: client pool full");
      if (fifo_in
	  (client->send_buf, SERVER_ERROR_MSG, strlen (SERVER_ERROR_MSG)) < 0)
	{
	  log (G.log, LL_ERROR, "fifo_in error");
	  client_close (client);
	}

      FD_SET (client->sock_fd, &G.write_set);
      client->shut_down = true;
    }
}				/* end of on_accept */

void
on_ready ()
{
  int i, sock, pipe;
  client_t *client;

  for (i = 0; (i <= G.maxi) && (G.num_ready > 0); i++)
    {
      if (!G.clients[i])
	continue;

      G.client_curr = G.clients[i];
      client = G.client_curr;

      sock = G.client_curr->sock_fd;
      pipe = G.client_curr->cgi_pipe;

      if (FD_ISSET (sock, &G.read_ready_set))
	{
	  G.num_ready--;
	  if (on_read_sock () < 0)
	    {
	      G.clients[i] = NULL;
	      continue;
	    }
	}
      if ((pipe >= 0) && FD_ISSET (pipe, &G.read_ready_set))
	{
	  G.num_ready--;
	  if (on_read_pipe () < 0)
	    {
	      G.clients[i] = NULL;
	      continue;
	    }
	}

      on_http_execute ();

      if (FD_ISSET (sock, &G.write_ready_set))
	{
	  G.num_ready--;
	  if (on_write () < 0)
	    {
	      G.clients[i] = NULL;
	      continue;
	    }
	}

      if (check_flushed (client))
	{
	  log (G.log, LL_INFO, "%s:%-5d - flushed ", client->ip,
	       client->port);
	  client_close (client);
	  G.clients[i] = NULL;
	}
      continue;
    }
}				/*  end of on_ready */

int
on_read_sock ()
{
  char buf[LISOD_MAXLEN];
  ssize_t readret;
  client_t *client;

  client = G.client_curr;
  time (&client->last_activity);

  if (client->ssl_context)
    readret = SSL_read (client->ssl_context, buf, LISOD_MAXLEN);
  else
    readret = recv (client->sock_fd, buf, LISOD_MAXLEN, 0);

  if (readret > 0)
    {
#ifdef DEBUG
      memcpy (DEBUG_BUF, buf, readret);
      DEBUG_BUF[readret] = '\0';
      log (G.log, LL_DEBUG, "%s:%-5d - on_read_sock: \n%s",
	   client->ip, client->port, DEBUG_BUF);
#endif
      if (fifo_in (client->recv_buf, buf, readret) < 0)
	return -1;
      return 0;
    }
  else if (errno == EINTR)
    {
      return 0;
    }
  else if (readret == 0)
    {
      client->shut_down = true;
      FD_CLR (client->sock_fd, &G.read_set);
      log (G.log, LL_INFO, "%s:%-5d - client shutdown",
	   client->ip, client->port);
      return 0;
    }
  else
    {
      log (G.log, LL_INFO, "%s:%-5d - read error %s", client->ip,
	   client->port, strerror (errno));
      client_close (client);
      return -1;
    }
  return -1;
}				/* end of on_read_sock */

int
on_read_pipe ()
{
  char buf[LISOD_MAXLEN];
  ssize_t readret;
  client_t *client;

  client = G.client_curr;

  readret = read (client->cgi_pipe, buf, LISOD_MAXLEN);

  if (readret > 0)
    {
      if (fifo_in (client->pipe_buf, buf, readret) < 0)
	{
	  log (G.log, LL_ERROR, "fifo_in error");
	  client_close (client);
	  return -1;
	}
      return 0;
    }
  else if (readret == 0)	/* job finished */
    {
      return on_cgi_job_done (client);
    }
  else if (errno == EINTR)
    {
      return 0;
    }
  else
    {
      log (G.log, LL_INFO, "[pipe] read error %s", strerror (errno));
      client_close (client);
      return -1;
    }
  return -1;
}

int
on_write ()
{
  ssize_t writeret;
  client_t *client;

  client = G.client_curr;

  if (fifo_len (client->send_buf) == 0)
    return 0;

  time (&client->last_activity);

  if (client->use_internal_error_buf)
    {
      writeret = send (client->sock_fd, client->internal_error_buf_ptr,
		       client->internal_error_buf_to_write_len, MSG_NOSIGNAL);
    }
  else
    {

      if (client->ssl_context)
	writeret = SSL_write (client->ssl_context, fifo_head (client->send_buf),
                              fifo_len (client->send_buf));
      else
	writeret = send (client->sock_fd, fifo_head (client->send_buf),
			 fifo_len (client->send_buf), MSG_NOSIGNAL);
    }

  if (writeret >= 0)
    {
      if (client->use_internal_error_buf)
	{
	  client->internal_error_buf_ptr += writeret;
	  client->internal_error_buf_to_write_len -= writeret;
	  return 0;
	}
      else
	{
	  fifo_out (client->send_buf, writeret);
	  return 0;
	}
      return 0;
    }
  else if (errno == EINTR)
    {
      return 0;
    }
  else
    {
      log (G.log, LL_INFO, "%s:%-5d - write error %s", client->ip,
	   client->port, strerror (errno));
      client_close (client);
      return -1;
    }
}				/* end of on_write */


/* let http module do with recv_buf and write response to send_buf or return
 * with a cgi_pipe with cgi_pid for on_write() to read into pipe_buf.
 * It also checks http module's return as connection_state parsed from header
 * or determined by parsing routine(e.g. bad request). */
int
on_http_execute ()
{
  int cgi_pipe, cgi_pid;
  enum http_connection_state conn_state;
  client_t *client;

  client = G.client_curr;

  if (client->has_job_undone || (fifo_len (client->recv_buf) == 0))
    return 0;

  log (G.log, LL_DEBUG, "%s:%-5d - on_http_execute", client->ip, client->port);

  cgi_pipe = -1;
  cgi_pid = -1;
  conn_state = http_handle_execute (client->http_handle,
				    client->recv_buf,
				    client->send_buf, &cgi_pipe, &cgi_pid);
  switch (conn_state)
    {
    case HCS_CONNECTION_CLOSE_BAD_REQUEST:
      {
	log (G.log, LL_INFO, "%s:%-5d - bad request, will close",
	     client->ip, client->port);

	client->shut_down = true;
	FD_CLR (client->sock_fd, &G.read_set);
        break;
      }				/* fall through to flush close procedure */
    case HCS_CONNECTION_CLOSE_FINISHED:	
      {
	log (G.log, LL_INFO, "%s:%-5d - connection: close",
	     client->ip, client->port);

	client->shut_down = true;
	FD_CLR (client->sock_fd, &G.read_set);

	if (cgi_pipe >= 0)
	  {
	    client->has_job_undone = true;
	    client->cgi_pipe = cgi_pipe;
	    client->cgi_pid = cgi_pid;
	    FD_SET (cgi_pipe, &G.read_set);
	    if (cgi_pipe > G.max_fd)
	      G.max_fd = cgi_pipe;
	  }
	break;
      }
    case HCS_CONNECTION_CLOSE_INTERNAL_ERROR:
      {
	log (G.log, LL_INFO, "%s:%-5d - internal error, will shutdown client",
             client->ip, client->port);
	FD_CLR (client->sock_fd, &G.read_set);	/* no recv but write to */
	client->use_internal_error_buf = true;
	client->internal_error_buf_ptr = SERVER_ERROR_MSG;
	client->internal_error_buf_to_write_len = SERVER_ERROR_MSG_LEN;
	break;
      }
    case HCS_CONNECTION_ALIVE:
      {
	if (cgi_pipe >= 0)	/* got cgi pipe as response: dynamic content */
	  {
	    client->has_job_undone = true;
	    client->cgi_pipe = cgi_pipe;
	    client->cgi_pid = cgi_pid;
	    FD_SET (cgi_pipe, &G.read_set);
	    if (cgi_pipe > G.max_fd)
	      G.max_fd = cgi_pipe;
	  }
      }
      break;
    default:
      break;
    }
  return 0;
}

/* removes cgi_pipe and translate CGI Status to HTTP response line */
int
on_cgi_job_done (client_t * client)
{
  log (G.log, LL_DEBUG, "on_cgi_job_done: %d", client->port);

  /* tranlate CGI response into http response */
  http_cgi_2_http_response (client->send_buf, client->pipe_buf);
  fifo_flush (client->pipe_buf);

  FD_CLR (client->cgi_pipe, &G.read_set);
  close (client->cgi_pipe);
  client->cgi_pipe = -1;
  client->has_job_undone = false;
  return 0;
}

/* add client to lisod client pool */
int
client_add (client_t * client)
{
  int i;

  for (i = 0; i < FD_SETSIZE; i++)
    {
      if (!G.clients[i])
	{
	  G.clients[i] = client;
	  FD_SET (client->sock_fd, &G.read_set);
	  FD_SET (client->sock_fd, &G.write_set);
	  if (client->sock_fd > G.max_fd)
	    G.max_fd = client->sock_fd;
	  if (i > G.maxi)
	    G.maxi = i;
	  break;
	}
    }
  if (i == FD_SETSIZE)
    return -1;
  return 0;
}

client_t *
client_init (int client_sock, const char *client_ip,
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
	  log (G.log, LL_ERROR, "SSL_new: Error creating client SSL context");
	  goto ssl_error;
	}
      if (SSL_set_fd (client->ssl_context, client_sock) == 0)
	{
	  SSL_free (client->ssl_context);
	  log (G.log, LL_ERROR,
	       "SSL_set_fd: Error creating client SSL context");
	  goto ssl_error;
	}
      if (SSL_accept (client->ssl_context) <= 0)
	{
	  SSL_free (client->ssl_context);
	  log (G.log, LL_ERROR,
	       "SSL_accept: Error accepting (handshake) client SSL context");
	  goto ssl_error;
	}
    }
  else
    {
      client->ssl_context = NULL;
    }
  client->has_job_undone = false;
  client->cgi_pipe = -1;
  client->cgi_pid = -1;

  strcpy (client->ip, client_ip);
  client->port = client_port;

  client->recv_buf = fifo_init (0);
  if (!client->recv_buf)
    goto fifo_error;
  client->pipe_buf = fifo_init (0);
  if (!client->pipe_buf)
    goto fifo_error;
  client->send_buf = fifo_init (0);
  if (!client->send_buf)
    goto fifo_error;

  client->shut_down = false;
  time (&client->last_activity);

  client->use_internal_error_buf = false;
  client->internal_error_buf_ptr = NULL;
  client->internal_error_buf_to_write_len = 0;
  hh.www_folder = G.www_folder;
  hh.cgi_path = G.cgi_path;
  hh.client_ip = client->ip;
  hh.client_port = client_port;
  hh.server_port = server_port;
  hh.use_https = (server_port == G.https_port ? true : false);
  hh.log = G.log;

  client->http_handle = http_handle_init (&hh);

  return client;

fifo_error:
  log (G.log, LL_ERROR, "fifo_init error");
  SSL_free (client->ssl_context);

ssl_error:
  free (client);
  return NULL;
}

client_t *
client_find_by_cgi_pid (pid_t pid)
{
  int i;

  for (i = 0; i <= G.maxi; i++)
    {
      if (!G.clients[i])
	continue;

      if (G.clients[i]->cgi_pid == pid)
	return G.clients[i];
    }

  return NULL;
}

/* clean up all client resources:fd, SSL, buffer */
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
      log (G.log, LL_INFO, "%s:%-5d - closed", client->ip, client->port);
    }
  if (client->cgi_pipe >= 0)
    {
      FD_CLR (client->cgi_pipe, &G.read_set);
      close (client->cgi_pipe);
    }

  fifo_free (client->recv_buf);
  fifo_free (client->pipe_buf);
  fifo_free (client->send_buf);
  http_handle_free (client->http_handle);
  free (client);
}				/* end of client_new & client_exit */

/* daemonize code referred from APUE chapter 13 */
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
  snprintf (buf, LISOD_MAXLEN, "%ld", (long) getpid ());
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

/* checks if daemon already running */
bool
already_running ()
{
#ifndef DEBUG
  static const mode_t LOCKMODE = (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  G.lock_file_fd =
    open (G.lock_file_path, O_RDWR | O_CREAT | O_EXCL, LOCKMODE);
  if (G.lock_file_fd < 0)
    {
      fprintf (stderr, "Error: cannot create lock file\n");
      return true;
    }
#endif

  return false;
}				/* end of already_running */

/* signal handler resigter wrapper */
handler_t *
Signal (int signum, handler_t * handler)
{
  struct sigaction action, old_action;

  action.sa_handler = handler;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_RESTART;

  if (sigaction (signum, &action, &old_action) < 0)
    {
      log (G.log, LL_ERROR, "Signal: %s", strerror (errno));
      exit (EXIT_FAILURE);
    }
  return (old_action.sa_handler);
}

/* check if client if shutdown and all response is flushed
 * then we can safely close the client socket */
bool
check_flushed (client_t * client)
{
  if (client->shut_down && !client->has_job_undone)
    {
      if (client->use_internal_error_buf
	  && client->internal_error_buf_to_write_len == 0)
	return true;
      else if
	(fifo_len (client->recv_buf) == 0 && fifo_len (client->send_buf) == 0)
	return true;
    }
  return false;
}

/* called by lisod_signal_handler on SIGALRM every TIMEOUTs
 * clean timedout client */
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
	  log (G.log, LL_INFO, "%s:%-5d timed out", client->ip, client->port);
	  client_close (client);
	  G.clients[i] = NULL;
	}
    }
  alarm (TIMEOUT);
}

int
open_listen_sock (char *port)
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

      if (setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof (int)) < 0)
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
}				/* end of open_listen_sock */

int
close_sock (int sock)
{
  if (close (sock))
    {
      log (G.log, LL_ERROR, "close: %s", strerror (errno));
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
       argv[8]))
    return -1;


  lisod_run ();

  return EXIT_FAILURE;
}
