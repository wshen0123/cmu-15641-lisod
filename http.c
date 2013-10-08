#include "http.h"

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
#include <signal.h>
#include <time.h>

static const int MAXLEN = 1000;
#define HTTP_CGI_MAX_ARGV    2
#define HTTP_CGI_MAX_ENVP    30
#define HTTP_CGI_ENVP_MAXLEN 1000


enum http_uri_type
{
  HTTP_URI_STATIC = 0,
  HTTP_URI_DYNAMIC = 1,

  HTTP_URI_INVALID,		/* contain invalid token */
};

static char *HTTP_NULL = "";

typedef struct
{
  int status_code;
  char *reason_phrase;
} http_status_code_reason_phrase;

const http_status_code_reason_phrase status_2_reason[] = {
  [SC_200_OK] = {200, "OK"},
  [SC_302_FOUND] = {302, "Found"},
  [SC_304_NOT_MODIFIED] = {304, "Not Modified"},
  [SC_400_BAD_REQUEST] = {400, "Bad Request"},
  [SC_403_FORBIDDEN] = {403, "Forbidden"},
  [SC_404_NOT_FOUND] = {404, "Not Found"},
  [SC_405_METHOD_NOT_ALLOWED] = {405, "Method Not Allowed"},
  [SC_411_LENGTH_REQUIRED] = {412, "Length Required"},
  [SC_413_REQUEST_ENTITY_TOO_LARGE] = {413, "Request Entity Too Large"},
  [SC_414_REQUEST_URI_TOO_LONG] = {414, "Request URI Too Long"},
  [SC_500_SERVER_INTERNAL_ERROR] = {500, "Server Internal Error"},
  [SC_501_NOT_IMPLEMENTED] = {501, "Not Implemented"},
  [SC_503_SERVICE_UNAVAILABLE] = {503, "Service Unavailable"},
  [SC_505_HTTP_VERSION_NOT_SUPPORTED] = {505, "HTTP Version Not Supported"},

  [SC_LAST] = {999, "Opps?!!! How do we get here :>=<:"},
};

enum http_uri_type check_uri_type (const char *uri);
int parse_uri_static (http_handle_t * hh, char *file_path);
int parse_uri_dynamic (http_handle_t * hh, char *path_info, char *request_uri,
		       char *query_string, char *script_name);

static int http_do_response (http_handle_t * req, fifo_t * send_buf,
			     int *pipe_fd, pid_t * cgi_pid);
static int http_do_response_static (http_handle_t * hh, fifo_t * send_buf);
static int http_do_response_dynamic (http_handle_t * hh, fifo_t * send_buf,
				     int *pipe_fd, int *pid);
static int http_do_response_error (http_handle_t * hh, fifo_t * send_buf);

ssize_t http_parser_execute (http_handle_t * h, char *request,
			     ssize_t req_len);
enum http_status http_parser_on_request_line (http_request_t * req,
					      const char *buf);
enum http_status http_parser_on_header_line (http_request_t * req,
					     const char *buf);

static void http_handle_reset (http_handle_t * h);
void http_parser_init (http_parser_t * parser);
void http_parser_reset (http_parser_t * parser);
void http_request_init (http_request_t * request);
void http_request_reset (http_request_t * request);

static void get_file_type (char *file_name, char *file_type);
void build_envp (http_handle_t * hh, char *envp[], char *path_info,
		 char *request_uri, char *query_string, char *script_name);
char *make_string (const char *str);


http_handle_t *
http_handle_init (http_setting_t * setting)
{
  http_handle_t *hh;

  hh = malloc (sizeof (http_handle_t));
  if (!hh)
    return NULL;

  http_parser_init (&hh->parser);
  http_request_init (&hh->request);
  hh->status = SC_UNKNOWN;

  hh->www_folder = setting->www_folder;
  hh->cgi_path = setting->cgi_path;
  hh->client_ip = setting->client_ip;
  hh->client_port = setting->client_port;
  hh->server_port = setting->server_port;
  hh->log = setting->log;

  return hh;
}

enum http_connection_state
http_handle_execute (http_handle_t * hh,
                     fifo_t * recv_buf,
		     fifo_t * send_buf,
                     int *pipe_fd, pid_t * cgi_pid)
{
  ssize_t handled_len;

  handled_len = http_parser_execute (hh, fifo_head(recv_buf), fifo_len(recv_buf));
  fifo_out(recv_buf, handled_len);

  if (PARSING_INCOMPLETE (hh->parser.state))
    {
      return HCS_CONNECTION_ALIVE;
    }

  if (http_do_response (hh, send_buf, pipe_fd, cgi_pid))
    {
      fifo_flush (recv_buf);
      return HCS_CONNECTION_CLOSE_INTERNAL_ERROR;
    }

  if (hh->parser.state == S_DEAD)
    {
      fifo_flush (recv_buf);
      return HCS_CONNECTION_CLOSE_BAD_REQUEST;
    }

  if (hh->parser.state == S_DONE)
    {
      if (hh->request.keep_alive)
        {
          http_handle_reset (hh);
          return HCS_CONNECTION_ALIVE;
        }
      else
        {
          fifo_flush (recv_buf);
          return HCS_CONNECTION_CLOSE_FINISHED;
        }
    }
  return HCS_CONNECTION_ALIVE;
}


void
http_handle_reset (http_handle_t * hh)
{
  if (!hh)
    return;
  http_parser_reset (&hh->parser);
  http_request_reset (&hh->request);
  hh->status = SC_LAST;
}

void
http_handle_free (http_handle_t * hh)
{
  if (!hh)
    return;
  http_request_reset (&hh->request);
  free (hh);
}

void
http_parser_init (http_parser_t * parser)
{
  http_parser_reset (parser);
}

void
http_parser_reset (http_parser_t * parser)
{
  if (!parser)
    return;
  parser->state = S_START;
  parser->header_len = 0;
  parser->body_len = 0;
  memset (parser->buf, 0, sizeof (parser->buf));
  parser->buf_index = 0;
}

ssize_t
http_parser_execute (http_handle_t * hh, char *request, ssize_t req_len)
{
  char c, *buf, *mbuf;
  const char *p, *pe;
  size_t to_read, header_len, body_len, buf_index;
  enum http_state state;
  http_parser_t *parser;

  parser = &hh->parser;
  state = parser->state;
  header_len = parser->header_len;
  body_len = parser->body_len;
  buf = parser->buf;
  buf_index = parser->buf_index;

  for (p = request, pe = request + req_len; p < pe; p++)
    {
      c = *p;
      if (PARSING_HEADER (state))
	{
	  header_len++;
	  if (header_len > HTTP_HEADER_MAXLEN)
	    {
	      state = S_DEAD;
	      hh->status = SC_413_REQUEST_ENTITY_TOO_LARGE;
	    }
	}

      switch (state)
	{
	case S_START:
	  state = S_REQUEST_LINE;
	case S_REQUEST_LINE:
	  if (c != CR)
	    {
	      buf[buf_index++] = c;
	      break;
	    }
	  buf[buf_index] = '\0';
	  hh->status = http_parser_on_request_line (&hh->request, buf);
	  if (ERROR_STATUS (hh->status))
	    state = S_DEAD;
	  else
	    state = S_REQUEST_LINE_LF;
	  buf_index = 0;
	  break;

	case S_REQUEST_LINE_LF:
	  if (c != LF)
	    {
	      state = S_DEAD;
	      break;
	    }

	  state = S_HEADER_LINE;
	  break;

	case S_HEADER_LINE:
	  if (c != CR)
	    {
	      buf[buf_index++] = c;
	      break;
	    }

	  buf[buf_index] = '\0';
	  if (buf_index > 0)
	    {
	      hh->status = http_parser_on_header_line (&hh->request, buf);
	      if (ERROR_STATUS (hh->status))
		state = S_DEAD;
	      else
		state = S_HEADER_LINE_LF;
	    }
	  else
	    {
	      state = S_HEADERS_LF;
	    }
	  buf_index = 0;
	  break;

	case S_HEADER_LINE_LF:
	  if (c != LF)
	    {
	      state = S_DEAD;
	      break;
	    }
	  state = S_HEADER_LINE;
	  break;

	case S_HEADERS_LF:
	  if (c != LF)
	    {
	      state = S_DEAD;
	      break;
	    }
	  if (HAS_BODY (hh->request.method))
	    {
	      if (hh->request.content_length >= 0)
		{
		  state = S_MESSAGE_BODY;
		}
	      else
		{
		  state = S_DEAD;
		  hh->status = SC_411_LENGTH_REQUIRED;
		}
	    }
	  else
	    {
	      state = S_DONE;
	    }
	  break;

	case S_MESSAGE_BODY:
	  if (!hh->request.message_body)
	    {
	      mbuf = malloc (hh->request.content_length);
	      if (mbuf)
		{
		  hh->request.message_body = mbuf;
		}
	      else
		{
		  hh->status = SC_500_SERVER_INTERNAL_ERROR;
		  state = S_DEAD;
		  log (hh->log, "ERROR", "malloc: %s", strerror (errno));
		}
	    }

	  to_read = MIN (pe - p, hh->request.content_length - body_len);

	  if (to_read > 0)
	    {
	      memcpy (hh->request.message_body, p, to_read);
	      body_len += to_read;
	      p += to_read;
	    }
	  if (body_len == hh->request.content_length)
	    {
	      state = S_DONE;
	    }
	  break;

	case S_DONE:
	  break;
	default:
	  break;
	}			/* end-of switch(c) */
      if (!PARSING_INCOMPLETE (state))
	break;
    }				/* end of for */
  parser->state = state;
  parser->header_len = header_len;
  parser->buf_index = buf_index;

  return p - request;
}


enum http_status
http_parser_on_request_line (http_request_t * req, const char *request_line)
{
  char method[HTTP_HEADER_MAXLEN] = "";
  char uri[HTTP_HEADER_MAXLEN] = "";
  char version[HTTP_HEADER_MAXLEN] = "";

  sscanf (request_line, "%s %s %s", method, uri, version);

  req->uri = make_string (uri);

  if (!strcmp (method, "GET"))
    req->method = HM_GET;
  else if (!strcmp (method, "HEAD"))
    req->method = HM_HEAD;
  else if (!strcmp (method, "POST"))
    req->method = HM_POST;
  else
    {
      req->method = HM_NOT_IMPLEMENTED;
      return SC_501_NOT_IMPLEMENTED;
    }

  if (!strcmp (version, "HTTP/1.0"))
    {
      req->version = HV_10;
    }
  else if (!strcmp (version, "HTTP/1.1"))
    {
      req->version = HV_11;
    }
  else
    {
      req->version = HV_NOT_IMPLEMENTED;
      return SC_505_HTTP_VERSION_NOT_SUPPORTED;
    }

  return SC_200_OK;
}

enum http_status
http_parser_on_header_line (http_request_t * req, const char *header_line)
{
  const char *p;
  char *cp;
  char name[HTTP_HEADER_MAXLEN] = "";
  char value[HTTP_HEADER_MAXLEN] = "";

  p = header_line;
  while (*p != '\0')
    if (!IS_HEADER_CHAR (*p++))
      return SC_400_BAD_REQUEST;

  sscanf (header_line, "%[^:]: %s", name, value);

  if (req->num_header < HTTP_MAX_HEADER_NUM)
    {
      req->headers[req->num_header][HTTP_HEADER_NAME] = make_string (name);
      req->headers[req->num_header][HTTP_HEADER_VALUE] = make_string (value);

      req->num_header++;

      if (!strcasecmp (name, "CONTENT-LENGTH"))
	{
	  if (strlen (value) == 0)
	    return SC_411_LENGTH_REQUIRED;

	  cp = value;
	  while (*cp != '\0')
	    if (!IS_NUM (*cp++))
	      {
		return SC_400_BAD_REQUEST;
		break;
	      }
	  req->content_length = atoi (value);
	}
      if (!strcasecmp (name, "CONNECTION"))
        {
          if (!strcasecmp (value, "keep-alive"))
            req->keep_alive = true;
          else
            req->keep_alive = false;
        }
    }
  else
    {
      return SC_413_REQUEST_ENTITY_TOO_LARGE;
    }

  return SC_200_OK;
}

void
http_request_init (http_request_t * request)
{
  request->method = HM_UNKNOWN;
  request->uri = NULL;
  request->version = HV_UNKNOWN;
  request->num_header = 0;
  request->keep_alive = false;
  request->message_body = NULL;
  request->content_length = -1;
}

void
http_request_reset (http_request_t * request)
{
  int i;

  for (i = 0; i < request->num_header; i++)
    {
      free (request->headers[i][HTTP_HEADER_NAME]);
      free (request->headers[i][HTTP_HEADER_VALUE]);
    }
  request->num_header = 0;

  if (request->uri)
    {
      free (request->uri);
      request->uri = NULL;
    }
  if (request->message_body)
    {
      free (request->message_body);
      request->message_body = NULL;
    }
  request->version = HV_UNKNOWN;
  request->keep_alive = false;
  request->content_length = -1;
}


int
http_do_response (http_handle_t * hh, fifo_t * send_buf, int *pipe_fd,
		  pid_t * cgi_pid)
{
  enum http_uri_type uri_type;

  if (ERROR_STATUS (hh->status))
    return http_do_response_error (hh, send_buf);

  uri_type = check_uri_type (hh->request.uri);

  switch (uri_type)
    {
    case HTTP_URI_STATIC:
      return http_do_response_static (hh, send_buf);
      break;
    case HTTP_URI_DYNAMIC:
      return http_do_response_dynamic (hh, send_buf, pipe_fd, cgi_pid);
      break;
    case HTTP_URI_INVALID:
      hh->status = SC_403_FORBIDDEN;
      return http_do_response_error (hh, send_buf);
      break;
    default:
      break;
    }

  return 0;
}

int
http_do_response_static (http_handle_t * hh, fifo_t * send_buf)
{
  static const char HTTP_RESPONSE_OK[] =
    "HTTP/1.0 200 ok\r\n"
    "Server: Lisod/1.0\r\n"
    "Date: %s\r\n"
    "Keep-Alive: timeout=5\r\n"
    "Content-length: %zd\r\n"
    "Content-type: %s\r\n\r\n";

  char buf[HTTP_HEADER_MAXLEN],
    file_path[MAXLEN], file_type[MAXLEN], date[MAXLEN], *file_data, *p;
  int file_fd;
  size_t file_size;
  struct stat sbuf;
  time_t now;
  struct tm tm;

  if (hh->request.method == HM_POST)
    {
      hh->status = SC_400_BAD_REQUEST;
      return http_do_response_error (hh, send_buf);
    }

  now = time (0);
  tm = *gmtime (&now);
  strftime (date, MAXLEN, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  if (parse_uri_static (hh, file_path))
    {
      hh->status = SC_400_BAD_REQUEST;
      return http_do_response_error (hh, send_buf);
    }

  if (stat (file_path, &sbuf) < 0)
    {
      hh->status = SC_404_NOT_FOUND;
      return http_do_response_error (hh, send_buf);
    }

  if (!(S_ISREG (sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode))
    {
      hh->status = SC_403_FORBIDDEN;
      return http_do_response_error (hh, send_buf);
    }

  file_size = sbuf.st_size;
  get_file_type (file_path, file_type);

  snprintf (buf, HTTP_HEADER_MAXLEN, HTTP_RESPONSE_OK, date, file_size, file_type);

  /* if has response body */

  if (hh->request.method == HM_GET)
    {
      file_fd = open (file_path, O_RDONLY);
      file_data = mmap (0, file_size, PROT_READ, MAP_PRIVATE, file_fd, 0);
      close (file_fd);
      if (!file_data)
	{
	  hh->status = SC_500_SERVER_INTERNAL_ERROR;
	  return http_do_response_error (hh, send_buf);
	}
      p = fifo_extend (send_buf, strlen (buf) + file_size);
      if (!p)
	return -1;
      memcpy (p, buf, strlen (buf));
      memcpy (p + strlen (buf), file_data, file_size);
      munmap (file_data, file_size);
    }
  else if (hh->request.method == HM_HEAD)
    {
      p = fifo_extend (send_buf, strlen (buf));
      if (!p)
	return -1;
      memcpy (p, buf, strlen (buf));
    }
  else
    {
      log (hh->log, "ERROR",
	   "http method not implemented, how do we get here?");
      return -1;
    }

  return 0;
}


int
http_do_response_error (http_handle_t * hh, fifo_t * send_buf)
{
  static const char HTTP_RESPONSE_ERROR[] =
    "HTTP/1.0 %d %s\r\n"
    "Server: Lisod/1.0\r\n"
    "Date: %s\r\n" "Content-length: %zd\r\n" "Content-type: %s\r\n\r\n";

  static const char HTTP_RESPONSE_ERROR_HTML[] =
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
    "<html><head>"
    "<title>%d %s</title>" "</head><body>" "<h1>%s</h1>" "</body></html>";

  char res_buf[MAXLEN], html_buf[MAXLEN], date[MAXLEN], *reason;
  int code;
  size_t content_length;
  time_t now;
  struct tm tm;

  now = time (0);
  tm = *gmtime (&now);
  strftime (date, MAXLEN, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  code = status_2_reason[hh->status].status_code;
  reason = status_2_reason[hh->status].reason_phrase;

  snprintf (html_buf, MAXLEN, HTTP_RESPONSE_ERROR_HTML, code, reason, reason);

  content_length = strlen (html_buf);

  snprintf (res_buf, MAXLEN, HTTP_RESPONSE_ERROR, code, reason, date, content_length,
	   "text/html");
  strcat (res_buf, html_buf);

  if (fifo_in (send_buf, res_buf, strlen (res_buf)) < 0)
    return -1;

  return 0;
}


int
http_do_response_dynamic (http_handle_t * hh, fifo_t * send_buf, int *pipe_fd,
			  pid_t * cgi_pid)
{
  pid_t pid;
  int write_ret;
  int stdin_pipe[2];
  int stdout_pipe[2];
  char *ARGV[HTTP_CGI_MAX_ARGV] = { NULL, };
  char *ENVP[HTTP_CGI_MAX_ENVP] = { NULL, };
  char path_info[HTTP_CGI_ENVP_MAXLEN] = "";
  char request_uri[HTTP_CGI_ENVP_MAXLEN] = "";
  char query_string[HTTP_CGI_ENVP_MAXLEN] = "";
  char script_name[HTTP_CGI_ENVP_MAXLEN] = "";

  if (parse_uri_dynamic
      (hh, path_info, request_uri, query_string, script_name))
    {
      hh->status = SC_400_BAD_REQUEST;
      return http_do_response_error (hh, send_buf);
    }

  if (pipe (stdin_pipe) < 0)
    return -1;
  if (pipe (stdout_pipe) < 0)
    return -1;

  pid = fork ();

  if (pid < 0)
    {
      log (hh->log, "ERROR", "fork: %s", strerror (errno));
      return -1;
    }

  if (pid == 0)
    {
      /* note we put those envp here to avoid leaking lisod memory */
      close (stdout_pipe[0]);
      close (stdin_pipe[1]);
      dup2 (stdout_pipe[1], fileno (stdout));
      dup2 (stdin_pipe[0], fileno (stdin));

      ARGV[0] = make_string (hh->cgi_path);
      ARGV[1] = NULL;

      build_envp (hh, ENVP, path_info, request_uri, query_string,
		  script_name);

      if (execve (ARGV[0], ARGV, ENVP))
	{
	  log (hh->log, "ERROR", "execve: %s", strerror (errno));
	  //TODO add do_http_response_error
	  exit (EXIT_FAILURE);
	}
    }
  else
    {
      close (stdout_pipe[1]);
      close (stdin_pipe[0]);

      if (hh->request.method == HM_POST)
	{
	  write_ret = write (stdin_pipe[1], hh->request.message_body,
			     hh->request.content_length);
	  if (write_ret < 0)
	    return -1;
	}

      close (stdin_pipe[1]);
      *pipe_fd = stdout_pipe[0];

      *cgi_pid = pid;

      return 0;
    }
  return 0;
}

void
http_cgi_finish_callback (fifo_t * send_buf, fifo_t * pipe_buf)
{
  static const char HTTP_RESPONSE_LINE[] = "HTTP/1.1 %d %s\r\n";
  static const size_t STATUS_LINE_MINLEN = 11;

  int i, status_code;
  char *cp, *reason_phrase, response_line[MAXLEN];

  cp = fifo_head (pipe_buf);

  if (fifo_len (pipe_buf) > STATUS_LINE_MINLEN
      && !strncasecmp (cp, "status: ", strlen ("status: ")))
    {
      cp += strlen ("status: ");
      status_code = atoi (cp);
      for (i = 0; i < SC_LAST - 1; i++)
	{
	  if (status_2_reason[i].status_code == status_code)
	    {
	      reason_phrase = status_2_reason[i].reason_phrase;
	      break;
	    }
	}
      snprintf (response_line, MAXLEN, HTTP_RESPONSE_LINE, status_code, reason_phrase);
      fifo_in (send_buf, response_line, strlen (response_line));
    }
  fifo_in (send_buf, fifo_head (pipe_buf), fifo_len (pipe_buf));
}

void
build_envp (http_handle_t * hh, char *envp[], char *path_info,
	    char *request_uri, char *query_string, char *script_name)
{
  int index, i;
  char buf[MAXLEN], *(*headers)[2];

  index = 0;

  envp[index++] = make_string ("GATEWAY_INTERFACE=CGI/1.1");
  envp[index++] = make_string ("SERVER_PROTOCOL=HTTP/1.1");
  envp[index++] = make_string ("SERVER_SOFTWARE=Lisod/1.0");
  envp[index++] = make_string ("SERVER_NAME=Wayne Lisod");
  snprintf (buf, MAXLEN, "PATH_INFO=%s", path_info);
  envp[index++] = make_string (buf);
  snprintf (buf, MAXLEN, "REQUEST_URI=%s", request_uri);
  envp[index++] = make_string (buf);
  snprintf (buf, MAXLEN, "REMOTE_ADDR=%s", hh->client_ip);
  envp[index++] = make_string (buf);
  snprintf (buf, MAXLEN, "SERVER_PORT=%d", hh->server_port);
  envp[index++] = make_string (buf);
  snprintf (buf, MAXLEN, "QUERY_STRING=%s", query_string);
  envp[index++] = make_string (buf);
  snprintf (buf, MAXLEN, "SCRIPT_NAME=%s", script_name);
  envp[index++] = make_string (buf);
  snprintf (buf, MAXLEN, "CONTENT_LENGTH=%zd", hh->request.content_length);
  envp[index++] = make_string (buf);


  switch (hh->request.method)
    {
    case HM_GET:
      envp[index++] = make_string ("REQUEST_METHOD=GET");
      break;
    case HM_POST:
      envp[index++] = make_string ("REQUEST_METHOD=POST");
      break;
    case HM_HEAD:
      envp[index++] = make_string ("REQUEST_METHOD=HEAD");
      break;
    default:
      break;
    }

  headers = hh->request.headers;

  for (i = 0; i < hh->request.num_header; i++)
    {
      if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "CONTENT-TYPE"))
	{
	  snprintf (buf, MAXLEN, "CONTENT_TYPE=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "ACCEPT"))
	{
	  snprintf (buf, MAXLEN, "HTTP_ACCEPT=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "REFERER"))
	{
	  snprintf (buf, MAXLEN, "HTTP_REFERER=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "ACCEPT-ENCODING"))
	{
	  snprintf (buf, MAXLEN, "HTTP_ACCEPT_ENCODING=%s",
		   headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "ACCPET-LANGUAGE"))
	{
	  snprintf (buf, MAXLEN, "HTTP_ACCEPT_LANGUAGE=%s",
		   headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "ACCEPT-CHARSET"))
	{
	  snprintf (buf, MAXLEN, "HTTP_ACCEPT_CHARSET=%s",
		   headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "COOKIE"))
	{
	  snprintf (buf, MAXLEN, "HTTP_COOKIE=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "USER-AGENT"))
	{
	  snprintf (buf, MAXLEN, "HTTP_USER_AGENT=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "CONNECTION"))
	{
	  envp[index++] = make_string (buf);
	}
      else if (!strcasecmp (headers[i][HTTP_HEADER_NAME], "HOST"))
	{
	  snprintf (buf, MAXLEN, "HTTP_HOST=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
    }
  envp[index] = NULL;
}


enum http_uri_type
check_uri_type (const char *uri)
{
  if (strstr (uri, ".."))
    return HTTP_URI_INVALID;

  if (strncmp (uri, "/cgi/", 5))
    return HTTP_URI_STATIC;
  else
    return HTTP_URI_DYNAMIC;
}


int
parse_uri_static (http_handle_t * hh, char *file_path)
{
  char *uri, *p;

  uri = hh->request.uri;

  strcpy (file_path, hh->www_folder);

  if (uri[strlen (uri) - 1] == '/')
    {
      strcat (file_path, "index.html");
    }
  else if (uri[0] == '/')
    {
      strcat (file_path, uri);
    }
  else if ((p = strstr (uri, "//")))
    {
      if ((p = strstr (p + 2, "/")))
	{
	  strcat (file_path, p);
	}
      else
	{
	  strcat (file_path, "index.html");
	}
    }
  else
    {
      return -1;
    }
  return 0;
}


int
parse_uri_dynamic (http_handle_t * hh, char *path_info, char *request_uri,
		   char *query_string, char *script_name)
{
  char *uri, *path, *query;

  uri = hh->request.uri;

  if ((path = strstr (uri, "/cgi/")))
    {
      if (!(query = index (uri, '?')))
	{
	  query = uri + strlen (uri);
	  strcpy (query_string, "");
	}
      else
	{
	  strcpy (query_string, query + 1);
	}
      strcpy (script_name, "/cgi");
      strncpy (path_info, path + 4, query - path - 4);
      strncpy (request_uri, path, query - path);
      return 0;
    }
  else
    {
      return -1;
    }
}



void
get_file_type (char *file_name, char *file_type)
{
  if (strstr (file_name, ".html"))
    strcpy (file_type, "text/html");
  else if (strstr (file_name, ".gif"))
    strcpy (file_type, "image/gif");
  else if (strstr (file_name, ".jpg"))
    strcpy (file_type, "image/jpeg");
  else
    strcpy (file_type, "text/plain");
}				/* end of get_file_type */


char *
make_string (const char *str)
{
  int len = strlen (str) + 1;
  char *newstr = (char *) malloc (len);
  if (newstr == NULL)
    return HTTP_NULL;
  else
    {
      strcpy (newstr, str);
      return newstr;
    }
}
