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

  HTTP_URI_INVALID, /* contain invalid token */
}; 

static char *HTTP_NULL = "";

typedef struct
{
  int status_code;
  char *reason_phase;
} http_status_code_reason_phase;

const http_status_code_reason_phase status_2_reason[] = {
  [sc_200_ok] = {200, "ok"},
  [sc_400_bad_request] = {400, "bad request"},
  [sc_403_forbidden] = {403, "forbidden"},
  [sc_404_not_found] = {404, "not found"},
  [sc_411_length_required] = {411, "length required"},
  [sc_413_request_entity_too_large] = {413, "request entity too large"},
  [sc_414_request_uri_too_long] = {414, "request uri too long"},
  [sc_500_server_internal_error] = {500, "server_internal_error"},
  [sc_501_not_implemented] = {501, "not implemented"},
  [sc_503_service_unavailable] = {503, "service unavailable"},
  [sc_505_http_version_not_supported] = {505, "http version not supported"},

  [sc_999_unknown] = {999, "Opps?!!! How do we get here :>=<:"},
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

ssize_t http_parser_execute (http_handle_t * h, char *request, ssize_t req_len);
enum http_status http_parser_request_line  (http_request_t * req,
					  const char *buf);
enum http_status http_parser_header_line  (http_request_t * req,
					 const char *buf);

static void http_handle_reset (http_handle_t * h);
void http_parser_reset (http_parser_t * parser);
void http_request_reset (http_request_t * request);

static void get_file_type (char *file_name, char *file_type);
void build_envp (http_handle_t * hh, char *envp[], char *path_info,
		 char *request_uri, char *query_string, char *script_name);
char *make_string (const char *str);


http_handle_t *
http_handle_new (http_setting_t * setting)
{
  http_handle_t *hh;

  hh = malloc (sizeof (http_handle_t));
  if (!hh)
    return NULL;

  memset (hh, 0, sizeof (http_handle_t));	/* member defaults to 0 */

  hh->www_folder_path = setting->www_folder_path;
  hh->cgi_folder_path = setting->cgi_folder_path;
  hh->client_ip = setting->client_ip;
  hh->client_port = setting->client_port;
  hh->server_port = setting->server_port;
  hh->log = setting->log;

  return hh;
}

ssize_t
http_handle_execute (http_handle_t * hh, char *request, ssize_t req_len,
		     fifo_t * send_buf, int *pipe_fd, pid_t * cgi_pid)
{
  ssize_t nparsed;

  nparsed = http_parser_execute (hh, request, req_len);

  if (PARSING_INCOMPLETE (hh->parser.state))
    return nparsed;

  if (http_do_response (hh, send_buf, pipe_fd, cgi_pid))
    return -1;

  if (hh->parser.state == s_dead)
    return -1;

  if (hh->parser.state == s_done)
    http_handle_reset (hh);

  return nparsed;
}


void
http_handle_reset (http_handle_t * hh)
{
  http_parser_reset(&hh->parser);
  http_request_reset(&hh->request);
  hh->status = sc_999_unknown;
}

void
http_parser_reset (http_parser_t * parser)
{
  parser->state = s_start;
  parser->header_len = 0;
  parser->body_len = 0;
  memset(parser->buf, 0, sizeof(parser->buf));
  parser->buf_index = 0;
}

void
http_request_reset (http_request_t * request)
{
  int i;
  
  for (i = 0; i < request->num_headers; i++)
    {
      free (request->headers[i][HTTP_HEADER_NAME]);
      free (request->headers[i][HTTP_HEADER_VALUE]);
    }
  request->num_headers = 0;

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
  request->content_length = -1;
}


void
http_handle_free (http_handle_t * hh)
{
  http_request_reset (&hh->request);
  free (hh);
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
	  if (header_len > HTTP_MAX_HEADER_SIZE)
	    {
	      state = s_dead;
	      hh->status = sc_413_request_entity_too_large;
	    }
	}

      switch (state)
	{
	case s_start:
	  state = s_request_line;
	case s_request_line:
	  if (c != CR)
	    {
	      buf[buf_index++] = c;
	      break;
	    }
	  buf[buf_index] = '\0';
	  hh->status = http_parser_request_line  (&hh->request, buf);
	  if (ERROR_STATUS (hh->status))
	    state = s_dead;
	  else
	    state = s_request_line_LF;
	  buf_index = 0;
	  break;

	case s_request_line_LF:
	  if (c != LF)
	    {
	      state = s_dead;
	      break;
	    }

	  state = s_header_line;
	  break;

	case s_header_line:
	  if (c != CR)
	    {
	      buf[buf_index++] = toupper (c);
	      break;
	    }

	  buf[buf_index] = '\0';
	  if (buf_index > 0)
	    {
	      hh->status = http_parser_header_line  (&hh->request, buf);
	      if (ERROR_STATUS (hh->status))
		state = s_dead;
	      else
		state = s_header_line_LF;
	    }
	  else
	    {
	      state = s_headers_LF;
	    }
	  buf_index = 0;
	  break;

	case s_header_line_LF:
	  if (c != LF)
	    {
	      state = s_dead;
	      break;
	    }
	  state = s_header_line;
	  break;

	case s_headers_LF:
	  if (c != LF)
	    {
	      state = s_dead;
	      break;
	    }
	  if (HAS_BODY (hh->request.method))
	    {
	      if (hh->request.content_length >= 0)
		{
		  state = s_message_body;
		}
	      else
		{
		  state = s_dead;
		  hh->status = sc_411_length_required;
		}
	    }
	  else
	    {
	      state = s_done;
	    }
	  break;

	case s_message_body:
	  if (!hh->request.message_body)
	    {
	      mbuf = malloc (hh->request.content_length);
	      if (mbuf)
		{
		  hh->request.message_body = mbuf;
		}
	      else
		{
		  hh->status = sc_500_server_internal_error;
		  state = s_dead;
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
	      state = s_done;
	    }
	  break;

	case s_done:
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
http_parser_request_line  (http_request_t * req, const char *buf)
{
  char method[HTTP_MAX_HEADER_SIZE], uri[HTTP_MAX_HEADER_SIZE],
    version[HTTP_MAX_HEADER_SIZE];

  sscanf (buf, "%s %s %s", method, uri, version);

  req->uri = make_string (uri);

  if (!strcmp (method, "GET"))
    req->method = HTTP_METHOD_GET;
  else if (!strcmp (method, "HEAD"))
    req->method = HTTP_METHOD_HEAD;
  else if (!strcmp (method, "POST"))
    req->method = HTTP_METHOD_POST;
  else
    {
      req->method = HTTP_METHOD_NOT_IMPLEMENTED;
      return sc_501_not_implemented;
    }

  if (!strcmp (version, "HTTP/1.1"))
    {
      req->version = HTTP_VERSION_1_1;
    }
  else
    {
      req->version = HTTP_VERSION_NOT_IMPLEMENTED;
      return sc_505_http_version_not_supported;
    }

  return sc_200_ok;
}

enum http_status
http_parser_header_line  (http_request_t * req, const char *buf)
{
  const char *p;
  char *cp;
  char name[HTTP_MAX_HEADER_SIZE] = "";
  char value[HTTP_MAX_HEADER_SIZE] = "";

  p = buf;
  while (*p != '\0')
    if (!IS_HEADER_CHAR (*p++))
      return sc_400_bad_request;

  sscanf (buf, "%[^:]: %s", name, value);

  if (req->num_headers < HTTP_MAX_HEADER_NUM)
    {
      req->headers[req->num_headers][HTTP_HEADER_NAME] = make_string (name);
      req->headers[req->num_headers][HTTP_HEADER_VALUE] = make_string (value);

      req->num_headers++;

      if (!strcmp (name, "CONTENT-LENGTH"))
	{
	  if (strlen (value) == 0)
	    return sc_411_length_required;

	  cp = value;
	  while (*cp != '\0')
	    if (!IS_NUM (*cp++))
	      {
		return sc_400_bad_request;
		break;
	      }
	  req->content_length = atoi (value);
	}
    }
  else
    {
      return sc_413_request_entity_too_large;
    }

  return sc_200_ok;
}

int
http_do_response (http_handle_t * hh, fifo_t * send_buf, int *pipe_fd,
		  pid_t * cgi_pid)
{
  enum http_uri_type uri_type;

  if (ERROR_STATUS (hh->status))
    return http_do_response_error (hh, send_buf);

  uri_type = check_uri_type(hh->request.uri);

  switch(uri_type) {
    case HTTP_URI_STATIC:
      return http_do_response_static (hh, send_buf);
      break;
    case HTTP_URI_DYNAMIC:
      return http_do_response_dynamic (hh, send_buf, pipe_fd, cgi_pid);
      break;
    case HTTP_URI_INVALID:
      hh->status = sc_403_forbidden;
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
    "Date: %s\r\n" "Content-length: %zd\r\n" "Content-type: %s\r\n\r\n";

  char buf[HTTP_MAX_HEADER_SIZE],
    file_path[MAXLEN], file_type[MAXLEN], date[MAXLEN], *file_data, *p;
  int file_fd;
  size_t file_size;
  struct stat sbuf;
  time_t now;
  struct tm tm;

  now = time (0);
  tm = *gmtime (&now);
  strftime (date, MAXLEN, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  if (parse_uri_static (hh, file_path))
    {
      hh->status = sc_400_bad_request;
      return http_do_response_error (hh, send_buf);
    }

  if (stat (file_path, &sbuf) < 0)
    {
      hh->status = sc_404_not_found;
      return http_do_response_error (hh, send_buf);
    }

  if (!(S_ISREG (sbuf.st_mode)) || !(S_IRUSR & sbuf.st_mode))
    {
      hh->status = sc_403_forbidden;
      return http_do_response_error (hh, send_buf);
    }

  file_size = sbuf.st_size;
  get_file_type (file_path, file_type);

  sprintf (buf, HTTP_RESPONSE_OK, date, file_size, file_type);

  if (hh->request.method == HTTP_METHOD_GET)
    {
      file_fd = open (file_path, O_RDONLY);
      file_data = mmap (0, file_size, PROT_READ, MAP_PRIVATE, file_fd, 0);
      close (file_fd);
      if (!file_data)
        {
          hh->status = sc_500_server_internal_error;
          return http_do_response_error (hh, send_buf);
        }
      p = fifo_extend (send_buf, strlen (buf) + file_size);
      if (!p)
        return -1;
      memcpy (p, buf, strlen (buf));
      memcpy (p + strlen (buf), file_data, file_size);
      munmap(file_data, file_size);
    }
  else
    {
      p = fifo_extend (send_buf, strlen (buf));
      if (!p)
        return -1;
      memcpy (p, buf, strlen (buf));
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

  static const char HTTP_RESPONSE_ERROR_BODY[] =
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">"
    "<html><head>"
    "<title>%d %s</title>" "</head><body>" "<h1>%s</h1>" "</body></html>";

  char buf[MAXLEN], buf_body[MAXLEN], date[MAXLEN], *reason;
  int code;
  size_t content_length;
  time_t now;
  struct tm tm;

  now = time (0);
  tm = *gmtime (&now);
  strftime (date, MAXLEN, "%a, %d %b %Y %H:%M:%S %Z", &tm);

  code = status_2_reason[hh->status].status_code;
  reason = status_2_reason[hh->status].reason_phase;

  sprintf (buf_body, HTTP_RESPONSE_ERROR_BODY, code, reason, reason);

  content_length = strlen (buf_body);

  sprintf (buf, HTTP_RESPONSE_ERROR, code, reason, date, content_length,
	   "text/html");
  strcat (buf, buf_body);

  if (fifo_in (send_buf, buf, strlen (buf)) < 0)
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
  char *ARGV[HTTP_CGI_MAX_ARGV];
  char *ENVP[HTTP_CGI_MAX_ENVP];
  char path_info[HTTP_CGI_ENVP_MAXLEN],
    request_uri[HTTP_CGI_ENVP_MAXLEN],
    query_string[HTTP_CGI_ENVP_MAXLEN], script_name[HTTP_CGI_ENVP_MAXLEN];

  ARGV[0] = "./cgi";

  if (parse_uri_dynamic
      (hh, path_info, request_uri, query_string, script_name))
    {
      hh->status = sc_400_bad_request;
      return http_do_response_error (hh, send_buf);
    }

  build_envp (hh, ENVP, path_info, request_uri, query_string,
		  script_name);

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

      if (chdir (hh->cgi_folder_path) < 0)
	{
	  log (hh->log, "ERROR", "chdir: %s", strerror (errno));
	  exit (EXIT_FAILURE);
	}

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

      write_ret = write (stdin_pipe[1], hh->request.message_body,
                         hh->request.content_length);
      if (write_ret < 0)
	return -1;


      close (stdin_pipe[1]);
      *pipe_fd = stdout_pipe[0];

      *cgi_pid = pid;

      return 0;
    }
  return 0;
}

void
build_envp (http_handle_t * hh, char *envp[], char *path_info,
	    char *request_uri, char *query_string, char *script_name)
{
  int index, i;
  char buf[1024], *(*headers)[2];

  index = 0;

  envp[index++] = make_string ("GATEWAY_INTERFACE=CGI/1.1");
  envp[index++] = make_string ("SERVER_PROTOCOL=HTTP/1.1");
  envp[index++] = make_string ("SERVER_SOFTWARE=Lisod/1.0");
  envp[index++] = make_string ("SERVER_NAME=Wayne Lisod");
  sprintf (buf, "PATH_INFO=%s", path_info);
  envp[index++] = make_string (buf);
  sprintf (buf, "REQUEST_URI=%s", request_uri);
  envp[index++] = make_string (buf);
  sprintf (buf, "REMOTE_ADDR=%s", hh->client_ip);
  envp[index++] = make_string (buf);
  sprintf (buf, "SERVER_PORT=%d", hh->server_port);
  envp[index++] = make_string (buf);
  sprintf (buf, "QUERY_STRING=%s", query_string);
  envp[index++] = make_string (buf);
  sprintf (buf, "SCRIPT_NAME=%s", script_name);
  envp[index++] = make_string (buf);
  sprintf (buf, "CONTENT_LENGTH=%zd", hh->request.content_length);
  envp[index++] = make_string (buf);


  switch (hh->request.method)
    {
    case HTTP_METHOD_GET:
      envp[index++] = make_string ("REQUEST_METHOD=GET");
      break;
    case HTTP_METHOD_POST:
      envp[index++] = make_string ("REQUEST_METHOD=POST");
      break;
    case HTTP_METHOD_HEAD:
      envp[index++] = make_string ("REQUEST_METHOD=HEAD");
      break;
    default:
      break;
    }

  headers = hh->request.headers;

  for (i = 0; i < hh->request.num_headers; i++)
    {
      if (!strcmp (headers[i][HTTP_HEADER_NAME], "CONTENT-TYPE"))
	{
	  sprintf (buf, "CONTENT_TYPE=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "ACCEPT"))
	{
	  sprintf (buf, "HTTP_ACCEPT=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "REFERER"))
	{
	  sprintf (buf, "HTTP_REFERER=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "ACCEPT-ENCODING"))
	{
	  sprintf (buf, "HTTP_ACCEPT_ENCODING=%s",
		   headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "ACCPET-LANGUAGE"))
	{
	  sprintf (buf, "HTTP_ACCEPT_LANGUAGE=%s",
		   headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "ACCEPT-CHARSET"))
	{
	  sprintf (buf, "HTTP_ACCEPT_CHARSET=%s",
		   headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "COOKIE"))
	{
	  sprintf (buf, "HTTP_COOKIE=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "USER-AGENT"))
	{
	  sprintf (buf, "HTTP_USER_AGENT=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "CONNECTION"))
	{
	  envp[index++] = make_string (buf);
	}
      else if (!strcmp (headers[i][HTTP_HEADER_NAME], "HOST"))
	{
	  sprintf (buf, "HTTP_HOST=%s", headers[i][HTTP_HEADER_VALUE]);
	  envp[index++] = make_string (buf);
	}
    }
}


enum http_uri_type
check_uri_type (const char *uri)
{
  if (strstr(uri, ".."))
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

  strcpy (file_path, hh->www_folder_path);

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
