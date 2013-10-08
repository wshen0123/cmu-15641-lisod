#ifndef __HTTP_PARSER_H__
#define __HTTP_PARSER_H__
#include "RFC2616.h"
#include "fifo.h"
#include "log.h"

#include <sys/types.h>
#include <stdbool.h>

#define HTTP_HEADER_MAXLEN 8192

enum http_connection_state
{
  HCS_CONNECTION_ALIVE,                 /* either unfinished or made Keep-alive */

#define HTTP_CONNECTION_WILL_CLOST(state) state >= HCS_CONNECTION_CLOSE
  /* please note these state will only lead to flush close, not immediate close */
  HCS_CONNECTION_CLOSE_FINISHED,        /* Connection: Keep-alive not specified */
  HCS_CONNECTION_CLOSE_BAD_REQUEST,     /* request error */
  HCS_CONNECTION_CLOSE_INTERNAL_ERROR,  /* server internal error */
};

/* forward state(next anticipated state) */
enum http_parser_state
{
  S_START = 0,

  S_REQUEST_LINE,
  S_REQUEST_LINE_LF,

  S_HEADER_LINE,
  S_HEADER_LINE_LF,
  S_HEADERS_LF,
#define PARSING_HEADER(STATE) (STATE <= S_HEADERS_LF)

  S_MESSAGE_BODY,
#define PARSING_INCOMPLETE(STATE) (STATE < S_DONE)
  S_DONE,

  S_DEAD,
  S_LAST,
};

enum http_status
{
  SC_UNKNOWN = -1,

  SC_200_OK = 0,

  SC_302_FOUND,
  SC_304_NOT_MODIFIED,

#define ERROR_STATUS(STATUS) (STATUS > SC_200_OK)
  SC_400_BAD_REQUEST,
  SC_403_FORBIDDEN,
  SC_404_NOT_FOUND,
  SC_405_METHOD_NOT_ALLOWED,
  SC_411_LENGTH_REQUIRED,
  SC_413_REQUEST_ENTITY_TOO_LARGE,
  SC_414_REQUEST_URI_TOO_LONG,

  SC_500_SERVER_INTERNAL_ERROR,
  SC_501_NOT_IMPLEMENTED,
  SC_503_SERVICE_UNAVAILABLE,
  SC_505_HTTP_VERSION_NOT_SUPPORTED,

  SC_LAST,
};

enum http_method
{
  HM_UNKNOWN = -1,

  HM_NOT_IMPLEMENTED = 0,
  HM_GET,
  HM_HEAD,
  HM_POST,

  HM_LAST,
};
#define HAS_BODY(method) (method == HM_POST)

enum http_version
{
  HV_UNKNOWN = -1,

  HV_NOT_IMPLEMENTED = 0,
  HV_10,
  HV_11,
};

/* http_parser: stream parser FSM holder,
 * only called by http_parser_execute/reset */
typedef struct
{
  enum http_parser_state state;

  size_t header_len;
  size_t body_len;

  char buf[HTTP_HEADER_MAXLEN];	/* used to hold uri/port/path/query string */
  size_t buf_index;

} http_parser_t;

/* http_reques_t: filled by parser_execute
 * and accessed by http_do_response, contain
 * info necessary to contruct response */
typedef struct
{
  enum http_method method;
  char *uri;
  enum http_version version;

#define HTTP_HEADER_NAME 0
#define HTTP_HEADER_VALUE 1
  char *headers[HTTP_MAX_HEADER_NUM][2];
  size_t num_header;

  bool keep_alive;

  char *message_body;
  ssize_t content_length;
} http_request_t;

/* http_handle_t: this is the handle hold by lisod
 * but none of the members shall be accessed public
 * they are self contained and only used by http
 * module functtions */
typedef struct
{
  /* setup var ( shallow copy: don't free them! ) */
  const char *www_folder;
  const char *cgi_path;
  const char *client_ip;
  unsigned short client_port;
  unsigned short server_port;
  log_t *log;

  /* handle */
  http_parser_t parser;
  http_request_t request;
  enum http_status status;

} http_handle_t;

/* http_setting_t: struct to pass http setting to
 * http handler */
typedef struct
{
  const char *www_folder;
  const char *cgi_path;

  const char *client_ip;
  unsigned short client_port;
  unsigned short server_port;

  log_t *log;
} http_setting_t;

http_handle_t *
http_handle_init (http_setting_t * setting);

enum http_connection_state
http_handle_execute (http_handle_t * hh,
                      fifo_t * recv_buf,
                      fifo_t * send_buf,
                      int *pipe_fd,
                      pid_t * cgi_pid);
void
http_handle_free (http_handle_t * hh);

void
http_cgi_finish_callback (fifo_t * send_buf, fifo_t * pipe_buf);

#endif
