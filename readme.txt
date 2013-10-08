$ make          compile with O3 optimization and minimal log
  
$ make DEBUG=1  compile without daemonization and log to stderr

Modules:
Lisod - the main select engine that maintains server connection and client pool.
	1. Accept client, initialize client resources and add client to select pool
	2. Wait for client I/O events:
		@ on_read_sock:
    read data off client socket and queue data into client.recv_buf.
		
    @ on_read_pipe:
    if the client has forked a CGI process, reads CGI response into
    client.pipe_buf. If the CGI process terminates, removes the pipe
    from select by on_cgi_job_done.

		@ on_write:
    write data to client.

		@ on_http_execute:
    feed request from recv_buf to the http module. The http module
    only parse up to a single request at a time. So keep the remaining
    request data in recv_buf.
		
Http - contains a stream parser that reads up to a full request or if not,
whatever it is given and maintain http request state across recv call boundary.
It also contains a http response engine. 

Log - the module for logging.
Fifo - the data structure that maintains fifo buffer for network/pipe read/write.

Note:

1. The client may shutdown its write but still receives response from server,
so I added a flag (bool shut_down) for each client. When lisod detects client
shutdown or http parser says it sends bad request, lisod stops reading from
that socket, tries to flushes all remaining/pending(from CGI process) response
to it.

2. The CGI process only generate Status header that for lisod it has to translate
Status header to http response line.

3. For dealing with pipelined request, I designed http module only to read up to
one request and serve with static content immediately or fork a CGI process and
add a lock (has_cgi_job_undone) to ensure that no further request is processed
before this one has finished. Although such design would possibly, though very
unusual, slow pipelined dynamic content request (with multiple CGI process fired
at the same time), but since CGI program’s output could very slow, and any later
request must wait to ensure proper ordering of responses, such lock would not
cause serious degradation.

4. In case of server failure like malloc error or other critical situation, lisod
use an internal static buffer to store predefined HTTP/500 server internal error
response.

5. In case of bad url like ones containing "..", lisod would generate bad request
response.
