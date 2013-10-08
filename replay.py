#! /usr/bin/env python
import os

requests = [
"GET / HTTP/1.1\r\nConnection: Keep-alive\r\n\r\n",
"HEAD / HTTP/1.1\r\nConnection: Keep-alive\r\n\r\n",
"POST / HTTP/1.1\r\nConnection: Keep-alive\r\nContent-Length: 5\r\n\r\n12345",
#"GET /cgi/ HTTP/1.1\r\nConnection:Keep-alive\r\n\r\n",
"GET / HTTP/1.1\r\n" + "1" * 100000]

for i in range(0, len(requests)):
    os.write(1, requests[i])

