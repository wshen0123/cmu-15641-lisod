#! /usr/bin/env python
import os

requests = [
"GET / HTTP/1.1\r\nConnection: Keep-alive\r\n\r\n",
"HEAD / HTTP/1.1\r\nConnection: Keep-alive\r\n\r\n",
"POST /cgi/ HTTP/1.1\r\nContent-Length: 5\r\n\r\n12345"]

for i in range(0, len(requests)):
    os.write(1, requests[i])

