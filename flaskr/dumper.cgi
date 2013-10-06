#! /usr/bin/env python
import sys
from os import environ

res_body = ''
req_body_len = 0

for key in environ:
    value = environ[key]
    res_body =  res_body + '\n' + str(key) + ":" + str(value)
    if key == 'CONTENT_LENGTH':
      req_body_len = int(value)

res_body = res_body + '\nstdin:"' + sys.stdin.read(req_body_len) + '"'

print 'Status: 200 OK\r'
print 'Content-Length: %d\r' % len(res_body)

print res_body
