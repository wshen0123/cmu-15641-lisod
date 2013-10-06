#! /usr/bin/env python
import os,sys

env = {'CONTENT_LENGTH':'31',
'HTTP_ACCEPT':'TEXT/HTML,APPLICATION/XHTML+XML,APPLICATION/XML;Q=0.9,*/*;Q=0.8', 
'HTTP_USER_AGENT':'MOZILLA/5.0',
'HTTP_REFERER':'HTTP://127.0.0.1:8080/CGI/LOGIN', 
'SERVER_NAME':'Wayne Lisod',
'GATEWAY_INTERFACE':'CGI/1.1',
'CONTENT_TYPE':'application/x-www-form-urlencoded',
'REMOTE_ADDR':'127.0.0.1',
'SERVER_SOFTWARE':'Lisod/1.0',
'SCRIPT_NAME':'/cgi',
'REQUEST_METHOD':'POST',
'HTTP_HOST':'127.0.0.1:8080',
'PATH_INFO': '/login',
'SERVER_PORT': '8080',
'SERVER_PROTOCOL': 'HTTP/1.1',
'QUERY_STRING': '',
'HTTP_ACCEPT_ENCODING': 'GZIP,',
'REQUEST_URI': '/cgi/login'}



if __name__ == '__main__':
    r, w = os.pipe()
    os.dup2(r, 0)

    pid = os.fork()
    if pid:
        txt = os.write(w, 'username=admin&password=default')
        os.waitpid(pid, 0)
    else:
        args = ('./flaskr.cgi', )
        os.execve(args[0], args, env) 
