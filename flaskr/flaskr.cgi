#!/usr/bin/python
from wsgiref.handlers import CGIHandler
from flaskr import app, init_db

init_db()
CGIHandler().run(app)
