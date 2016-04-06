#!/usr/bin/env python3


import os
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer
from tornado.ioloop import IOLoop
from app import app


def main():
    http_server = HTTPServer(WSGIContainer(app))
    http_server.listen(int(os.environ["PORT"]))
    IOLoop.instance().start()


if __name__ == "__main__":
    main()
