import logging

from server.core import createSocket
from server.shell import *


def run():
    initLogging(logging.DEBUG)

    server = createSocket()
    server.createDataSocket()
    server.createCommandSocket()
    server.createVerifySocket()


if __name__ == '__main__':
    run()
