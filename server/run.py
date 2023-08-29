from server.core import createSocket
from server.shell import *


def run():
    """
    服务启动后返回Core(多个socket)实例
    """
    initLogging(logging.DEBUG)

    server = createSocket()
    server.createDataSocket()
    server.createCommandSocket()
    server.createVerifySocket()


if __name__ == '__main__':
    run()
