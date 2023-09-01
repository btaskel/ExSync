from server.core import createSocket, socket_manage
from server.shell import *


class Init:
    def __init__(self):
        self.server = None
        self.run()

    def run(self):
        """
        服务启动后返回Core(多个socket)实例
        """
        initLogging(logging.DEBUG)

        # 初始化服务端/客户端
        server = createSocket()
        server.createDataSocket()
        server.createCommandSocket()
        server.createVerifySocket()
        self.server = server

    def clientHandle(self, ip):
        client_example = socket_manage[ip] # ip映射为唯一的客户端实例
        data_socket = client_example.client_data_socket # data Socket
        command_socket = client_example.client_socket # command Socket


if __name__ == '__main__':
    init = Init()
    init.run()
