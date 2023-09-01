from server.client import CommandSend
from server.core import createSocket, socket_manage
from server.shell import *
from server.tools.tools import relToAbs

global_vars = {}


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


class Control(Init):
    def __init__(self, ip):
        super().__init__()
        self.ip = ip

    def postFile(self, path, mode=1):
        client_example = socket_manage[self.ip]  # ip映射为唯一的客户端实例
        data_socket = client_example.client_data_socket  # data Socket
        command_socket = client_example.client_socket  # command Socket
        command_send = CommandSend(data_socket, command_socket)
        path = relToAbs(path)
        command_send.post_File(path, mode)

    def getFile(self, path):
        client_example = socket_manage[self.ip]  # ip映射为唯一的客户端实例
        data_socket = client_example.client_data_socket  # data Socket
        command_socket = client_example.client_socket  # command Socket
        command_send = CommandSend(data_socket, command_socket)
        path = relToAbs(path)
        command_send.get_File(path)


if __name__ == '__main__':
    init = Init()
    init.run()
