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
    """操作接口"""

    def __init__(self):
        super().__init__()

    @staticmethod
    def _get_command_send(ip):
        client_example = socket_manage[ip]  # ip映射为唯一的客户端实例
        data_socket = client_example.client_data_socket  # data Socket
        command_socket = client_example.client_socket  # command Socket
        return CommandSend(data_socket, command_socket)

    @staticmethod
    def postFile(ip, path, mode=1):
        """
        输入文件路径，发送文件至服务端
        data_socket: 与服务端连接的socket
        path: 文件绝对路径

        mode = 0;
        如果不存在文件，则创建文件，返回True。否则不执行操作，返回False。

        mode = 1;
        如果不存在文件，则创建文件，返回True。否则重写文件，返回False。

        mode = 2;
        如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件，返回True。否则停止发送返回False。
        :param ip:
        :param path:
        :param mode:
        :return:
        """
        command_send = Control._get_command_send(ip)
        return command_send.post_File(relToAbs(path), mode)

    @staticmethod
    def getFile(ip, path):
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        :param ip:
        :param path:
        :return:
        """
        command_send = Control._get_command_send(ip)
        return command_send.get_File(relToAbs(path))

    @staticmethod
    def postFolder(ip, path):
        command_send = Control._get_command_send(ip)
        command_send.post_Folder(relToAbs(path))

    @staticmethod
    def getFolder(ip, path):
        command_send = Control._get_command_send(ip)
        command_send.get_Folder(relToAbs(path))


if __name__ == '__main__':
    pass
