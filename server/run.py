from server.client import CommandSend
from server.core import createSocket, socket_manage, socket_manage_id
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
    def _idToIp(device_id):
        """
        :param device_id:
        :return device_ip:
        """
        return socket_manage_id[device_id].getpeername()[0]

    @staticmethod
    def _get_command_send(device_id):
        client_example = socket_manage[Control._idToIp(device_id)]  # ip映射为唯一的客户端实例
        data_socket = client_example.client_data_socket  # data Socket
        command_socket = client_example.client_socket  # command Socket
        return CommandSend(data_socket, command_socket)

    @staticmethod
    def getAllDevice():
        """
        :return 返回所有设备id:
        """
        return list(socket_manage_id.keys())

    @staticmethod
    def postFile(device_id, path, mode=1):
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
        :param device_id:
        :param path:
        :param mode:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.post_File(relToAbs(path), mode)

    @staticmethod
    def getFile(device_id, path):
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        :param device_id:
        :param path:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.get_File(relToAbs(path))

    @staticmethod
    def postFolder(device_id, path):
        """
        创建远程文件夹路径
        :param device_id:
        :param path:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        command_send.post_Folder(relToAbs(path))

    @staticmethod
    def getFolder(device_id, path):
        """
        遍历远程path路径下的所有文件夹路径并返回
        :param device_id:
        :param path:
        :return paths:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        command_send.get_Folder(relToAbs(path))

    @staticmethod
    def getIndex(device_id):
        command_send = Control._get_command_send(Control._idToIp(device_id))
        command_send.get_Folder()


if __name__ == '__main__':
    pass
