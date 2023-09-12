import threading

from server.client import CommandSend
from server.core import createSocket, socket_manage, socket_manage_id
from server.shell import *
from server.tools.tools import relToAbs

global_vars = {}


class Init:
    """EXSync初始化"""

    def __init__(self):
        self.run()

    @staticmethod
    def run():
        initLogging(logging.DEBUG)

        # 初始化服务端/客户端
        server = createSocket()
        socket_ls = [server.createDataSocket, server.createCommandSocket, server.createVerifySocket]
        for thread in socket_ls:
            thread = threading.Thread(target=thread)
            thread.start()


class Control(Init):
    """
    本地客户端与远程服务端操作接口
    """

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
    def getFile(device_id, path, output_path=None):
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        :param output_path:
        :param device_id:
        :param path:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.get_File(relToAbs(path), output_path)

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
    def getIndex(device_id, spacename):
        """
        获取指定设备的同步目录的索引文件
        :param device_id:
        :param spacename:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.get_Index(spacename)

    @staticmethod
    def postIndex(device_id, spacename, json_object, is_file=True):
        """
        接收同步空间名，将dict_example更新到远程索引中
        :param is_file:
        :param device_id:
        :param spacename:
        :param json_object:
        :return:

        "H:\\Python project\\Sync\\test\\space\\\u795e\u91cc\u51cc\u534e-adjust.jpg": {
            "type": "file",
            xxxx......

        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.post_Index(spacename, json_object, is_file)

    @staticmethod
    def sendCommand(device_id, command):
        """
        客户端向指定设备id发送指令
        如果当前设备没有权限操作对方系统级指令则只能执行EXSync指令(成功返回True, 否则为False)
        如果当前设备有权限操作对方系统级指令则执行返回信息，否则返回False
        :param device_id:
        :param command:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.send_Command(command)


if __name__ == '__main__':
    pass
