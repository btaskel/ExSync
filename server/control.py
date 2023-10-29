import logging
import os
import threading

from server.client import CommandSend
from server.core import createSocket, socket_manage
from server.tools.tools import relToAbs

global_vars = {}


class Init:
    """EXSync初始化"""

    def __init__(self):
        # 初始化服务端/客户端
        server = createSocket()
        socket_ls = [server.createDataSocket, server.createCommandSocket]
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
    def _idToIp(device_id: str):
        """
        :param device_id:
        :return device_ip:
        """
        return socket_manage[device_id]['ip']

    @staticmethod
    def _get_command_send(device_ip: str):
        if device_ip in socket_manage:
            client_example = socket_manage[device_ip]  # ip映射为唯一的客户端实例
            data_socket = client_example['data_socket']  # data Socket
            command_socket = client_example['command_socket']  # command Socket
            return CommandSend(data_socket, command_socket)
        else:
            return False

    @staticmethod
    def getAllDevice():
        """
        :return 返回所有设备id:
        """
        ipList = []
        for value in socket_manage.values():
            ipList.append(value['ip'])
        return ipList

    @staticmethod
    def postFile(device_id: str, path: str, mode: int = 1):
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
    def getFile(device_id: str, path: str, output_path: str = None):
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
    def postFolder(device_id: str, path: str):
        """
        创建远程文件夹路径
        :param device_id:
        :param path:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        command_send.post_Folder(relToAbs(path))

    @staticmethod
    def getFolder(device_id: str, path: str):
        """
        遍历远程path路径下的所有文件夹路径并返回
        :param device_id:
        :param path:
        :return paths:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        command_send.get_Folder(relToAbs(path))

    @staticmethod
    def getIndex(device_id: str, spacename: str):
        """
        获取指定设备的同步目录的索引文件
        :param device_id:
        :param spacename:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.get_Index(spacename)

    @staticmethod
    def postIndex(device_id: str, spacename: str, json_object, is_file: bool = True):
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
    def sendCommand(device_id: str, command: str):
        """
        客户端向指定设备id发送指令
        如果当前设备没有权限操作对方系统级指令则只能执行EXSync指令
        如果当前设备有权限操作对方系统级指令则执行返回 CommandSet.EXSYNC_INSUFFICIENT_PERMISSION
        如果当前设备发送指令后对方设备长时间未答复则返回 Status.DATA_RECEIVE_TIMEOUT
        如果当前设备发送指令后对方答复的内容格式不正确则返回 CommandSet.FORMAT_ERROR
        :param device_id:
        :param command:
        :return:
        """
        command_send = Control._get_command_send(Control._idToIp(device_id))
        return command_send.send_Command(command)


class Plugin:
    """插件初始化载入"""

    def __init__(self, path: str):
        self.path = path

    def read_plugins(self):
        for file in os.listdir('plugins'):
            file_path = os.path.join(self.path, file)
            if os.path.isdir(file_path):
                self.load(file_path, method=0)
                logging.info(f'Plugin {file} loaded successfully.')
            elif os.path.isfile(file_path):
                self.load(file_path, method=1)
                logging.info(f'Plugin {file} loaded successfully.')
            else:
                # 读取插件失败
                logging.error(f'Plugin read failed!: {file}')
                continue

    def load(self, path: str, method: int):
        """
        method = 0;
        按文件加载插件
        method = 1;
        按文件夹加载插件

        :param path:
        :param method:
        :return:
        """
        file_path = os.path.join(self.path, path)


if __name__ == '__main__':
    pass
