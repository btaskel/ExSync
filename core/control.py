import importlib
import logging
import os
import sys
import threading

from core.client.command import CommandSend
from core.option import readConfig
from core.server.main import Server, socket_manage


class Control(readConfig):
    """
    本地客户端与远程服务端操作接口
    """

    def __init__(self):
        super().__init__()
        self.config = self.readJson()
        self.userdata: dict = {}
        for space in self.config['userdata']:
            self.userdata[space['spacename']] = space

    def getAllDevice(self) -> list:
        """
        :return 返回所有设备id:
        """
        ipList = []
        for value in socket_manage.values():
            ipList.append(value['ip'])
        return ipList

    @staticmethod
    def getDevice(device_id: str) -> CommandSend | None:
        """
        根据设备id获取对应的设备控制客户端
        :param device_id:
        :return:
        """
        device = socket_manage.get(device_id)
        if device:
            command_send = device.get('control')
            return command_send
        return None

    def getSpace(self, spacename: str) -> dict:
        """
        根据同步空间名称获取同步空间的实例对象
        :param spacename:
        :return:
        """
        for space in self.config['userdata']:
            if space['spacename'] == spacename:
                return space
        return {}

    def _commonpath(self, file_path: str) -> dict:
        """
        当前绝对路径是否匹配到本地保存的同步空间
        :param file_path:
        :return:
        """
        for space in self.config['userdata']:
            if not os.path.isabs(space['path']):
                space_path = os.path.abspath(space['path'])
                if space_path == os.path.commonpath([space_path, file_path]):
                    return space
        return {}

    def postFile(self, device_id: str, spacename: str, path: str, file_status: dict, mode: int = 1) -> str:
        """
        输入文件路径，发送文件至服务端
        path: 文件相对路径

        mode = 0;
        如果不存在文件，则创建文件，返 回True。否则不执行操作，返回False。

        mode = 1;
        如果不存在文件，则创建文件，返回True。否则重写文件，返回False。

        mode = 2;
        如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件，返回True。否则停止发送返回False。
        :param file_status: 文件状态信息 { filehash:..... }
        :param spacename: 同步空间id
        :param device_id: 设备id
        :param path: 文件相对路径
        :param mode: 操作模式
        :return: 执行状态
        """
        command_send = self.getDevice(device_id)
        space = self.userdata.get(spacename)
        if not space:
            logging.error(f'postFile: No synchronization space {spacename} found!')
            return 'NotSpace'
        if not command_send:
            logging.error(f'postFile: No synchronization device {device_id} found!')
            return 'NotDevice'

        return command_send.postFile(relative_path=path, file_status=file_status, mode=mode, space=space)

    def getFile(self, device_id: str, path: str, output_path: str = None):
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        :param output_path:
        :param device_id:
        :param path:
        :return:
        """
        command_send = self.getDevice(device_id)
        return command_send.getFile(relToAbs(path), output_path) if command_send else None

    def postFolder(self, device_id: str, path: str):
        """
        创建远程文件夹路径
        :param device_id:
        :param path:
        :return:
        """
        command_send = self.getDevice(device_id)
        return command_send.postFolder(relToAbs(path)) if command_send else None

    def getFolder(self, device_id: str, path: str):
        """
        遍历远程path路径下的所有文件夹路径并返回
        :param device_id:
        :param path:
        :return paths:
        """
        command_send = self.getDevice(device_id)
        return command_send.getFolder(relToAbs(path)) if command_send else None

    def getIndex(self, device_id: str, spacename: str):
        """
        获取指定设备的同步目录的索引文件
        :param device_id:
        :param spacename:
        :return:
        """
        command_send = self.getDevice(device_id)
        return command_send.getIndex(spacename) if command_send else None

    def postIndex(self, device_id: str, spacename: str, json_object: dict, is_file: bool = True):
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
        command_send = self.getDevice(device_id)
        return command_send.postIndex(spacename, json_object, is_file) if command_send else None

    def sendCommand(self, device_id: str, command: str):
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
        command_send = self.getDevice(device_id)
        return command_send.send_Command(command) if command_send else None


class Plugin:
    """插件初始化载入"""

    def __init__(self):
        self.__plugins = os.path.join(os.getcwd(), 'data', 'plugins')

    def read_plugins(self):
        for file in os.listdir(self.__plugins):
            file_path = os.path.join(self.__plugins, file)

            if not os.path.exists(file_path):
                logging.error(f'Plugin {file} path does not exist!')
                continue

            elif os.path.isdir(file_path):
                # 按文件夹加载
                if self.load(file_path, method=1):
                    logging.info(f'Plugin {file} loaded successfully.')
                else:
                    logging.error(f'Plugin read failed!: {file}')

            elif os.path.isfile(file_path) and file.endswith('.py'):
                # 按文件加载
                if self.load(file_path, method=0):
                    logging.info(f'Plugin {file} loaded successfully.')
                else:
                    logging.error(f'Plugin read failed!: {file}')

            else:
                # 读取插件失败, 未知的文件类型
                logging.error(f'Plugin read failed!: {file}')
                continue

    @staticmethod
    def load(path: str, method: int) -> bool:
        """
        method = 0;
        按文件加载插件
        method = 1;
        按文件夹加载插件

        :param path:
        :param method:
        :return:
        """

        if method == 0:
            try:
                filename = os.path.basename(path).split('.')[0]
                sys.path.append(os.path.dirname(path))
                module = importlib.import_module(filename)
            except ImportError as e:
                print(e)
                return False
            try:
                result = module.main()
            except AttributeError as e:
                print(e)
                return False
            logging.info(f'Plugin X loaded: {result}')
            return True

        elif method == 1:
            folder_name = os.path.basename(path)
            sys.path.append(path)
            try:
                module = importlib.import_module(f'{folder_name}.main')
            except ImportError as e:
                print(e)
                return False
            try:
                result = module.main()
            except AttributeError as e:
                print(e)
                return False
            logging.info(f'Plugin X loaded: {result}')
            return True
        raise ValueError(f'{path}, method: {method}未知的插件导入方式！')


class RunServer(Control, Plugin):
    """
    EXSync初始化
    """

    def __init__(self):
        # 初始化服务端/客户端
        super().__init__()
        logging.debug('Initializing core control service...')
        server = Server()

        """
        持续合并指令与数据传输套接字
        """
        funcs: list = [server.mergeSocket, server.updateIplist]
        for func in funcs:
            thread = threading.Thread(target=func)
            thread.start()

        """
        创建Command / Data Socket
        """
        socket_types: dict = {
            server.command_port: server.verifyCommandSocket,
            server.data_port: server.verifyDataSocket
        }
        for port, verify_func in socket_types.items():
            thread = threading.Thread(target=server.createSocket, args=(port, verify_func))
            thread.start()


if __name__ == '__main__':
    RunServer()
