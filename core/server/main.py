import logging
import socket
import threading
import time

from core.client.main import Client
from core.proxy import Proxy
from core.server.command import RecvCommand
from core.server.scan import Scan
from core.tools import Status, PermissionEnum, HashTools

"""
客户端实例管理
client_mark : {
        'ip': ip,
        'id': remote_id,
        'client': client,
        'command_socket': client_command_socket,
        'permission': PermissionEnum.USER.value,
        'control': control,
        'AES_KEY': aes_key
    }
"""
socket_manage: dict = {}


class Manage:
    """
    对socket_manager的管理
    """

    @staticmethod
    def getAllConnectedDev() -> dict:
        """
        列出所有已经连接并验证成功的设备
        :return:
        """
        return socket_manage

    @staticmethod
    def getDevInfo(attr: str) -> str:
        """
        通过某一个设备的属性找到对应的信息内容
        :param attr: 属性
        :return: 设备信息对象
        """
        for dev in socket_manage:
            for info in dev:
                return info.get(attr)

    @staticmethod
    def delDevInfo(client_mark: str) -> bool:
        """
        param client_mark: 客户端mark值
        :return:
        """
        if socket_manage.pop(client_mark):
            return True
        return False


class Server(Scan, Manage, Proxy):
    """
    创建命令收发和数据收发套接字

    过程：
    1.首先服务端会设置代理（适用于数据、指令、监听Socket）。
    2.指令Socket等待客户端指令Socket连接，如果客户端的ip在白名单中，则连接成功，并进入等待循环。
    3.当指令Socket连接成功并通过验证后，数据Socket才能够进行连接。
    4.循环等待客户端指令。
    """

    def __init__(self):
        super().__init__()
        logging.debug('Starting core services...')

        """
        Socket套接字连接成功实例存储
        address : {
            command: command_socket 
            data: data_socket
        }
        """
        self.merge_socket: dict = {}

        """
        获取当前代理状态并判断是否启用Socks5代理
        """
        if self.config['server']['proxy'].get('enabled'):
            socket.socket = self.setProxyServer(self.config)

        logging.info(
            f'EXSync runs on {self.local_ip}:{self.data_port}(data) and {self.local_ip}:{self.data_port + 1}(command)')

    def createSocket(self, port: int, verifyFunc):
        """
        创建套接字对象
        :param port: 端口号
        :param verifyFunc: 目标验证套接字
        :return:
        """
        tcp = socket.socket(self.socket_family, socket.SOCK_STREAM)
        tcp.bind((self.local_ip, port))
        tcp.listen(128)
        tcp.settimeout(4)

        while True:
            # 等待客户端连接服务端
            sub_socket, addr = tcp.accept()
            thread = threading.Thread(target=verifyFunc, args=(sub_socket, addr))
            thread.start()

    def verifyDataSocket(self, data_socket: socket, address: str):
        """
        验证数据套接字，确保连接对象是否已经通过验证
        :param data_socket: 数据套接字
        :param address: 客户端地址
        :return:
        """
        logging.debug(f'Starting to verify data socket connection from {address}...')
        if address[0] in self.verify_manage and self.verify_manage[address[0]]['AES_KEY']:
            data_socket.permission = PermissionEnum.USER
        else:
            try:
                data_socket.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                print(e)
                logging.debug(e)
            data_socket.close()
        # 如果指令套接字存在则添加
        if address[0] in self.verified_devices:
            self.merge_socket[address[0]]["data"] = data_socket
        else:
            self.merge_socket[address[0]] = {
                "command": None,
                "data": data_socket
            }

    def verifyCommandSocket(self, command_socket: socket, address: str):
        """
        验证指令套接字，验证连接对象是否已经通过验证
        主动验证：当对方客户端主动连接，但本机并未扫描验证对方，就会触发此模式。
        被动验证：当本机已经扫描验证对方连接，当对方再次连接时就会按白名单内容予以通过验证。
        :param command_socket: 指令套接字
        :param address: 目标客户端IP地址
        :return:
        """
        logging.debug(f'Starting to verify command socket connection from {address}...')
        if address[0] in self.verify_manage and self.verify_manage[address[0]]['AES_KEY']:
            # 开始主动验证
            command_socket.permission = PermissionEnum.USER
        else:
            # 被动验证
            command_socket.permission = PermissionEnum.GUEST
        if address[0] in self.verified_devices:
            self.merge_socket[address[0]]['command'] = command_socket
        else:
            self.merge_socket[address[0]] = {
                "command": command_socket,
                "data": None
            }

    def mergeSocket(self):
        """
        当远程客户端同时连接上data_socket和command_socket后开始指令与数据的收发
        :return:
        """
        while True:
            index = 0
            for key, value in self.merge_socket.items():
                if value['command'] and value['data']:
                    command_socket, data_socket = self.merge_socket.pop(index)
                    command = RecvCommand(command_socket, data_socket, Manage.getDevInfo('AES_KEY'))
                    thread = threading.Thread(target=command.recvCommand)
                    thread.start()
                    index += 1
            time.sleep(0.05)

    def createClientCommandSocket(self, ip: str):
        """
        本地客户端主动连接远程服务端
        :param ip: 目标EXSync指令套接字地址
        :return:
        """
        client_mark = HashTools.getRandomStr(8)
        aes_key = self.verify_manage[ip].get('AES_KEY')
        remote_id = self.verify_manage[ip].get('REMOTE_ID')

        client = Client(ip, self.data_port)
        client_info = {
            'client_mark': client_mark,
            'ip': ip,
            'id': None,
            'AES_KEY': aes_key
        }
        client.host_info(client_info)
        client_command_socket = client.createCommandSocket()

        if not client.connectRemoteCommandSocket():  # 连接指令Socket
            logging.error(f'Client: {client_mark}, server: {ip} connection failure!')
            return

        client_data_socket = client.createClientDataSocket()  # 连接数据Socket
        if client_data_socket == Status.CONNECT_TIMEOUT:
            client.closeAllSocket()  # 连接超时, 关闭客户端连接
            return
        elif client_data_socket == Status.SESSION_FALSE:
            client.closeAllSocket()  # 会话验证失败, 关闭客户端连接
            return
        elif client_command_socket.permission >= PermissionEnum.USER.value:
            # 连接成功

            control = client.createCommand()  # 初始化指令控制对象

            socket_manage[client_mark] = {
                'ip': ip,
                'id': remote_id,
                'client': client,
                'command_socket': client_command_socket,
                'permission': PermissionEnum.USER.value,
                'control': control,
                'AES_KEY': aes_key
            }

            return socket_manage[client_mark]

    def updateIplist(self):
        """
        持续更新设备列表, 并主动连接已验证的设备
        :return:
        """
        while True:
            ip_list = self.scanStart()
            devices = self.testDevice(ip_list)
            logging.debug(f'Devices list update: {devices}')
            for ip in devices:
                if ip not in self.verified_devices:
                    thread = threading.Thread(target=self.createClientCommandSocket, args=(ip,))
                    thread.start()
                    self.verified_devices.add(ip)
            time.sleep(15)


if __name__ == '__main__':
    # s = createSocket()
    # s.createCommandSocket()
    # s.createDataSocket()
    # s = Scan()
    # print(s.start())
    pass
