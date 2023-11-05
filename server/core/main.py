import logging
import socket
import threading
import time

import socks
import xxhash

from server.client.command import CommandSend as Client
from server.core.command import RecvCommand
from server.core.scan import Scan
from server.tools.status import Status, PermissionEnum
from server.tools.tools import HashTools

"""
客户端实例管理
"""
socket_manage = {}


class createSocket(Scan):
    """
    创建命令收发和数据收发套接字

    过程：
    1.首先服务端会设置代理（适用于数据、指令、监听Socket）。
    2.监听Socket等待客户端指令Socket连接，验证成功的客户端ip会增加进白名单列表，如果验证成功开始第三步。
    3.指令Socket等待客户端指令Socket连接，如果客户端的ip在白名单中，则连接成功，并进入等待循环。
    4.数据Socket等待客户端数据Socket连接，如果客户端的ip在白名单中，则连接成功，终止指令Socket的等待循环。
    5.循环等待客户端指令。
    """

    def __init__(self):
        super().__init__()
        # Socks5代理设置
        self.host_id = self.config['server']['addr']['id']
        self.devices = None
        self.client_connected = set()
        if self.config['server']['proxy']['enabled']:
            proxy_host, proxy_port = self.config['server']['proxy']['hostname'], self.config['server']['proxy']['port']
            socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
            # 替换socket
            socket.socket = socks.socksocket

        self.local_password_hash = xxhash.xxh3_128(self.config['server']['addr']['password']).hexdigest()

        """
        当前与客户端建立连接的ip
        """
        self.connected = set()

        """
        Socket套接字连接成功实例存储
        address : {
            command: command_socket 
            data: data_socket
        }
        """
        self.socket_info = {}

        # 已验证标识的计算机
        self.whitelist = set()

        # 持续合并指令与数据传输套接字
        funcs = [self.mergeSocket, self.updateIplist]
        for func in funcs:
            thread = threading.Thread(target=func)
            thread.start()

    def createDataSocket(self):
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.bind((self.config["server"]["addr"]["ip"], int(self.config["server"]["addr"]["port"])))
        data_socket.listen(128)

        while True:
            # 等待客户端连接服务端
            sub_socket, addr = data_socket.accept()
            thread = threading.Thread(target=self.verifyDataSocket, args=(sub_socket, addr))
            thread.start()

    def verifyDataSocket(self, data_socket, address):
        """
        验证数据套接字；
        验证连接对象是否已经通过验证
        :return:
        """
        if address[0] in self.verify_manage and self.verify_manage[address[0]]['AES_KEY']:
            data_socket.permission = PermissionEnum.USER
        else:
            data_socket.permission = PermissionEnum.GUEST
        # 如果指令套接字存在则添加
        if address[0] in self.socket_info:
            self.socket_info[address[0]]["data"] = data_socket
        else:
            self.socket_info[address[0]] = {
                "command": None,
                "data": data_socket
            }

    def createCommandSocket(self):
        """创建指令传输套接字"""
        command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        command_socket.bind((self.config['server']['addr']['ip'], self.command_port))
        command_socket.listen(128)
        while True:
            sub_socket, addr = command_socket.accept()
            thread = threading.Thread(target=self.verifyCommandSocket, args=(sub_socket, addr))
            thread.start()

    def verifyCommandSocket(self, command_socket, address):
        """
        验证指令套接字，验证连接对象是否已经通过验证
        主动验证：当对方客户端主动连接，但本机并未扫描验证对方，就会触发此模式。
        被动验证：当本机已经扫描验证对方连接，当对方再次连接时就会按白名单内容予以通过验证。
        """
        if address[0] in self.verify_manage and self.verify_manage[address[0]]['AES_KEY']:
            # 被动验证
            command_socket.permission = PermissionEnum.USER
        else:
            # 开始主动验证
            command_socket.permission = PermissionEnum.GUEST
        command_socket.send('')
        if address[0] in self.socket_info:
            self.socket_info[address[0]]['command'] = command_socket
        else:
            self.socket_info[address[0]] = {
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
            for key, value in self.socket_info.items():
                if value['command'] and value['data']:
                    command_socket, data_socket = self.socket_info.pop(index)
                    command = RecvCommand(command_socket, data_socket)
                    thread = threading.Thread(target=command.recvCommand)
                    thread.start()
                    index += 1
            time.sleep(0.05)

    def createClientCommandSocket(self, ip: str):
        """
        本地客户端主动连接远程服务端
        """
        client_mark = HashTools.getRandomStr(8)
        aes_key = self.verify_manage[ip].get('aes_key', None)

        client = Client(ip, self.data_port)
        client_info = {
            'client_mark': client_mark,
            'ip': ip,
            'id': self.host_id,
            'AES_KEY': aes_key
        }
        client.host_info(client_info)
        client_command = client.createCommandSocket()

        match client.connectRemoteCommandSocket():  # 连接指令Socket
            case Status.CONNECTED:
                # 连接成功
                pass
            case Status.CONNECT_TIMEOUT:
                if client.closeAllSocket():
                    logging.error(f'Client: {client_mark}, server: {ip} connection timeout!')
                    client = None  # 超时退出：
            case _:
                if client.closeAllSocket():
                    logging.error(f'Client: {client_mark}, server: {ip} connection failure!')
                    client = None  # 意外退出：

        client_data = client.createClientDataSocket()  # 连接数据Socket
        if client_data == Status.CONNECT_TIMEOUT:
            client.closeAllSocket()  # 连接超时, 关闭客户端连接

        elif client_data == Status.SESSION_FALSE:
            client.closeAllSocket()  # 会话验证失败, 关闭客户端连接

        else:
            socket_manage[client_mark] = {
                'ip': ip,
                'id': self.host_id,
                'client': client,
                'command_socket': client_command,
                'data_socket': client_data,
                'AES_KEY': aes_key
            }

    def updateIplist(self):
        """持续更新设备列表"""
        while True:
            time.sleep(15)
            ip_list = self.scanStart()
            self.devices = self.testDevice(ip_list)
            logging.debug(f'IP list update: {self.devices}')
            for ip in self.devices:
                if ip not in self.client_connected:
                    thread = threading.Thread(target=self.createClientCommandSocket, args=(ip,))
                    thread.start()
                    self.client_connected.add(ip)


if __name__ == '__main__':
    s = createSocket()
    s.createCommandSocket()
    s.createDataSocket()
    # s = Scan()
    # print(s.start())
