import hashlib
import json
import locale
import logging
import os
import re
import socket
import subprocess
import threading
import time
import uuid

import socks
import xxhash
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from server.client import Client
from server.config import readConfig
from server.tools.status import Status, PermissionEnum, CommandSet
from server.tools.timedict import TimeDictInit, TimeDictTools
from server.tools.tools import SocketTools, HashTools

"""
客户端实例管理
"""
socket_manage = {}

"""
验证结果管理

在等待客户端和服务端连接后，会保存验证信息和Key,
TestSocket关闭, 并等待客户端与服务端的连接建立, 
会与socket_manage产生关联

verify_manage = {
    "1.1.1.1": {
        "AES_KEY": "123456"
    }
}
"""
verify_manage = {}


class Scan(readConfig):
    """
    对局域网/指定网段进行扫描和添加设备
    """

    def __init__(self):
        super().__init__()
        self.config = readConfig.readJson()
        self.ip_list = []

        # 端口类型
        self.data_port = self.config['server']['addr']['port']
        self.command_port = self.config['server']['addr']['port'] + 1
        self.listen_port = self.config['server']['addr']['port'] + 2

        self.password = self.config["server"]["addr"]["password"]

        # 读取编码类型
        if self.config['server']['setting']['encode']:
            self.encode_type = self.config['server']['setting']['encode']
        else:
            self.encode_type = 'utf-8'

        self.verified_devices = set()

    def scanStart(self):
        """
        添加
        """
        ip_list = []
        global_ = {}
        for key, value in self.config["server"]["scan"].items():
            global_[key] = value

        if global_['enabled']:
            if global_['type'].lower() == 'lan':
                """
                LAN模式：逐一扫描局域网并自动搜寻具有正确密钥的计算机
                """

                # 获取局域网所在的网段
                result = os.popen('ipconfig /all').read()
                pattern = re.compile(r'IPv4.*?(\d+\.\d+\.\d+)\.\d+')
                match = pattern.search(result)
                if not match:
                    print('无法获取局域网所在的网段')
                    return
                net = match.group(1)

                # 清空当前所有的 arp 映射表
                os.popen('arp -d *')

                # 循环遍历当前网段所有可能的 IP 与其 ping 一遍建立 arp 映射表
                for i in range(1, 256):
                    os.popen(f'ping {net}.{i} -n 1 -w 1')

                # 读取缓存的映射表获取所有与本机连接的设备的 MAC 地址
                result = os.popen('arp -a').read()
                pattern = re.compile(
                    r'(\d+\.\d+\.\d+\.\d+)\s+([\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2})')
                ips = pattern.findall(result)
                for ip, mac in ips:
                    ip_list.append(ip)
                logging.debug('LAN: Search for IP completed')
                return ip_list

            elif global_['type'].lower() == 'white':
                """
                白名单模式：在此模式下只有添加的ip才能连接
                """
                for value in self.config['server']['scan']['device']:
                    ip_list.append(value)
                logging.info('White List: Search for IP completed')

            elif global_['type'].lower() == 'black':
                """
                黑名单模式：在此模式下被添加的ip将无法连接
                """
                for value in self.config['server']['scan']['device']:
                    ip_list.append(value)
                logging.info('Black List: Search for IP completed')

        remove_ip = ['192.168.1.1', socket.gethostbyname(socket.gethostname())]
        if ip_list:
            for j in remove_ip:
                ip_list.remove(j)
        return ip_list

    def testDevice(self, ip_list):
        """
        主动验证：主动嗅探并验证ip列表是否存在活动的设备
        如果存在活动的设备判断密码是否相同
        :return: devices
        """

        for ip in ip_list:
            if ip not in verify_manage:
                test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test.settimeout(1)
                # 连接设备的指定端口
                if test.connect_ex((ip, self.command_port)) == 0:
                    version = self.g['verify_version']
                    remote_password_sha256 = SocketTools.sendCommandNoTimeDict(test,
                                                                               f'/_com:comm:sync:post:verifyConnect:{version}')
                    # 验证sha256值是否匹配
                    try:
                        remote_password_sha256, rsa_publickey = remote_password_sha256.split(':')
                    except Exception as e:
                        print(e)
                        test.shutdown(socket.SHUT_RDWR)
                        test.close()
                        continue

                    if remote_password_sha256 == hashlib.sha256(self.password.encode('utf-8')).hexdigest():

                        # 发送xxh3_128的密码值
                        result = SocketTools.sendCommandNoTimeDict(test, xxhash.xxh3_128(self.password).hexdigest())
                        if result == 'success':
                            # 验证成功
                            self.verified_devices.add(ip)
                            verify_manage[test.getpeername()[0]] = {
                                "AES_KEY": self.password
                            }
                        elif result == 'fail':
                            # todo: 验证服务端密码失败
                            pass
                        elif result == Status.DATA_RECEIVE_TIMEOUT:
                            # todo: 验证服务端密码超时
                            pass
                        else:
                            # todo: 验证服务端密码时得到未知参数
                            pass

                        test.shutdown(socket.SHUT_RDWR)
                        test.close()
                        continue

                    elif remote_password_sha256 == 'None' and rsa_publickey:
                        # 对方密码为空，示意任何设备均可连接
                        # 首先使用RSA发送一个随机字符串给予对方
                        RSA.import_key(rsa_publickey)

                        cipher_pub = PKCS1_OAEP.new(rsa_publickey)

                        message = HashTools.getRandomStr(8).encode('utf-8')

                        ciphertext = cipher_pub.encrypt(message)

                        SocketTools.sendCommandNoTimeDict(test, ciphertext, output=False)

                        self.verified_devices.add(ip)
                        verify_manage[test.getpeername()[0]] = {
                            "AES_KEY": self.password
                        }

                    elif remote_password_sha256 == Status.DATA_RECEIVE_TIMEOUT:
                        # todo: 验证客户端密码哈希超时
                        pass

                    else:
                        # todo: 验证客户端密码哈希得到未知参数
                        pass

                    test.shutdown(socket.SHUT_RDWR)
                    test.close()
                    continue

            return self.verified_devices


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

        """
        本机会话随机数
        用于表示本次会话的id
        """
        self.uuid = uuid.uuid4()

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
            if addr[0] in self.connected:

                # 如果指令套接字存在
                if sub_socket.getpeername()[0] in self.socket_info:
                    self.socket_info[sub_socket.getpeername()[0]]["data"] = sub_socket
                else:
                    self.socket_info[sub_socket.getpeername()[0]] = {
                        "command": None,
                        "data": sub_socket
                    }

            else:
                # 关闭连接
                sub_socket.shutdown(socket.SHUT_RDWR)
                sub_socket.close()

    def verifyDataSocket(self, data_socket, address):
        """
        验证数据套接字；
        验证连接对象是否已经通过验证
        :return:
        """
        if address[0] in self.whitelist:
            # 通过验证
            data_socket.permission = PermissionEnum.SYNC
            self.socket_info[address[0]] = {
                "command": None,
                "data": data_socket
            }
        else:
            data_socket.shutdown(socket.SHUT_RDWR)
            data_socket.close()

    def createCommandSocket(self):
        """创建指令传输套接字"""
        command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        command_socket.bind((self.config['server']['addr']['ip'], self.command_port))
        command_socket.listen(128)
        while True:
            sub_socket, addr = command_socket.accept()
            thread = threading.Thread(target=self.verifyCommandSocket, args=(sub_socket, addr))
            thread.start()

    # def createVerifySocket(self):
    #     """
    #     创建监听套接字，并且验证双方身份
    #     被动连接，则对方主动连接CommandSocket
    #     """
    #     verify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #     # 设置收发命令的端口号(DataSocket Port + 1)
    #     verify_socket.bind((self.config['server']['addr']['ip'], self.listen_port))
    #     verify_socket.listen(128)
    #
    #     while True:
    #         if len(self.ip_list) <= self.config['server']['scan']['max']:
    #             sub_socket, addr = verify_socket.accept()
    #             thread = threading.Thread(target=self.verifySocket, args=(sub_socket, addr,))
    #             thread.start()
    #         else:
    #             break
    #
    # def verify(self, command_socket, addr):
    #     result = SocketTools.sendCommandNoTimeDict(command_socket, '/_com:comm:sync:get:password_hash')
    #     if result == xxhash.xxh3_128(self.config['server']['password']).hexdigest():
    #         # 验证成功
    #         SocketTools.sendCommandNoTimeDict(command_socket, self.config['password'], output=False)
    #         SocketTools.sendCommandNoTimeDict(command_socket, self.uuid, output=False)
    #         self.connected.add(addr[0])
    #
    #         if command_socket.getpeername()[0] in self.socket_info:
    #             self.socket_info[command_socket.getpeername()[0]]["command"] = command_socket
    #         else:
    #             command_socket.permission = PermissionEnum.SYNC
    #             self.socket_info[command_socket.getpeername()[0]] = {
    #                 "command": command_socket,
    #                 "data": None
    #             }
    #     else:
    #         SocketTools.sendCommandNoTimeDict(command_socket, 'passwordError', output=False)
    #
    # def verifySocket(self, verify_socket, verify_addr):
    #     """
    #     如果被连接则客户端与服务端的套接字开始验证连接合法性
    #     1.获取对方密码哈希值
    #     2.对比自身密码哈希值
    #     3.增加至服务端白名单
    #     """
    #     # 被动模式，等待连接
    #     password_hash = SocketTools.sendCommandNoTimeDict(verify_socket, f'/_com:comm:sync:get:password_hash:_')
    #     if password_hash == self.local_password_hash:
    #         # 哈希验证成功，ip添加进白名单
    #         if verify_addr[0] not in self.ip_list:
    #             self.ip_list.add(verify_addr)
    #     verify_socket.shutdown(socket.SHUT_RDWR)
    #     verify_socket.close()

    def verifyCommandSocket(self, command_socket, address):
        """
        验证指令套接字；
        验证连接对象是否已经通过验证
        :return:
        """
        if address[0] in self.whitelist:
            # 通过验证
            command_socket.permission = PermissionEnum.SYNC
            if address[0] in self.socket_info:
                self.socket_info[address[0]]['command'] = command_socket
            else:
                self.socket_info[address[0]] = {
                    "command": command_socket,
                    "data": None
                }
        else:
            command_socket.shutdown(socket.SHUT_RDWR)
            command_socket.close()

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
                    command = CommandSocket(command_socket, data_socket)
                    thread = threading.Thread(target=command.recvCommand)
                    thread.start()
                    index += 1
            time.sleep(0.05)

    def createClientCommandSocket(self, ip):
        """
        本地客户端主动连接远程服务端
        """
        client_mark = HashTools.getRandomStr(8)
        aes_key = verify_manage[ip].get('aes_key', None)

        client = Client(ip, self.data_port)
        # 连接指令Socket
        client.host_info(
            {
                'client_mark': client_mark,
                'ip': ip,
                'AES_KEY': aes_key
            }
        )
        client.connectCommandSocket()
        # 连接数据Socket
        client_data = client.createClientDataSocket()
        if client_data == Status.SESSION_FALSE:
            client.closeAllSocket()
        else:
            socket_manage[client_mark] = {
                'ip': ip,
                'command_socket': client,
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


class DataSocket(Scan):
    """
    数据传输套接字：主要用于文件收发的方法实现
    所有方法的command参数传入皆为指令中值的列表

    例如：/_com:data:file(folder):get:filepath|size|hash|mode:_
    需传入[filepath, size, hash, mode]
    """

    def __init__(self, command_socket, data_socket):
        super().__init__()
        # 数据包传输分块大小(bytes)

        self.block = 1024
        self.command_socket = command_socket
        self.data_socket = data_socket
        self.system_encode = locale.getpreferredencoding()

        self.timedict = TimeDictInit(data_socket, command_socket)
        self.timeDictTools = TimeDictTools(self.timedict)
        self.closeTimeDict = False

    def recvFile(self, command, mark):
        """
        客户端发送文件至服务端
        文件与文件夹的传输指令:
        /_com:data:file(folder):get:filepath|size|hash|mode:_
        /_com:data:file(folder):post:filepath|size|hash|mode:_

        mode = 0;
        如果不存在文件，则创建文件。否则不执行操作。

        mode = 1;
        如果不存在文件，则创建文件。否则重写文件。

        mode = 2;
        如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件。
        """
        remote_file_path = command[0]
        remote_file_size = command[1]
        mode = int(command[3])
        # 用于文件传输
        filemark = command[4]
        # 用于信息的交换答复
        reply_mark = mark

        # 接收数据初始化
        self.timedict.createRecv(filemark)

        if os.path.exists(remote_file_path):
            local_file_size = os.path.getsize(remote_file_path)
            local_file_hash = HashTools.getFileHash(remote_file_path)
            local_file_date = os.path.getmtime(remote_file_path)
            exists = True
        else:
            local_file_size, local_file_hash, local_file_date = None, None, None
            exists = False

        # 将所需文件信息返回到客户端
        SocketTools.sendCommand(self.timedict, self.data_socket,
                                f'{exists}|{local_file_size}|{local_file_hash}|{local_file_date}',
                                output=False, mark=reply_mark)

        # 文件传输切片
        if not local_file_size:
            return
        data_block = self.block - len(filemark)
        match mode:
            case 0:
                # 如果不存在文件，则创建文件。否则不执行操作。
                if exists:
                    return
                file_size = int(remote_file_size[1])
                with open(remote_file_path, mode='ab') as f:
                    while True:
                        if file_size > 0:
                            file_size -= data_block
                            data = self.timedict.getRecvData(filemark, decrypt_password=self.password)
                            f.write(data)
            case 1:
                # 如果不存在文件，则创建文件。否则重写文件。
                if exists:
                    os.remove(remote_file_path)
                    with open(remote_file_path, mode='ab') as f:
                        read_data = remote_file_size
                        while True:
                            if read_data > 0:
                                read_data -= data_block
                                data = self.timedict.getRecvData(filemark, decrypt_password=self.password)
                                f.write(data)
                else:
                    file_size = int(remote_file_size[1])
                    with open(remote_file_path, mode='ab') as f:
                        while True:
                            if file_size > 0:
                                file_size -= data_block
                                data = self.timedict.getRecvData(filemark, decrypt_password=self.password)
                                f.write(data)
                            else:
                                # todo: 将接收完毕的文件状态写入本地索引文件

                                break

            case 2:
                # 如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件。
                if exists:
                    # self.command_socket.send(
                    #     f'/_com:data:reply:{filemark}|{exists}|{local_file_size}|{local_file_hash}|{local_file_date}'.encode())

                    status = self.timedict.getRecvData(reply_mark)
                    if status == 'True':
                        # 对方客户端确认未传输完成，继续接收文件
                        with open(remote_file_path, mode='ab') as f:
                            difference = remote_file_size - local_file_size
                            read_data = 0
                            self.data_socket.settimeout(2)
                            while True:
                                if read_data <= difference:
                                    try:
                                        data = self.timedict.getRecvData(filemark, decrypt_password=self.password)
                                    except Exception as e:
                                        print(e)
                                        return Status.DATA_RECEIVE_TIMEOUT
                                    f.write(data)
                                    read_data += self.block
                                else:
                                    break
                            return True
                else:
                    # 不存在文件，不予传输
                    return False

    def sendFile(self, command, mark):
        """
        服务端发送文件至客户端

        mode = 0;
        直接发送所有数据。

        mode = 1;
        根据客户端发送的文件哈希值，判断是否是意外中断传输的文件，如果是则继续传输。
        """
        block = 1024
        reply_mark = mark
        path, remote_file_hash, remote_size, filemark = command[0], command[1], command[2], command[3]
        data_block = block - len(filemark)

        if os.path.exists(path):
            local_file_size = os.path.getsize(path)
            local_file_hash = HashTools.getFileHash(path)
        else:
            local_file_size = 0
            local_file_hash = 0

        # 向客户端回复/_com:data:reply:filemark:{remote_size}|{hash_value}

        SocketTools.sendCommand(self.timedict, self.data_socket, f'{local_file_size}|{local_file_hash}',
                                mark=reply_mark,
                                output=False)
        if local_file_size == 0:
            return

        if remote_size:
            read_data = 0
            breakpoint_hash = xxhash.xxh3_128()
            block_times, little_block = divmod(remote_size, 8192)
            with open(path, mode='rb') as f:
                while True:
                    if read_data < block_times:
                        data = f.read(8192)
                        breakpoint_hash.update(data)
                        read_data += 1
                    else:
                        data = f.read(little_block)
                        breakpoint_hash.update(data)
                        break
            file_block_hash = breakpoint_hash.hexdigest()

            if file_block_hash == remote_file_hash:
                # 确定为中断文件，开始继续传输
                SocketTools.sendCommand(self.timedict, self.data_socket, 'True', output=False,
                                        mark=reply_mark)
                with open(path, mode='rb') as f:
                    f.seek(remote_size)
                    while True:
                        data = f.read(data_block)
                        if not data:
                            break
                        data = bytes(filemark, 'utf-8') + data
                        self.data_socket.send(data)
            else:
                SocketTools.sendCommand(self.timedict, self.data_socket, 'False', output=False,
                                        mark=reply_mark)
        else:
            with open(path, mode='rb') as f:
                while True:
                    data = f.read(data_block)
                    if not data:
                        break
                    data = bytes(filemark, 'utf-8') + data
                    self.data_socket.send(data)

    def recvFolder(self, command):
        """
        接收路径并创建文件夹
        """
        if not os.path.exists(command[0]):
            os.makedirs(command[0])
        return

    def getFolder(self, command, mark):
        """
        获取文件夹信息
        如果服务端存在文件夹，以及其索引，则返回索引
        如果不存在则向客户端返回状态
        """

        paths = []
        path = command[4]
        if os.path.exists(path):
            for home, folders, files in os.walk(path):
                paths.append(folders)
            SocketTools.sendCommand(self.timedict, self.data_socket, str(paths), output=False, mark=mark)
            return paths
        else:
            SocketTools.sendCommand(self.timedict, self.data_socket, 'pathError', output=False, mark=mark)
            return

    def postIndex(self, command, mark):
        """
        根据远程发送过来的索引数据更新本地同步空间的索引
        """
        reply_mark = mark
        spacename, json_example, isfile = command[0], command[1], command[2]
        if spacename in self.config['userdata']:
            path = self.config['userdata'][spacename]['path']
            files_index_path = os.path.join(path, '\\.sync\\info\\files.json')
            folders_index_path = os.path.join(path, '\\.sync\\info\\folders.json')
            for file in [files_index_path, folders_index_path]:
                if not os.path.exists(file):
                    SocketTools.sendCommand(self.timedict, self.command_socket,
                                            'remoteIndexNoExist', output=False, mark=reply_mark)
                    return False
            try:
                json_example = json.loads(command[1])
            except Exception as e:
                print(e)
                logging.warning(f'Failed to load local index: {command[0]}')
                return False

            def __updateIndex(index_path):
                with open(index_path, mode='r+', encoding=self.encode_type) as f:
                    try:
                        data = json.load(f)
                    except Exception as error:
                        print(error)
                        logging.warning(f'Failed to load index file: {index_path}')
                        SocketTools.sendCommand(self.timedict, self.command_socket,
                                                'remoteIndexError',
                                                output=False, mark=reply_mark)
                        return False
                    data['data'].update(json_example)
                    f.truncate(0)
                    json.dump(data, f, indent=4)

            if isfile == 'True':
                # 写入文件索引
                __updateIndex(files_index_path)
            else:
                # 写入文件索引
                __updateIndex(folders_index_path)

            SocketTools.sendCommand(self.timedict, self.command_socket, 'remoteIndexUpdated', output=False,
                                    mark=reply_mark)
            return True
        else:
            SocketTools.sendCommand(self.timedict, self.command_socket, 'remoteSpaceNameNoExist',
                                    output=False, mark=reply_mark)
            return False

    def executeCommand(self, command, mark):
        """
        执行远程的指令
        :return return_code, output, error
        """
        if command.startswith('/sync'):
            # sync指令
            if self.command_socket.permission == PermissionEnum.SYNC:
                logging.debug(f'Sync level command: {command}')
                if command == '/sync restart':
                    # todo:重启服务
                    pass
                return 0
            else:
                SocketTools.sendCommand(self.timedict, self.command_socket,
                                        f'[{CommandSet.EXSYNC_INSUFFICIENT_PERMISSION}]', mark=mark)
                return CommandSet.EXSYNC_INSUFFICIENT_PERMISSION

        else:
            # 系统指令
            if self.command_socket.permission == PermissionEnum.ADMIN:
                logging.debug(f'System level command: {command}')
                process = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           shell=True)
                output, error = process.communicate()
                return_code = process.wait()
                SocketTools.sendCommand(self.timedict, self.data_socket, f'[{return_code}, {output}, {error}]',
                                        output=False, mark=mark)
                return return_code
            else:
                SocketTools.sendCommand(self.timedict, self.data_socket,
                                        f'[{CommandSet.EXSYNC_INSUFFICIENT_PERMISSION}]', mark=mark)
                return CommandSet.EXSYNC_INSUFFICIENT_PERMISSION


class CommandSocket(DataSocket):
    """
    异步收发指令

    Data操作指令：
    文件与文件夹的传输指令:
        /_com:data:file(folder):get:filepath|size|hash|mode|filemark:_
        /_com:data:file(folder):post:filepath|size|hash|mode|filemark:_

    EXSync通讯指令:
    会话id确认：
        /_com:comm:sync:post:session|True:_
        /_com:comm:sync:post:session|False:_

    获取密码:
        [命令：sync：信息交换方式：本机密码哈希：哈希标识]
        密码哈希指令
        内容 | 值
        /_com:comm:sync:get:password_hash|local_hash:_
        /_com:comm:sync:post:password_hash|local_hash:_

        密码指令
        /_com:comm:sync:get:password|local_password:_
        /_com:comm:sync:post:password|local_password:_

    获取客户端信息:
        /_com:comm:sync:get:version:_
        /_com:comm:sync:post:version:_

    系统级指令:

    """

    def __init__(self, command_socket, data_socket):
        super().__init__(command_socket, data_socket)
        self.command_socket = command_socket
        self.data_socket = data_socket

    def verifyConnect(self, version: str, mark: str):
        """
        被验证：验证对方服务端TestSocket发送至本地服务端CommandSocket的连接是否合法
        如果合法则加入可信任设备列表

        密码为空:
            1. 如果使用加密, 则任何设备都可以连接本地服务端, 会使用AES、RSA进行密钥交换, 进行私密通讯。
            2. 如果不使用加密, 则任何设备都可以连接本地服务端，且通讯为明文.
        密码存在:
            1. 如果使用加密, 则信任连接双方使用AES进行加密通讯.
            2. 如果不使用加密, 则信任连接双方为明文.
        """
        if self.g['verify_version'] == version:
            if self.password == '' or self.password is None:
                # 如果密码为空, 则与客户端交换AES密钥

                # 生成一个新的RSA密钥对
                key = RSA.generate(2048)

                # 导出公钥和私钥
                private_key = key.export_key()
                public_key = key.publickey().export_key()

                # 发送公钥, 等待对方使用公钥加密随机密码
                aes_Key = SocketTools.sendCommand(timedict=self.timedict, socket_=self.command_socket,
                                                   command=f'None:{public_key}', mark=mark)
                if aes_Key == Status.DATA_RECEIVE_TIMEOUT:
                    self.command_socket.shutdown(socket.SHUT_RDWR)
                    self.command_socket.close()
                    return

                # 加载公钥和私钥
                private_key = RSA.import_key(private_key)
                public_key = RSA.import_key(public_key)

                # 创建一个新的cipher实例
                cipher_pub = PKCS1_OAEP.new(public_key)
                cipher_priv = PKCS1_OAEP.new(private_key)

                # # 加密一条消息
                # message = b'This is a secret message'
                # ciphertext = cipher_pub.encrypt(message)

                # 解密这条消息
                aes_Key = cipher_priv.decrypt(aes_Key).decode('utf-8')

                address = self.command_socket.getpeername()[0]
                verify_manage[address] = {
                    "AES_KEY": key
                }

            else:
                # 如果密码不为空, 则无需进行密钥交换, 只需验证密钥即可
                password_sha256 = hashlib.sha256(self.password.encode('utf-8')).hexdigest()
                password_xxhash = xxhash.xxh3_128(self.password).hexdigest()
                # 验证xxh3_128值是否匹配
                remote_password_xxhash = SocketTools.sendCommand(timedict=self.timedict, socket_=self.data_socket,
                                                                 command=f'{password_sha256}:None',
                                                                 mark=mark)  # password_sha256, RSA_publicKey
                if remote_password_xxhash == password_xxhash:
                    # 验证通过
                    SocketTools.sendCommand(timedict=self.timedict, socket_=self.data_socket, command='success',
                                            output=False)
                    self.command_socket.verify_status, self.data_socket.verify_status = True

                    address = self.command_socket.getpeername()[0]
                    verify_manage[address] = {
                        "AES_KEY": self.password
                    }

                elif remote_password_xxhash == Status.DATA_RECEIVE_TIMEOUT:
                    # todo: 服务端密码验证失败(超时)
                    pass

                else:
                    # todo: 服务端密码验证失败(或得到错误参数)
                    SocketTools.sendCommand(timedict=self.timedict, socket_=self.data_socket, command='fail',
                                            output=False)

                self.command_socket.shutdown(socket.SHUT_RDWR)
                self.command_socket.close()
                return

        else:
            # todo: 客户方与服务端验证版本不一致
            return

    def recvCommand(self):
        """
        持续倾听并解析指令
        :return:
        """

        while True:
            # 收指令
            command = self.command_socket.recv(1024).decode(self.encode_type)
            if ':' in command:
                command = command.split(':')

                try:
                    mark = command[0].split('/_com')[0]
                except Exception as e:
                    print(e)
                    continue

                # 数据类型判断
                if command[1] == 'data':
                    # 文件操作
                    if command[2] == 'file':

                        if command[3] == 'post':
                            # 对方使用post提交文件至本机
                            values = command[4].split('|')
                            thread = threading.Thread(target=self.recvFile, args=(values, mark))
                            thread.start()

                        elif command[3] == 'get':
                            values = command[4].split('|')
                            thread = threading.Thread(target=self.sendFile, args=(values, mark))
                            thread.start()
                    # 文件夹操作
                    elif command[2] == 'folder':

                        # 获取服务端文件夹信息
                        if command[3] == 'get':
                            values = command[4]
                            thread = threading.Thread(target=self.getFolder, args=(values, mark))
                            thread.start()

                        # 创建服务端文件夹
                        elif command[3] == 'post':
                            values = command[4].split('|')
                            thread = threading.Thread(target=self.recvFolder, args=(values,))
                            thread.start()

                # 普通命令判断
                elif command[1] == 'comm':
                    # EXSync通讯指令
                    if command[2] == 'sync':
                        # 获取EXSync信息
                        if command[3] == 'get':
                            if command[4] == 'password_hash':
                                # 发送本地密码xxh128哈希
                                password = self.config['server']['addr']['password']
                                password_hash = xxhash.xxh3_128(password).hexdigest()
                                SocketTools.sendCommand(self.timedict, self.command_socket,
                                                        password_hash,
                                                        output=False, mark=mark)
                            elif command[4] == 'index':
                                # 获取索引文件
                                for userdata in self.config['userdata']:
                                    if command[5] == userdata['spacename']:
                                        SocketTools.sendCommand(self.timedict, self.command_socket, userdata['path'],
                                                                mark=mark)

                        # 提交EXSync信息
                        elif command[3] == 'post':
                            if command[4] == 'password_hash':

                                # 对比本地密码hash
                                password = self.config['server']['addr']['password']
                                password_hash = xxhash.xxh3_128(password).hexdigest()
                                if command[4].split('|')[1] == password_hash:
                                    SocketTools.sendCommand(self.timedict, self.command_socket,
                                                            'True', output=False, mark=mark)

                                else:
                                    SocketTools.sendCommand(self.timedict, self.command_socket,
                                                            'False', output=False, mark=mark)
                            elif command[4] == 'verifyConnect':
                                # 验证对方连接合法性
                                # 对方发送：[8bytes_mark]/_com:comm:sync:post:verifyConnect:password_hash
                                try:
                                    values = command[5].split('|')
                                except Exception as e:
                                    print(e)
                                    continue
                                thread = threading.Thread(target=self.verifyConnect, args=(values[0], mark))
                                thread.start()


                            # 更新本地索引
                            elif command[4] == 'index':
                                thread = threading.Thread(target=self.postIndex, args=(command[5], mark))
                                thread.start()

                            elif command[4] == 'comm':
                                thread = threading.Thread(target=self.executeCommand,
                                                          args=(command['/_com:comm:sync:post:comm:'][1], mark))
                                thread.start()


if __name__ == '__main__':
    s = createSocket()
    s.createCommandSocket()
    s.createDataSocket()
    # s = Scan()
    # print(s.start())
