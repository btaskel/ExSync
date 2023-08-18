import os
import socket
import threading
import time
import uuid

import socks
import xxhash
from ping3 import ping

from client import Client
from config import readConfig
from tools.tools import SocketTools, HashTools


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

    def start(self):
        """
        添加
        """
        global_ = {}
        for key, value in self.config["server"]["scan"].items():
            global_[key] = value

        if global_['enabled']:
            if global_['type'].lower() == 'lan':
                """
                LAN模式：逐一扫描局域网并自动搜寻具有正确密钥的计算机
                """

                def scan(j):
                    for c_value in range(j * 15 + 1, j * 15 + 16):
                        if len(self.ip_list) < self.config['server']['scan']['max']:
                            ip = f'192.168.1.{c_value}'
                            if ping(ip, timeout=1):
                                self.ip_list.append(ip)
                        else:
                            # 排除列表
                            remove_ip = ['192.168.1.1', socket.gethostbyname(socket.gethostname())]
                            for j in remove_ip:
                                self.ip_list.remove(j)
                            return self.ip_list

                threads = []
                for i in range(17):
                    t_ = threading.Thread(target=scan, args=(i,))
                    t_.start()
                    threads.append(t_)

                for thread in threads:
                    thread.join()

            elif global_['type'].lower() == 'white':
                """
                白名单模式：在此模式下只有添加的ip才能连接
                """
                for value in self.config['server']['scan']['device']:
                    self.ip_list.append(value)

            elif global_['type'].lower() == 'black':
                """
                黑名单模式：在此模式下被添加的ip将无法连接
                """
                for value in self.config['server']['scan']['device']:
                    self.ip_list.append(value)

        remove_ip = ['192.168.1.1', socket.gethostbyname(socket.gethostname())]
        for j in remove_ip:
            self.ip_list.remove(j)
        return self.ip_list

    def testDevice(self):
        """
        主动嗅探并验证ip列表是否存在活动的设备
        如果存在活动的设备判断密码是否相同
        :return: devices
        """
        self.g['devices'] = []
        ip_list = self.start()

        for ip in ip_list:
            test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test.settimeout(0.3)
            # 连接设备的指定端口
            if test.connect_ex((ip, self.command_port)) == 0:

                # 如果密码为空，则任何客户端均可以连接
                if self.password == "":
                    version = SocketTools.sendCommand(test, '/_com:comm:sync:get:version:_')
                    if version == self.config['version']:
                        self.g['devices'].append(ip)
                else:
                    # 密码不为空，则开始验证
                    version = SocketTools.sendCommand(test, '/_com:comm:sync:get:version:_')
                    if version == self.config['version']:
                        password_hash = SocketTools.sendCommand(test, '/_com:comm:sync:post:password|hash:_')
                        # 如果 远程密码哈希=本地密码哈希 则验证成功
                        if password_hash == xxhash.xxh3_128(self.password).hexdigest():
                            # 如果密码哈希值验证成功，则验证密码
                            self.g['devices'].append(ip)

            test.shutdown(socket.SHUT_RDWR)
            test.close()
        return self.g['devices']

    # def scanDevice(self):
    #     """
    #     持续扫描目标局域网的设备
    #     """
    #     scan = Scan()
    #     ip_list = scan.start()
    #
    #     # 多线程验证设备
    #     if len(ip_list) % 8 == 0:
    #         for i in range(8):
    #             thread = threading.Thread(target=scan.testDevice, args=(ip_list,))
    #             thread.start()
    #             thread.join()
    #     else:
    #         l = []
    #         q, r = divmod(len(ip_list), 8)
    #         for i in range(8):
    #             l.append(ip_list[i * q:(i + 1) * q + 1])
    #         remainder = ip_list[-1:-r - 1:-1]
    #         l.append(remainder)
    #
    #         threads = []
    #         for i in l:
    #             thread = threading.Thread(target=scan.testDevice, args=(i,))
    #             thread.start()
    #             threads.append(thread)
    #
    #         for i in threads:
    #             i.join()


class createSocket(Scan, Client):
    """
    创建命令收发和数据收发套接字
    """

    def __init__(self):
        super().__init__()
        # Socks5代理设置
        if self.config['server']['proxy']['enabled']:
            proxy_host, proxy_port = self.config['server']['proxy']['hostname'], self.config['server']['proxy']['port']
            socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
            # 替换socket
            socket.socket = socks.socksocket

        self.local_password_hash = xxhash.xxh3_128(self.config['server']['addr']['password']).hexdigest()
        self.ip_list = set(self.testDevice())
        self.connected = set()

        # 会话随机数
        self.uuid = uuid.uuid4()

        updateIplist = threading.Thread(target=self.updateIplist)
        updateIplist.start()

    def createDataSocket(self):
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.bind((self.config["server"]["addr"]["ip"], int(self.config["server"]["addr"]["port"])))
        data_socket.listen(128)

        while True:
            # 等待客户端连接服务端
            sub_socket, addr = data_socket.accept()
            if addr[0] in self.connected:

                if self.uuid == sub_socket.recv(1024).decode(self.encode_type):
                    # 确认会话id
                    SocketTools.sendCommand(sub_socket, '/_com:comm:sync:post:session|True:_', output=False)
                    thread = threading.Thread(target=DataSocket.handle_client, args=(sub_socket, addr,))
                    thread.start()
                else:
                    # 会话id错误
                    SocketTools.sendCommand(sub_socket, '/_com:comm:sync:post:session|False:_', output=False)
                    sub_socket.shutdown(socket.SHUT_RDWR)

            else:
                # 关闭连接
                sub_socket.shutdown(socket.SHUT_RDWR)
                sub_socket.close()

    def createCommandSocket(self):
        """创建指令传输套接字"""
        command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        command_socket.bind((self.config['server']['addr']['ip'], self.command_port))
        command_socket.listen(128)
        while True:
            sub_socket, addr = command_socket.accept()
            verified = False
            if addr[0] in self.ip_list:
                verified = True
            else:
                # 验证对方合法性
                self.client_socket.settimeout(2)
                password_hash = SocketTools.sendCommand(sub_socket, '/_com:comm:sync:get:password_hash')
                if password_hash == self.local_password_hash:
                    # 验证成功
                    SocketTools.sendCommand(sub_socket, 'yes', output=False)
                    SocketTools.sendCommand(sub_socket, str(self.uuid), output=False)
                    self.connected.add(addr[0])
                    verified = True
                else:

                    # 验证失败
                    SocketTools.sendCommand(sub_socket, 'no', output=False)

            t1 = threading.Thread(target=CommandSocket().recvCommand, args=(sub_socket, verified,))
            t1.start()

    def createVerifySocket(self):
        """
        创建监听套接字，并且验证双方身份
        被动连接，则对方主动连接CommandSocket
        """
        verify_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 设置收发命令的端口号(DataSocket Port + 1)
        verify_socket.bind((self.config['server']['addr']['ip'], self.listen_port))
        verify_socket.listen(128)

        while True:
            if len(self.ip_list) <= self.config['server']['scan']['max']:
                sub_socket, addr = verify_socket.accept()
                thread = threading.Thread(target=self.verifySocket, args=(sub_socket, addr,))
                thread.start()
            else:
                break

    def verifySocket(self, verify_socket, verify_addr):
        """
        如果被连接则客户端与服务端的套接字开始验证连接合法性
        1.获取对方密码哈希值
        2.对比自身密码哈希值
        3.增加至服务端白名单
        """
        # 被动模式，等待连接
        password_hash = SocketTools.sendCommand(verify_socket, f'/_com:comm:sync:get:password_hash:_')
        if password_hash == self.local_password_hash:
            # 哈希验证成功，ip添加进白名单
            if verify_addr[0] not in self.ip_list:
                self.ip_list.add(verify_addr)
        verify_socket.shutdown(socket.SHUT_RDWR)
        verify_socket.close()

    def updateIplist(self):
        """持续更新设备列表"""
        while True:
            client = Client()
            client.connectSocket(self.ip_list)
            time.sleep(15)
            self.ip_list = self.testDevice()


class DataSocket(Scan):
    """
    数据传输套接字：主要用于文件收发的方法实现
    所有方法的command参数传入皆为指令中值的列表

    例如：/_com:data:file(folder):get:filepath|size|hash|mode:_
    需传入[filepath, size, hash, mode]
    """

    def __init__(self, command_socket, data_socket):
        super().__init__()
        self.command_socket = command_socket
        self.data_socket = data_socket

    def recvFile(self, command):
        """
        文件操作方法
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
        remote_file_hash = command[2]
        mode = int(command[3])

        if os.path.exists(remote_file_path):
            local_file_size = os.path.getsize(remote_file_path)
            local_file_hash = HashTools.getFileHash(remote_file_path)
            local_file_date = os.path.getmtime(remote_file_path)
            exists = True
        else:
            local_file_size, local_file_hash, local_file_date = None, None, None
            exists = False

        # 文件信息
        remote_file_date = os.path.getmtime(remote_file_path)

        match mode:
            case 0:
                if exists:
                    # 服务端返回信息格式：exist | filesize | filehash | filedate
                    self.command_socket.send(
                        f'/_com:data:reply:True:{exists}|{local_file_size}|{local_file_hash}|{local_file_date}'.encode())
                    return

                file_size = int(remote_file_size[1])
                with open(remote_file_path, mode='ab') as f:
                    while True:
                        if file_size > 0:
                            file_size -= 1024
                            data = self.data_socket.recv(1024)
                            f.write(data)
                        else:
                            # todo: 将接收完毕的文件状态写入本地索引文件

                            break
            case 1:
                pass

            case 2:
                if exists:
                    # xxh = xxhash.xxh3_128()
                    # with open(remote_file_path, mode='rb') as f:
                    #     while True:
                    #         if string:
                    #             string = f.read(8192)
                    #             xxh.update(string)
                    #         else:
                    #             break
                    #         local_file_hash = xxh.hexdigest()

                    self.command_socket.send(
                        f'/_com:data:reply:True:{exists}:{local_file_size}|{local_file_hash}|{local_file_date}'.encode())

                    result = self.command_socket.recv(1024).decode().split(':')
                    if result[3] == 'True' and result[4] == 'True':
                        # 对方客户端确认未传输完成，继续传输
                        with open(remote_file_path, mode='ab') as f:
                            difference = remote_file_size - local_file_size
                            read_data = 0
                            while True:
                                if read_data <= difference:
                                    data = self.data_socket.recv(1024)
                                    f.write(data)
                                    read_data += 1024
                                else:
                                    break



                else:
                    return


class CommandSocket(Scan):
    """
    异步收发指令

    Data操作指令：
    文件与文件夹的传输指令:
        /_com:data:file(folder):get:filepath|size|hash|mode:_
        /_com:data:file(folder):post:filepath|size|hash|mode:_

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

    def __init__(self):
        super().__init__()

    def recvCommand(self, command_socket, data_socket, verified=False):
        """
        持续倾听并解析指令
        verified 验证状态：True已验证，False未验证
        :return:
        """

        command_set = DataSocket(command_socket, data_socket)

        while True:
            # 收指令
            command = command_socket.recv(1024).decode(self.encode_type)
            if command.startswith('/_com:'):
                command = command.split(':')

                # 数据类型判断
                if command[1] == 'data' and verified is True:
                    # 文件操作
                    if command[2] == 'file':

                        if command[3] == 'post':
                            # 对方使用post提交文件至本机
                            thread = threading.Thread(target=command_set.recvFile, args=(command[4].split('|'),))
                            thread.start()

                        elif command[3] == 'get':
                            # todo: 对方使用get获取本机文件
                            pass

                    # 文件夹操作
                    elif command[2] == 'folder':

                        state = command[4].split('|')
                        # 创建本地文件夹
                        if state[0] == 'get':
                            if not os.path.exists(command[3]):
                                os.makedirs(command[3])
                        # 创建远程文件夹
                        elif state[0] == 'post':
                            pass

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
                                SocketTools.sendCommand(command_socket, password_hash.encode(self.encode_type),
                                                        output=False)
                        # 提交EXSync信息
                        elif command[3] == 'post':
                            if command[4] == 'password_hash':
                                # 对比本地密码hash
                                password = self.config['server']['addr']['password']
                                password_hash = xxhash.xxh3_128(password).hexdigest()
                                if command[4].split('|')[1] == password_hash:
                                    SocketTools.sendCommand(command_socket, 'True'.encode(self.encode_type),
                                                            output=False)
                                else:
                                    SocketTools.sendCommand(command_socket, 'False'.encode(self.encode_type),
                                                            output=False)


if __name__ == '__main__':
    s = createSocket()
    s.createCommandSocket()
    s.createDataSocket()
    # s = Scan()
    # print(s.start())
