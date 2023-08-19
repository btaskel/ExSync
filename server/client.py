import os
import socket

import socks
import xxhash

from server.config import readConfig
from server.tools.status import Status
from server.tools.tools import HashTools
from server.tools.tools import SocketTools


class Client(readConfig):
    def __init__(self):
        super().__init__()
        self.client_socket = None
        self.client_data_socket = None
        self.config = readConfig.readJson()
        # 已连接列表
        self.connected = []
        # 会话id
        self.uuid = None

        self.data_port = self.config['server']['addr']['port']
        self.command_port = self.config['server']['addr']['port'] + 1
        self.listen_port = self.config['server']['addr']['port'] + 2
        self.encode = self.config['server']['addr']['encode']
        self.createSocket()

    def createSocket(self):
        """创建客户端的指令套接字，并且初始化代理设置"""
        proxy_host, proxy_port = self.config['server']['proxy']['hostname'], self.config['server']['proxy']['port']
        socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
        socket.socket = socks.socksocket
        # 创建套接字
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.bind((self.config['server']['addr']['ip'], 0))

        self.client_socket = client_socket

    def connectSocket(self, ip_list):
        """
        尝试连接ip_list,连接成功返回连接的ip，并且增加进connected列表
        连接至对方的server-command_socket
        """
        for ip in ip_list:
            if ip not in self.connected:
                for i in range(3):
                    self.client_socket.settimeout(2)
                    if self.client_socket.connect_ex((ip, self.command_port)) == 0:

                        # 开始验证合法性
                        result = self.client_socket.recv(1024).decode(self.config['server']['addr']['encode'])
                        if result == '/_com:comm:sync:get:password_hash':
                            result = SocketTools.sendCommand(self.client_socket, xxhash.xxh3_128(
                                self.encode).hexdigest())

                            if result == 'yes':
                                # 通过验证，接收会话id
                                self.uuid = self.client_socket.recv(1024).decode(
                                    self.config['server']['addr']['encode'])

                                self.connected.append(ip)
                                return self.client_socket

                            else:
                                # 验证失败
                                return Status.CONFIRMATION_FAILED
                        else:
                            return Status.KEY_ERROR
                    return Status.CONNECT_TIMEOUT
                return Status.CONNECTED

    def createClientDataSocket(self, ip):
        """
        创建并连接client_data_socket - server_command_socket
        :return:
        """
        self.client_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_data_socket.bind((self.config['server']['addr']['ip'], 0))
        if self.client_data_socket.connect_ex((ip, self.data_port)) != 0:
            # 关闭连接
            self.closeAllSocket()

        session = SocketTools.sendCommand(self.client_data_socket,
                                          str(self.uuid))
        if eval(session.split(':')[4].split('|')[1]):
            # 会话验证成功
            pass
        else:
            # 会话验证失败
            return Status.SESSION_FALSE

    def closeAllSocket(self):
        """结束与服务端的所有会话"""
        pass


class CommandSend(Client):
    """客户端指令发送类"""

    def __init__(self):
        super().__init__()

    def send_File(self, data_socket, path, mode=1):
        """
        输入文件路径，发送文件至服务端

        mode = 0;
        如果不存在文件，则创建文件，返回True。否则不执行操作，返回False。

        mode = 1;
        如果不存在文件，则创建文件，返回True。否则重写文件，返回False。

        mode = 2;
        如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件，返回True。否则停止发送返回False。
        """
        local_size = os.path.getsize(path)
        hash_value = HashTools.getFileHash(path)
        result = SocketTools.sendCommand(self.client_socket,
                                         f'/_com:data:file:{path}:post|{local_size}|{hash_value}|{mode}:_')
        result = CommandSend.status(result)
        if result[0]:
            # 服务端准备完毕，开始传输文件
            # 服务端返回信息格式：exist | filesize | filehash | filedate
            info = result[1].split('|')

            # 文件存在状态
            if result[0] == 'True':
                exist = True
            elif result[0] == 'False':
                exist = False
            else:
                return Status.PARAMETER_ERROR

            # 远程文件大小, 远程文件hash值，远程文件日期
            remote_size, remote_filehash, remote_filedate = info[1], info[2], info[3]

            # 本地文件大小，本地文件hash值，远程文件日期
            local_size, local_filehash, local_filedate = local_size, hash_value, os.path.getmtime(path)

            match mode:
                case 0:
                    if exist:
                        return False
                    else:
                        with open(path, mode='rb') as f:
                            data = f.read(1024)
                            while True:
                                local_size -= 1024
                                if local_size > 0:
                                    data_socket.send(data)
                                    data = f.read(1024)
                                else:
                                    break

                case 1:
                    with open(path, mode='rb') as f:
                        if exist:
                            # 如果服务端已经存在文件，那么从服务端缺少的字节起始位置读取并发送
                            local_size -= remote_size
                            f.seek(remote_size)
                        data = f.read(1024)
                        while True:
                            local_size -= 1024
                            if local_size > 0:
                                data_socket.send(data)
                                data = f.read(1024)
                            else:
                                break

                case 2:
                    # 远程服务端准备完成
                    xxh = xxhash.xxh3_128()

                    if result == 'True':
                        block, little_block = divmod(remote_size, 8192)

                        read_data = 0
                        with open(path, mode='rb') as f:
                            if read_data < block:
                                read_data += 8192
                                data = f.read(8192)
                                xxh.update(data)
                            else:
                                data = f.read(little_block)
                                xxh.update(data)
                        file_block_hash = xxh.hexdigest()

                        if remote_filehash == file_block_hash:
                            # 文件前段xxhash_128相同，证明为未传输完成文件
                            SocketTools.sendCommand(self.client_socket, '/_com:data:reply:True:True:None:None:None',
                                                    output=False)

                            with open(path, mode='rb') as f:
                                f.seek(remote_size)
                                data = f.read(1024)
                                while True:
                                    if not data:
                                        break
                                    data_socket.send(data)
                            return True
                        else:
                            # ？这是肾么文件，这个文件不是中断传输的产物
                            return False

    @staticmethod
    def send_Folder(socket_, path):
        """输入文件路径，发送文件夹创建指令至服务端"""
        result = SocketTools.sendCommand(socket_, f'/_com:data:folder:post:{path}|None|None:_')
        return CommandSend.status(result)

    @staticmethod
    def status(result):
        """状态值返回，用于集中判断服务端的接收状态"""
        # /_com:data:reply:True:Value:_

        result = result.split(':')
        if result[3] == 'True':
            return True, result[4]
        elif result[3] == 'False':
            return False, result[4]

        # 如果接收超时
        elif result == Status.DATA_RECEIVE_TIMEOUT:
            return Status.DATA_RECEIVE_TIMEOUT
