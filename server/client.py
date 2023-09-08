import logging
import os
import shutil
import socket

import socks
import xxhash

from server.config import readConfig
from server.tools.status import Status
from server.tools.tools import HashTools, SocketTools

"""
子Socket管理
当客户端与服务端建立连接后, 用于管理指令与数据传输Socket的存储

ip: {
    command: 指令Socket
    data: 数据传输Socket
}
"""
socket_manage = {}


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
        self.encode = self.config['server']['setting']['encode']
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

    def connectCommandSocket(self, ip):
        """
        尝试连接ip_list,连接成功返回连接的ip，并且增加进connected列表
        连接至对方的server-command_socket
        """

        if not socket_manage['command'] and ip not in self.connected:
            for i in range(3):
                self.client_socket.settimeout(2)
                if self.client_socket.connect_ex((ip, self.command_port)) == 0:

                    # 开始验证合法性
                    result = self.client_socket.recv(1024).decode(self.encode)
                    if result == '/_com:comm:sync:get:password_hash':
                        result = SocketTools.sendCommand(self.client_socket, xxhash.xxh3_128(
                            self.encode).hexdigest())

                        if result == 'yes':
                            # 通过验证，接收会话id
                            self.uuid = self.client_socket.recv(1024).decode(
                                self.encode)

                            self.connected.append(ip)
                            socket_manage['command'] = self.client_socket
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
        """
        if not socket_manage['data']:
            self.client_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_data_socket.bind((self.config['server']['addr']['ip'], 0))
            if self.client_data_socket.connect_ex((ip, self.data_port)) != 0:
                # 关闭连接
                self.closeAllSocket()

            session = SocketTools.sendCommand(self.client_data_socket,
                                              str(self.uuid))
            if session.split(':')[4].split('|')[1] == 'True':
                # 会话验证成功
                socket_manage['data'] = self.client_socket
                return self.client_data_socket
            else:
                # 会话验证失败
                return Status.SESSION_FALSE

    def closeAllSocket(self):
        """结束与服务端的所有会话"""
        pass


class CommandSend:
    """客户端指令发送类"""

    def __init__(self, data_socket, command_socket):
        self.data_socket = data_socket
        self.command_socket = command_socket
        # 数据包发送分块大小(含filemark)
        self.block = 1024

    def post_File(self, path, mode=1, output_path=None):
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
        """
        if not output_path:
            output_path = path

        # 获取6位数长度的文件头标识,用于保证文件的数据唯一性
        filemark = HashTools.getRandomStr()

        local_size = os.path.getsize(path)
        hash_value = HashTools.getFileHash(path)
        data_block = self.block - len(filemark)
        # 远程服务端初始化接收文件
        result = SocketTools.sendCommand(self.command_socket,
                                         f'/_com:data:file:post:{path}|{local_size}|{hash_value}|{mode}|{filemark}:_')
        result = CommandSend.status(result)
        if result[0]:
            # 服务端准备完毕，开始传输文件
            # 服务端返回信息格式：exist | filesize | filehash | filedate
            info = result[1].split(':')
            value = info.split('|')

            # 文件存在状态
            if value[0] == 'True':
                exist = True
            elif value[0] == 'False':
                exist = False
            else:
                return Status.PARAMETER_ERROR

            # 远程文件大小, 远程文件hash值，远程文件日期
            remote_size, remote_filehash, remote_filedate = value[1], value[2], value[3]

            # 本地文件大小，本地文件hash值，远程文件日期
            local_size, local_filehash, local_filedate = local_size, hash_value, os.path.getmtime(path)

            if mode == 0 or mode == 1:
                if mode == 0 and exist:
                    self.replyFinish(filemark, False)
                    return False
                else:
                    with open(output_path, mode='rb') as f:
                        if mode == 1 and exist:
                            # 如果服务端已经存在文件，那么重写该文件
                            local_size -= remote_size
                            f.seek(remote_size)
                        data = f.read(data_block)
                        while True:
                            local_size -= data_block
                            if local_size <= 0:
                                break
                            self.data_socket.send(bytes(filemark, 'utf-8') + data)
                            data = f.read(data_block)

                        self.replyFinish(filemark)

            elif mode == 2:
                # 远程服务端准备完成
                xxh = xxhash.xxh3_128()

                if result == 'True':
                    block_times, little_block = divmod(remote_size, 8192)
                    read_data = 0
                    with open(output_path, mode='rb') as f:
                        while True:
                            if read_data < block_times:
                                data = f.read(8192)
                                xxh.update(data)
                                read_data += 1
                            else:
                                data = f.read(little_block)
                                xxh.update(data)
                                break
                    file_block_hash = xxh.hexdigest()

                    if remote_filehash == file_block_hash:
                        # 文件前段xxhash_128相同，证明为未传输完成文件
                        SocketTools.sendCommand(self.command_socket,
                                                f'/_com:data:reply:{filemark}:True:None:None:None',
                                                output=False)

                        with open(output_path, mode='rb') as f:
                            f.seek(remote_size)
                            data = f.read(data_block)
                            while True:
                                if not data:
                                    break
                                data = bytes(filemark, 'utf-8') + data
                                self.data_socket.send(data)
                        self.replyFinish(filemark)
                        return True
                    else:
                        # ？这是肾么文件，这个文件不是中断传输的产物
                        self.replyFinish(filemark, False)
                        return False
                self.replyFinish(filemark, False)
                return

    def get_File(self, path, output_path=None):
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        如果远程文件不存在则返回False

        output_path: 写入路径（如果未填写则按path参数写入）
        """
        filemark = HashTools.getRandomStr()
        data_block = self.block - len(filemark)

        if os.path.exists(path):
            file_hash = HashTools.getFileHash(path)
            file_size = os.path.getsize(path)
        else:
            file_hash = 0
            file_size = 0

        # 发送指令，远程服务端准备
        # 服务端return: /_com:data:reply:filemark:{remote_size}|{hash_value}
        result = SocketTools.sendCommand(self.command_socket,
                                         f'/_com:data:file:get:{path}|{file_hash}|{file_size}|{filemark}:_')
        command = CommandSend.status(result)[1].split(':')
        if not command[4]:
            return False

        values = command[4].split('|')
        remote_filemark, remote_file_size, remote_file_hash = command[3], values[0], values[1]

        if not output_path:
            output_path = path
        if file_size:
            read_data = 0
            with open(output_path, mode='ab') as f:
                f.seek(file_size)
                while True:
                    if read_data < remote_file_size:
                        data = self.data_socket.recv(self.block)
                    else:
                        return True
                    if data[:6] == filemark:
                        data = data[6:]
                        f.write(data)
                        read_data += data_block
        else:
            read_data = 0
            with open(output_path, mode='ab') as f:
                while True:
                    if read_data < remote_file_size:
                        data = self.data_socket.recv(self.block)
                    else:
                        return True
                    if data[:6] == filemark:
                        data = data[6:]
                        f.write(data)
                        read_data += data_block

    def post_Folder(self, path):
        """输入文件路径，发送文件夹创建指令至服务端"""
        SocketTools.sendCommand(self.command_socket,
                                f'/_com:data:folder:post:{path}:_', output=False)
        return True

    def get_Folder(self, path):
        """
        遍历获取远程文件夹下的所有文件夹
        :param path:
        :return folder_paths:
        """
        result = SocketTools.sendCommand(self.command_socket, f'/_com:data:folder:get:{path}', output=False)
        if result == Status.DATA_RECEIVE_TIMEOUT:
            return False
        paths = self.data_socket.recv(1024).decode('utf-8')
        return paths

    def get_Index(self, spacename):
        """
        获取对方索引文件
        :param spacename:
        :return Boolean:
        """
        path = SocketTools.sendCommand(self.command_socket, f'/_com:comm:sync:get:index:{spacename}_')
        if path == Status.DATA_RECEIVE_TIMEOUT:
            return False
        else:
            index_save_path = os.path.join(os.getcwd(), f'\\userdata\\space')
            cache_path = os.path.join(index_save_path, 'cache')
            save_path = os.path.join(cache_path, HashTools.getRandomStr())

            if not os.path.exists(cache_path):
                os.makedirs(cache_path)
            result = self.get_File(os.path.join(path, '\\.sync\\info\\files.json'),
                                   os.path.join(save_path, 'files.jsons')), self.get_File(
                os.path.join(path, '\\.sync\\info\\folders.json'), os.path.join(save_path, 'folders.json'))

            if all(result):
                folder_name = HashTools.getFileHash_32(
                    os.path.join(save_path, 'files.jsons')) + HashTools.getFileHash_32(
                    os.path.join(save_path, 'folders.jsons'))
                save_folder_path = os.path.join(index_save_path, spacename, folder_name)
                if os.path.exists(save_folder_path):
                    if os.path.exists(os.path.join(save_folder_path, 'files.jsons')) and os.path.exists(
                            os.path.join(save_folder_path, 'folders.jsons')):
                        logging.debug(f'{spacename} getIndex finish.')
                        return save_folder_path
                else:
                    os.makedirs(save_folder_path)
                    for file in [os.path.join(save_path, 'files.jsons'), os.path.join(save_path, 'folders.json')]:
                        shutil.move(file, os.path.join(save_folder_path, file))
                    logging.debug(f'{spacename} getIndex finish.')
                    return save_folder_path
            else:
                return False

    def post_Index(self, local_index_path):
        SocketTools.sendCommand(self.command_socket, f'/_com:comm:sync:post:index|{local_index_path}:_', output=False)
        self.post_File(os.path.join(local_index_path, '\\.sync\\info\\files.json'))
        self.post_File(os.path.join(local_index_path, '\\.sync\\info\\folders.json'))

    @staticmethod
    def status(result):
        """状态值返回，用于集中判断服务端的接收状态"""
        # /_com:data:reply:filemark:Value:_
        if result == Status.DATA_RECEIVE_TIMEOUT:
            return False, Status.DATA_RECEIVE_TIMEOUT
        else:
            result = result.split(':')
            return True, result

    def replyFinish(self, filemark, expect=True, *args):
        """
        发送请求结束传输，并让服务端删除答复记录
        此方法不接收服务端返回状态
        :param filemark: 文件传输标识
        :param expect: 是否达到客户端的预期目标
        :param args: 返回至服务端的参数
        :return: 超时/正常状态
        """
        return SocketTools.sendCommand(self.command_socket, f'/_com:data:reply_end:{filemark}:{expect}:{args}',
                                       output=False)
