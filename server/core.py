import json
import locale
import logging
import os
import socket
import subprocess
import threading
import time
import uuid

import socks
import xxhash

from server.scan import Scan
from server.tools.status import Status, PermissionEnum, CommandSet
from server.tools.tools import SocketTools, HashTools, TimeDictInit

"""
存储答复数据
除指令的收发次数(count)其它内容均不稳定(随时改变)
基本格式[ Random_string: "答复指令" ]

data(数据传输)
文件随机头: {
    count: 收发次数(int),
    
    exist: 文件存在状态(Boolean),
    filesize: 文件比特大小(int),
    filehash: 文件xxh_128哈希值(string),
    filedate: 文件处理模式(string)
}
备注: 将在文件/文件夹传输正确完成后, 答复记录会自动销毁.
"""
reply_manage = {}

"""
客户端实例管理

ip : client_server
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
        self.client_connected = set()
        if self.config['server']['proxy']['enabled']:
            proxy_host, proxy_port = self.config['server']['proxy']['hostname'], self.config['server']['proxy']['port']
            socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
            # 替换socket
            socket.socket = socks.socksocket

        self.local_password_hash = xxhash.xxh3_128(self.config['server']['addr']['password']).hexdigest()

        # 首先扫描设备
        self.ip_list = set(self.testDevice())

        # 服务端指令Socket连接状态
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

        """
        当前与客户端建立连接的ip
        """
        self.ip = None

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

                if self.uuid == sub_socket.recv(1024).decode(self.encode_type):
                    # 确认会话id
                    SocketTools.sendCommandNoTimeDict(sub_socket, '/_com:comm:sync:post:session|True:_', output=False)
                    # 如果指令套接字存在
                    if sub_socket.getpeername()[0] in self.socket_info:
                        self.socket_info[sub_socket.getpeername()[0]]["data"] = sub_socket
                    else:
                        self.socket_info[sub_socket.getpeername()[0]] = {
                            "command": None,
                            "data": sub_socket
                        }

                else:
                    # 会话id错误
                    SocketTools.sendCommandNoTimeDict(sub_socket, '/_com:comm:sync:post:session|False:_', output=False)
                    sub_socket.shutdown(socket.SHUT_RDWR)
                    sub_socket.close()

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

            def done():
                # 验证成功
                SocketTools.sendCommandNoTimeDict(sub_socket, 'yes', output=False)
                SocketTools.sendCommandNoTimeDict(sub_socket, str(self.uuid), output=False)
                self.connected.add(addr[0])

                if sub_socket.getpeername()[0] in self.socket_info:
                    self.socket_info[sub_socket.getpeername()[0]]["command"] = sub_socket
                else:
                    sub_socket.permission = PermissionEnum.SYNC
                    self.socket_info[sub_socket.getpeername()[0]] = {
                        "command": sub_socket,
                        "data": None
                    }

            if addr[0] in self.ip_list:
                done()

            else:
                # 验证对方合法性
                sub_socket.settimeout(2)
                password_hash = SocketTools.sendCommandNoTimeDict(sub_socket, '/_com:comm:sync:get:password_hash')
                if password_hash == self.local_password_hash:
                    done()

                else:
                    # 验证失败
                    SocketTools.sendCommandNoTimeDict(sub_socket, 'no', output=False)
                    sub_socket.shutdown(socket.SHUT_RDWR)
                    sub_socket.close()

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
        password_hash = SocketTools.sendCommandNoTimeDict(verify_socket, f'/_com:comm:sync:get:password_hash:_')
        if password_hash == self.local_password_hash:
            # 哈希验证成功，ip添加进白名单
            if verify_addr[0] not in self.ip_list:
                self.ip_list.add(verify_addr)
        verify_socket.shutdown(socket.SHUT_RDWR)
        verify_socket.close()

    def mergeSocket(self):
        """如果在被动模式下指令套接字连接完毕则"""
        # command = CommandSocket()
        # while True:
        #     if self.socket_info[0] and self.socket_info[0][0] and self.socket_info[0][1]:
        #         addr = self.socket_info.pop(0)
        #         thread = threading.Thread(target=command.recvCommand, args=(addr['command'], addr['data']))
        #         thread.start()
        #     time.sleep(0.25)
        while True:
            index = 0
            for key, value in self.socket_info.items():
                if value['command'] and value['data']:
                    command_socket, data_socket = self.socket_info.pop(index)
                    command = CommandSocket(command_socket, data_socket)
                    thread = threading.Thread(target=command.recvCommand)
                    thread.start()
                    index += 1
            time.sleep(0.25)

    @staticmethod
    def createClientCommandSocket(ip, Client):
        """
        本地客户端主动连接远程服务端
        """
        client = Client()
        # 连接指令Socket
        client.connectCommandSocket(ip)
        socket_manage[HashTools.getRandomStr(8)] = {
            'ip': ip,
            'command_socket': client
        }
        # 连接数据Socket
        client.createClientDataSocket(ip)

    def updateIplist(self):
        """持续更新设备列表"""
        while True:
            time.sleep(15)
            self.ip_list = self.testDevice()
            logging.debug(f'IP list update: {self.ip_list}')
            for ip in self.ip_list:
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
        filemark = command[4]
        reply_mark = mark

        # 接收数据初始化
        self.timedict.createRecv(filemark)
        # # 答复初始化
        # reply_manage[filemark] = {
        #     'count': 0
        # }

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
        filemark_bytes = bytes(filemark, self.encode_type)
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
                            data = self.timedict.getRecvData(filemark_bytes)
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
                                data = self.timedict.getRecvData(filemark_bytes)
                                f.write(data)
                else:
                    file_size = int(remote_file_size[1])
                    with open(remote_file_path, mode='ab') as f:
                        while True:
                            if file_size > 0:
                                file_size -= data_block
                                data = self.timedict.getRecvData(filemark_bytes)
                                f.write(data)
                            else:
                                # todo: 将接收完毕的文件状态写入本地索引文件

                                break

            case 2:
                # 如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件。
                if exists:
                    # self.command_socket.send(
                    #     f'/_com:data:reply:{filemark}|{exists}|{local_file_size}|{local_file_hash}|{local_file_date}'.encode())

                    # result = SocketTools.replyCommand(1, reply_manage, filemark)
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
                                        data = self.timedict.getRecvData(filemark)
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
        SocketTools.sendCommand(self.timedict, self.data_socket, f'{local_file_size}|{local_file_hash}', mark=mark,
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

            SocketTools.sendCommand(self.timedict, self.command_socket, 'remoteIndexUpdated', output=False, mark=reply_mark)
            return True
        else:
            SocketTools.sendCommand(self.timedict, self.command_socket, 'remoteSpaceNameNoExist',
                                    output=False, mark=reply_mark)
            return False

    def executeCommand(self, command):
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
                SocketTools.sendCommand(self.command_socket, f'[{CommandSet.EXSYNC_INSUFFICIENT_PERMISSION}]')
                return CommandSet.EXSYNC_INSUFFICIENT_PERMISSION

        else:
            # 系统指令
            if self.command_socket.permission == PermissionEnum.ADMIN:
                logging.debug(f'System level command: {command}')
                process = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                           shell=True)
                output, error = process.communicate()
                return_code = process.wait()
                SocketTools.sendCommand(self.command_socket, f'[{return_code}, {output}, {error}]',
                                        output=False)
                return return_code
            else:
                SocketTools.sendCommand(self.command_socket, f'[{CommandSet.EXSYNC_INSUFFICIENT_PERMISSION}]')
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

                # 数据类型判断
                if command[1] == 'data':
                    # 文件操作
                    if command[2] == 'file':

                        if command[3] == 'post':
                            # 对方使用post提交文件至本机
                            values = command[4].split('|')
                            mark = command[0].split('/_com')[0]
                            thread = threading.Thread(target=self.recvFile, args=(values, mark))
                            thread.start()

                        elif command[3] == 'get':
                            values = command[4].split('|')
                            thread = threading.Thread(target=self.sendFile, args=(values,))
                            thread.start()
                    # 文件夹操作
                    elif command[2] == 'folder':

                        # 获取服务端文件夹信息
                        if command[3] == 'get':
                            values = command[4]
                            mark = command[0].split('/_com')[0]
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
                                                        password_hash.encode(self.encode_type),
                                                        output=False)
                            elif command[4] == 'index':
                                # 获取索引文件
                                for userdata in self.config['userdata']:
                                    if command[5] == userdata['spacename']:
                                        SocketTools.sendCommand(self.timedict, self.command_socket, userdata['path'],
                                                                mark=command[0].split('/_com')[0])

                        # 提交EXSync信息
                        elif command[3] == 'post':
                            if command[4] == 'password_hash':

                                # 对比本地密码hash
                                password = self.config['server']['addr']['password']
                                password_hash = xxhash.xxh3_128(password).hexdigest()
                                if command[4].split('|')[1] == password_hash:
                                    SocketTools.sendCommand(self.timedict, self.command_socket,
                                                            'True'.encode(self.encode_type),
                                                            output=False)

                                else:
                                    SocketTools.sendCommand(self.timedict, self.command_socket,
                                                            'False'.encode(self.encode_type),
                                                            output=False)

                            # 更新本地索引
                            elif command[4] == 'index':
                                mark = command[0].split('/_com')[0]
                                thread = threading.Thread(target=self.postIndex, args=(command[5],mark))
                                thread.start()

                            elif command[4] == 'comm':
                                thread = threading.Thread(target=self.executeCommand,
                                                          args=(command['/_com:comm:sync:post:comm:'][1],))
                                thread.start()


if __name__ == '__main__':
    s = createSocket()
    s.createCommandSocket()
    s.createDataSocket()
    # s = Scan()
    # print(s.start())
