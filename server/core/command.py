import hashlib
import json
import locale
import logging
import os
import socket
import subprocess
import threading
from ast import literal_eval

import xxhash
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from server.core.scan import Scan
from server.tools.status import Status, CommandSet
from server.tools.timedict import TimeDictInit, TimeDictTools
from server.tools.tools import SocketTools, HashTools


class BaseCommandSet(Scan):
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
        self.address = self.command_socket.getpeername()[0]

        self.system_encode = locale.getpreferredencoding()

        self.timedict = TimeDictInit(data_socket, command_socket)
        self.timeDictTools = TimeDictTools(self.timedict)
        self.closeTimeDict = False

    def recvFile(self, data_: dict, mark: str):
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

        {
            "command": "data",
            "type": "file",
            "method": "post",
            "data": {
                "file_path": "%s",
                "file_size": %s,
                "file_hash": "%s",
                "mode": %s,
                "filemark": "%s"
            }
        }
        """
        remote_file_path: str = str(data_.get('file_path'))
        remote_file_size: int = data_.get('file_size', 0)
        remote_file_hash: str = str(data_.get('file_hash'))
        mode = data_.get('mode')
        filemark = str(data_.get('filemark'))  # 用于接下来的文件传输的mark
        nonce_length: int = 8

        if not remote_file_path:
            logging.warning('Core function recvFile: Missing parameter [file_path]!')
            return Status.PARAMETER_ERROR

        elif not remote_file_size:
            logging.warning('Core function recvFile: Missing parameter [file_size]!')
            return Status.PARAMETER_ERROR

        elif not remote_file_hash:
            logging.warning('Core function recvFile: Missing parameter [file_hash]!')
            return Status.PARAMETER_ERROR

        elif not mode:
            logging.warning('Core function recvFile: Missing parameter [mode]!')
            return Status.PARAMETER_ERROR

        elif not filemark:
            logging.warning('Core function recvFile: Missing parameter [filemark]!')
            return Status.PARAMETER_ERROR

        elif len(filemark) == 8 and isinstance(remote_file_size, int) and isinstance(mode, int) and len(
                remote_file_hash) == 32:
            logging.warning('Core function recvFile: parameter error!')
            return Status.PARAMETER_ERROR

        # 用于信息的交换答复
        reply_mark = mark

        # 接收数据初始化
        self.timedict.createRecv(filemark, )

        if os.path.exists(remote_file_path):
            local_file_size = os.path.getsize(remote_file_path)
            local_file_hash = HashTools.getFileHash(remote_file_path)
            local_file_date = os.path.getmtime(remote_file_path)
            exists = True
        else:
            local_file_size, local_file_hash, local_file_date = None, None, None
            exists = False

        # 将所需文件信息返回到客户端
        command = """
        "data": {
            "exists": %s,
            "file_size": %s,
            "file_hash": %s,
            "file_date": %s
        }
        """ % (exists, local_file_size, local_file_hash, local_file_date)
        SocketTools.sendCommand(self.timedict, self.data_socket, command, output=False, mark=reply_mark)

        # 文件传输切片
        if not local_file_size:
            return
        data_block = self.block - len(filemark) - nonce_length
        match mode:
            case 0:
                # 如果不存在文件，则创建文件。否则不执行操作。
                if exists:
                    return
                file_size = remote_file_size
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
                    file_size = remote_file_size
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

    def sendFile(self, data_: dict, mark: str):
        """
        服务端发送文件至客户端

        mode = 0;
        直接发送所有数据。

        mode = 1;
        根据客户端发送的文件哈希值，判断是否是意外中断传输的文件，如果是则继续传输。
        """
        block = 1024
        reply_mark = mark
        # path, remote_file_hash, remote_size, filemark = command[0], command[1], command[2], command[3]
        path = data_.get('path')

        remote_file_hash = data_.get('remote_file_hash', 0)
        remote_size = data_.get('remote_size', 0)
        filemark = data_.get('filemark')
        if not filemark:
            logging.warning('Core function sendFile: Missing parameter [filemark]!')

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

    def postFolder(self, data_: dict):
        """
        接收路径并创建文件夹
        """
        path = data_.get('path')
        if not path:
            logging.warning(f'Client {self.address} : Missing parameter [path] for execution [postFolder]')
            return False
        try:
            if not os.path.exists(path):
                os.makedirs(path)
            return True
        except ValueError as e:
            print(e)
            logging.warning(f'Client {self.address} : Parameter [path] error for execution [postFolder]')
            return False

    def getFolder(self, data_: dict, mark: str):
        """
        获取文件夹信息
        如果服务端存在文件夹，以及其索引，则返回索引
        如果不存在则向客户端返回状态
        """

        paths = []
        path = data_.get('path')
        if not path:
            logging.warning(f'Client {self.address} : Missing parameter [path] for execution [getFolder]')
            return False

        if os.path.exists(path):
            for home, folders, files in os.walk(path):
                paths.append(folders)
            SocketTools.sendCommand(self.timedict, self.data_socket, str(paths), output=False, mark=mark)
            return paths
        else:
            SocketTools.sendCommand(self.timedict, self.data_socket, 'pathError', output=False, mark=mark)
            return

    def postIndex(self, data_: dict, mark: str):
        """
        根据远程发送过来的索引数据更新本地同步空间的索引
        """
        reply_mark = mark

        spacename, json_example, isfile = data_.get('spacename'), data_.get('json'), data_.get('isfile')
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
                json_example = json.loads(json_example)
            except Exception as e:
                print(e)
                logging.warning(f'Failed to load local index: {spacename}')
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

    def executeCommand(self, data_: dict, mark: str):
        """
        执行远程的指令
        :return return_code, output, error
        """
        command = data_.get('command')
        if not command:
            logging.warning(f'Client {self.address} : Missing parameter [command] for execution [executeCommand]')
            return False

        if command.startswith('/sync'):
            # sync指令
            if self.command_socket.permission >= 10:
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
            if self.command_socket.permission >= 20:
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


class CommandSetExpand(BaseCommandSet):
    """
    对于基本命令的拓展集
    """

    def __init__(self, command_socket, data_socket):
        super().__init__(command_socket, data_socket)

    def postPasswordHash(self, command: list, mark: str):
        """
        对比远程密码sha256是否与本地密码sha256相同
        :param command:
        :param mark:
        :return:
        """
        password = self.config['server']['addr']['password']
        local_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
        if command[4].split('|')[1] == local_password:
            SocketTools.sendCommand(self.timedict, self.command_socket,
                                    'True', output=False, mark=mark)

        else:
            SocketTools.sendCommand(self.timedict, self.command_socket,
                                    'False', output=False, mark=mark)

    def getPasswordHash(self, mark: str):
        """
        远程获取本地密码的sha256
        :param mark:
        :return:
        """
        password = self.config['server']['addr']['password']
        password_hash = xxhash.xxh3_128(password).hexdigest()
        SocketTools.sendCommand(self.timedict, self.command_socket, password_hash, output=False,
                                mark=mark)

    def getIndex(self, data_: dict, mark: str):
        """
        获取本地某个同步空间的索引路径
        :param data_:
        :param mark:
        :return:
        """
        spacename = data_.get('spacename')
        if not spacename:
            logging.warning(f'Client {self.address} : Missing parameter [spacename] for execution [getIndex]')
            return False
        for userdata in self.config['userdata']:
            if spacename == userdata['spacename']:
                SocketTools.sendCommand(self.timedict, self.command_socket, userdata['path'],
                                        mark=mark)
                return True
        return False

    def verifyConnect(self, data_: dict, mark: str):
        """
        被验证：验证对方服务端TestSocket发送至本地服务端CommandSocket的连接是否合法
        如果合法则加入可信任设备列表

        密码为空:
            1. 如果使用加密, 则任何设备都可以连接本地服务端, 会使用AES、RSA进行密钥交换, 进行私密通讯。
            2. 如果不使用加密, 则任何设备都可以连接本地服务端，且通讯为明文.
        密码存在:
            RSA: 初始化RSA密钥对象——导出公钥私钥——加载公钥和私钥——创建cipher实例——开始加密/解密
            1. 如果使用加密, 则信任连接双方使用AES进行加密通讯.
            2. 如果不使用加密, 则信任连接双方为明文.

        """

        version = data_.get('version')
        if not version:
            logging.warning(f'Client {self.address} : Missing parameter [version] for execution [verifyConnect]')
            return False

        if not self.g['verify_version'] == version:
            # todo: 客户方与服务端验证版本不一致
            return

        if not self.password:
            # 如果密码为空, 则与客户端交换AES密钥

            # 生成一个新的RSA密钥对
            key = RSA.generate(2048)

            # 导出公钥和私钥
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            # 发送公钥, 等待对方使用公钥加密随机密码
            result = SocketTools.sendCommand(timedict=self.timedict, socket_=self.command_socket, mark=mark,
                                             command='''{"data": {"public_key": "%s"}}''' % public_key)

            if result == Status.DATA_RECEIVE_TIMEOUT:
                self.command_socket.shutdown(socket.SHUT_RDWR)
                self.command_socket.close()
                return

            # 加载公钥和私钥
            private_key = RSA.import_key(private_key)
            public_key = RSA.import_key(public_key)

            # 创建一个新的cipher实例
            cipher_pub = PKCS1_OAEP.new(public_key)
            private_key = PKCS1_OAEP.new(private_key)

            # # 加密一条消息
            # message = b'This is a secret message'
            # ciphertext = cipher_pub.encrypt(message)

            # 解密这条消息
            source = private_key.decrypt(result).decode('utf-8')

            try:
                data = literal_eval(source)['data']
                session_password = data.get('session_password')
                remote_id = data.get('id')
            except Exception as e:
                print(e)
                return

            address = self.command_socket.getpeername()[0]
            self.verify_manage[address] = {
                "REMOTE_ID": remote_id,
                "AES_KEY": session_password
            }

        else:
            # 如果密码不为空, 则无需进行密钥交换, 只需验证密钥即可
            password_sha256 = hashlib.sha256(self.password.encode('utf-8')).hexdigest()
            # 远程验证sha256值是否匹配
            result = SocketTools.sendCommand(timedict=self.timedict, socket_=self.data_socket,
                                             mark=mark, command='''
            {
                "data": {
                "password_hash": "%s"
                }
            }
            '''.replace('\x20', '') % password_sha256)  # password_sha256, RSA_publicKey

            try:
                remote_password_sha384 = literal_eval(result).get('data').get('password_hash')
            except Exception as e:
                print(e)
                return

            # 验证sha384值是否匹配
            password_sha384 = hashlib.sha384(self.password.encode('utf-8')).hexdigest()
            if remote_password_sha384 == password_sha384:
                # 验证通过
                SocketTools.sendCommand(timedict=self.timedict, socket_=self.data_socket, mark=mark,
                                        command="""
                {
                    "data": {
                        "status": 'success',
                        "id": %s
                    }
                }
                """.replace('\x20', '') % self.id, output=False)

                self.command_socket.verify_status, self.data_socket.verify_status = True

                address = self.command_socket.getpeername()[0]
                self.verify_manage[address] = {
                    "REMOTE_MARK": 1,
                    "AES_KEY": self.password
                }

            elif remote_password_sha384 == Status.DATA_RECEIVE_TIMEOUT:
                # todo: 服务端密码验证失败(超时)
                pass

            else:
                # todo: 服务端密码验证失败(或得到错误参数)
                SocketTools.sendCommand(timedict=self.timedict, socket_=self.data_socket, mark=mark, command="""
                {
                    "data": {
                        "status": 'fail',
                        "id": %s
                    }
                }
                """.replace('\x20', '') % self.id, output=False)

            self.command_socket.shutdown(socket.SHUT_RDWR)
            self.command_socket.close()
            return


class RecvCommand(CommandSetExpand):
    """
    异步收发指令
    """

    def __init__(self, command_socket, data_socket):
        super().__init__(command_socket, data_socket)
        self.command_socket = command_socket
        self.data_socket = data_socket

    def closeCommand(self):
        return

    def recvCommand(self):
        """
        以dict格式接收指令:
        [8bytesMark]{
            "command": "data"/"comm", # 命令类型
            "type": "file",      # 操作类型
            "method": "get",     # 操作方法
            "data": {            # 参数数据集
                "a": 1
                ....
            }
        }

        :return:
        """
        while True:
            command = self.command_socket.recv(1024).decode(self.encode_type)
            if len(command) < 9:
                continue
            mark, command = command[:8], command[8:]  # 8字节的mark头信息和指令

            command = literal_eval(command)
            if not isinstance(command, dict):
                logging.warning(f'Server {self.address}: Missing MARK in {command} command!')
                continue
            command_ = command.get('command')
            type_ = command.get('type')
            method_ = command.get('method')
            data_ = command.get('data')
            if not command_ and not type_ and not method_ and not data_:
                logging.warning(f'Server {self.address}: Command {command} parsing failed!')
                continue

            command_ = command_.lower()
            type_ = type_.lower()
            method_ = method_.lower()

            if command_ == 'data' and type_ == 'file' and method_ == 'get':
                self.dataGetFile(data_, mark)

            elif command_ == 'data' and type_ == 'file' and method_ == 'post':
                self.dataPostFile(data_, mark)

            elif command_ == 'data' and type_ == 'folder' and method_ == 'get':
                self.dataGetFolder(data_, mark)

            elif command_ == 'data' and type_ == 'folder' and method_ == 'post':
                self.dataPostFolder(data_)

            elif command_ == 'data' and type_ == 'index' and method_ == 'get':
                self.dataGetIndex(data_, mark)

            elif command_ == 'data' and type_ == 'index' and method_ == 'post':
                self.dataPostIndex(data_, mark)

            elif command_ == 'comm' and type_ == 'verifyconnect' and method_ == 'post':
                self.commPostVerifyConnect(data_, mark)

            elif command_ == 'comm' and type_ == 'command' and method_ == 'post':
                self.commPostCommand(data_, mark)

    def dataGetFile(self, data_: dict, mark: str) -> bool:
        """
        远程客户端请求本地发送文件

        "data": {
            "path": ...
            "remote_file_hash": ...
            "remote_size": ...
            "filemark": ...
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.sendFile, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: dataGetFile executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel sending [file] due to insufficient permissions!')
            return False

    def dataPostFile(self, data_: dict, mark: str) -> bool:
        """
        远程客户端请求本地接收文件

        "data": {
            "file_path": ...,
            "file_size": ...,
            "mode": ...,
            "filemark": ...
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.recvFile, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: dataPostFile executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel receiving [file] due to insufficient permissions!')
            return False

    def dataGetFolder(self, data_: dict, mark: str) -> bool:
        """

        "data":{
            "path": ...
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.getFolder, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: dataGetFolder executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel sending [folder] due to insufficient permissions!')
            return False

    def dataPostFolder(self, data_: dict) -> bool:
        """

        "data": {
            "path": ...
        }
        :param data_:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.postFolder, args=(data_,))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: dataPostFolder executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel receiving [folder] due to insufficient permissions!')
            return False

    def dataGetIndex(self, data_: dict, mark: str) -> bool:
        """

        "data": {
            "spacename": ...
            "json": {
                file1
                file2
                ...
            }
            "isfile": Boolean
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.getIndex, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: dataGetIndex executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel sending [Index] due to insufficient permissions!')
            return False

    def dataPostIndex(self, data_: dict, mark: str) -> bool:
        """

        "data": {
            "spacename": ... # 同步空间名称
            "json": ... # json字符串
            "isfile": Boolean # 是否为文件索引
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.postIndex, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: dataPostIndex executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel receiving [Index] due to insufficient permissions!')
            return False

    def commPostVerifyConnect(self, data_: dict, mark: str) -> bool:
        # 验证对方连接合法性
        # 对方发送：[8bytes_mark]/_com:comm:sync:post:verifyConnect:version
        """

        "data": {
            "version": ...
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 0:
            thread = threading.Thread(target=self.verifyConnect, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: commPostVerifyConnect executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel [verifyConnect] due to insufficient permissions!')
            return False

    def commPostCommand(self, data_: dict, mark: str) -> bool:
        """

        "data": {
            "command": ...
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.executeCommand, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: commPostCommand executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel [postCommand] due to insufficient permissions!')
            return False
