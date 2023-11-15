import base64
import hashlib
import json
import locale
import logging
import os
import socket
import subprocess
import threading

import xxhash
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from core.server.scan import Scan
from core.tools.encryption import CryptoTools
from core.tools.status import Status, CommandSet, PermissionEnum
from core.tools.timedict import TimeDictInit
from core.tools.tools import HashTools, SocketSession, Session


class BaseCommandSet(Scan):
    """
    数据传输套接字：主要用于文件收发的方法实现
    所有方法的command参数传入皆为指令中值的列表

    例如：/_com:data:file(folder):get:filepath|size|hash|mode:_
    需传入[filepath, size, hash, mode]
    """

    def __init__(self, command_socket, data_socket, key: str = None):
        super().__init__()
        # 数据包传输分块大小(bytes)

        self.block = 1024
        self.command_socket = command_socket
        self.data_socket = data_socket
        self.key = key
        self.address = self.command_socket.getpeername()[0]

        self.system_encode = locale.getpreferredencoding()

        self.timedict = TimeDictInit(data_socket, command_socket, self.key)
        # self.session = Session(self.timedict, key)
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
        mode: int = data_.get('mode')
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
        self.timedict.createRecv(filemark, 'aes-128-ctr')

        if os.path.exists(remote_file_path):
            local_file_size = os.path.getsize(remote_file_path)
            local_file_hash = HashTools.getFileHash(remote_file_path)
            local_file_date = os.path.getmtime(remote_file_path)
            exists = True
        else:
            local_file_size, local_file_hash, local_file_date = None, None, None
            exists = False

        # 将所需文件信息返回到客户端
        command = {
            "data": {
                "exists": exists,
                "file_size": local_file_size,
                "file_hash": local_file_hash,
                "file_date": local_file_date
            }
        }
        with SocketSession(self.timedict, data_socket=self.data_socket, mark=reply_mark,
                           encrypt_password=self.key) as command_session:
            command_session.send(command, output=False)

        # 文件传输切片
        if not local_file_size:
            return
        data_block = self.block - len(filemark) - nonce_length

        match mode:
            case 0:
                # 如果不存在文件，则创建文件。否则不执行操作。
                if exists:
                    return False
                read_data = remote_file_size
                with open(remote_file_path, mode='ab') as f:
                    while read_data > 0:
                        read_data -= data_block
                        data = self.timedict.getRecvData(filemark)
                        f.write(data)
            case 1:
                # 如果不存在文件，则创建文件。否则重写文件。
                if exists:
                    os.remove(remote_file_path)
                read_data = remote_file_size
                with open(remote_file_path, mode='ab') as f:
                    while read_data > 0:
                        read_data -= data_block
                        data = self.timedict.getRecvData(filemark)
                        f.write(data)

            case 2:
                # 如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件。
                if not exists:
                    # 不存在文件，取消传输
                    return False

                file_block = remote_file_size / 1048576  # 计算大约超时时间
                status = self.timedict.getRecvData(reply_mark, timeout=int(file_block))
                try:
                    status = json.loads(status).get('data').get('status')
                except Exception as e:
                    print(e)
                    return

                if not status:
                    return
                # 对方客户端确认未传输完成，继续接收文件
                self.data_socket.settimeout(2)
                with open(remote_file_path, mode='ab') as f:
                    difference = remote_file_size - local_file_size
                    read_data = 0
                    while read_data <= difference:
                        try:
                            data = self.timedict.getRecvData(filemark)
                        except Exception as e:
                            print(e)
                            return Status.DATA_RECEIVE_TIMEOUT
                        f.write(data)
                        read_data += self.block
                    return True

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
        path = data_.get('path')
        remote_file_hash = data_.get('local_file_hash', 0)
        remote_size = data_.get('local_file_size', 0)
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

        # 向客户端回复本地文件状态
        command = {
            "data": {
                "local_file_size": local_file_size,
                "local_file_hash": local_file_hash
            }
        }
        with SocketSession(self.timedict, data_socket=self.data_socket, mark=reply_mark,
                           encrypt_password=self.key) as command_session:
            command_session.send(command, output=False)
            if not local_file_size:
                return

            def update_hash(file, block_size, total_blocks):
                file_xxh = xxhash.xxh3_128()
                read_blocks = 0
                while read_blocks < total_blocks:
                    f_data = file.read(block_size)
                    file_xxh.update(f_data)
                    read_blocks += 1
                return file_xxh

            def send_data(file, block_size, _socket, _filemark):
                while True:
                    f_data = file.read(block_size)
                    if not f_data:
                        break
                    f_data = bytes(_filemark, 'utf-8') + f_data
                    with SocketSession(self.timedict, _socket, mark=_filemark, encrypt_password=self.key) as session:
                        session.send(f_data)

            if remote_size < local_file_size:
                # 检查是否需要续写文件
                with open(path, mode='rb') as f:
                    file_block, little_block = divmod(remote_size, 8192)
                    xxh = update_hash(f, 8192, file_block)
                    data = f.read(little_block)
                    xxh.update(data)
                    if remote_file_hash == xxh.hexdigest():
                        # 确定为需要断点继传
                        command = {
                            "data": {
                                "status": True
                            }
                        }
                        command_session.send(command, output=False)
                        f.seek(remote_size)
                        send_data(f, data_block, self.data_socket, filemark)
                        return True
                    else:
                        return False
            elif remote_size > local_file_size:
                # 重写远程文件
                with open(path, mode='rb') as f:
                    send_data(f, data_block, self.data_socket, filemark)
                return True
            else:
                # 检查哈希值是否相同
                if remote_file_hash == local_file_hash:
                    with open(path, mode='rb') as f:
                        send_data(f, data_block, self.data_socket, filemark)
                    return True
                else:
                    return False

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

        with SocketSession(self.timedict, data_socket=self.data_socket, mark=mark,
                           encrypt_password=self.key) as command_session:

            if os.path.exists(path):
                for home, folders, files in os.walk(path):
                    paths.append(folders)
                command = {
                    "data": {
                        "status": 'success',
                        "paths": paths
                    }
                }
                command_session.send(command)
                return paths
            else:
                command = {
                    "data": {
                        "status": 'pathError'
                    }
                }
                command_session.send(command)
                return

    def postIndex(self, data_: dict, mark: str):
        """
        根据远程发送过来的索引数据更新本地同步空间的索引
        """

        spacename, json_example, isfile = data_.get('spacename'), data_.get('json'), data_.get('isfile')
        with SocketSession(self.timedict, data_socket=self.data_socket, mark=mark,
                           encrypt_password=self.key) as command_session:
            if spacename in self.config['userdata']:
                path = self.config['userdata'][spacename]['path']
                files_index_path = os.path.join(path, '\\.sync\\info\\files.json')
                folders_index_path = os.path.join(path, '\\.sync\\info\\folders.json')
                for file in [files_index_path, folders_index_path]:
                    if not os.path.exists(file):
                        command = {
                            "data": {
                                "status": 'remoteIndexNoExist'
                            }
                        }
                        command_session.send(command, output=False)
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
                            command_ = {
                                "data": {
                                    "status": 'remoteIndexError'
                                }
                            }
                            command_session.send(command_, output=False)
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

                command = {
                    "data": {
                        "status": 'remoteIndexUpdated'
                    }
                }
                command_session.send(command, output=False)
                return True
            else:
                command = {
                    "data": {
                        "status": 'remoteSpaceNameNoExist'
                    }
                }
                command_session.send(command, output=False)
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

        with SocketSession(self.timedict, self.data_socket, mark=mark, encrypt_password=self.key) as session:
            if command.startswith('/sync'):
                # sync指令
                if self.command_socket.permission >= 10:
                    logging.debug(f'Sync level command: {command}')
                    if command == '/sync restart':
                        # todo:重启服务
                        pass
                    return 0
                else:
                    command = {
                        "data": {
                            "status": CommandSet.EXSYNC_INSUFFICIENT_PERMISSION.value
                        }
                    }
                    session.send(command, output=False)
                    return CommandSet.EXSYNC_INSUFFICIENT_PERMISSION

            else:
                # 系统指令
                if self.command_socket.permission >= 20:
                    logging.debug(f'System level command: {command}')
                    process = subprocess.Popen(command.split(' '), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                               shell=True)
                    output, error = process.communicate()
                    return_code = process.wait()
                    command = {
                        "data": {
                            "return_code": return_code,
                            "output": output,
                            "error": error
                        }
                    }
                    session.send(command, output=False)
                    # self.session.sendCommand(self.data_socket, f'[{return_code}, {output}, {error}]',
                    #                          output=False, mark=mark)
                    return return_code
                else:
                    command = {
                        "data": {
                            "status": CommandSet.EXSYNC_INSUFFICIENT_PERMISSION.value
                        }
                    }
                    session.send(command, output=False)
                    return CommandSet.EXSYNC_INSUFFICIENT_PERMISSION


class CommandSetExpand(BaseCommandSet):
    """
    对于基本命令的拓展集
    """

    def __init__(self, command_socket, data_socket, key: str):
        super().__init__(command_socket, data_socket, key)
        self.session = Session(self.timedict)

    def getIndex(self, data_: dict, mark: str) -> bool:
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
                command = {
                    "data": {
                        "path": userdata.get('path')
                    }
                }
                with SocketSession(self.timedict, self.data_socket, mark=mark, encrypt_password=self.key) as session:
                    session.send(command, output=False)
                return True
        return False

    def verifyConnect(self, data_: dict, mark: str) -> bool:
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

        :param data_:
        :param mark:
        :return:
        """

        version = data_.get('version')
        if not version:
            logging.warning(f'Client {self.address} : Missing parameter [version] for execution [verifyConnect]')
            return False

        if not self.config['version'] == version:
            # todo: 客户方与服务端验证版本不一致
            return False

        if not self.password:
            # 如果密码为空, 则与客户端交换AES密钥

            # 生成一个新的RSA密钥对
            key = RSA.generate(2048)

            # 导出公钥和私钥
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            # 发送公钥, 等待对方使用公钥加密随机密码
            command = {
                "data": {
                    "public_key": base64.b64encode(public_key)
                }
            }
            with SocketSession(self.timedict, data_socket=self.data_socket, mark=mark) as command_session:
                result = command_session.send(command)

                if result == Status.DATA_RECEIVE_TIMEOUT.value:
                    self.command_socket.shutdown(socket.SHUT_RDWR)
                    self.command_socket.close()
                    return False
                else:
                    try:
                        data = json.loads(result).get('data')
                    except Exception as e:
                        print(e)
                        return False
                session_password: str = data.get('session_password')
                session_id: str = data.get('id')
                if not session_id and not session_password:
                    return False
                # 加载公钥和私钥
                private_key = RSA.import_key(private_key)
                # public_key = RSA.import_key(public_key)

                # 创建一个新的cipher实例
                # cipher_pub = PKCS1_OAEP.new(public_key)
                private_key = PKCS1_OAEP.new(private_key)

                # # 加密一条消息
                # message = b'This is a secret message'
                # ciphertext = cipher_pub.encrypt(message)

                # 解密这条消息
                # 字符串 -> byte(utf-8) -> encry -> base64 -> str
                base64_session_password = base64.b64decode(session_password)
                base64_session_id = base64.b64decode(session_id)

                de_session_password = private_key.decrypt(base64_session_password).decode('utf-8')
                de_session_id = private_key.decrypt(base64_session_id).decode('utf-8')

                crypt_id = CryptoTools(de_session_password).b64_ctr_encrypt(self.id.encode('utf-8'))

                command = {
                    "data": {
                        "status": "success",
                        "id": crypt_id
                    }
                }
                command_session.send(command, output=False)

            address = self.command_socket.getpeername()[0]
            self.verify_manage[address] = {
                "REMOTE_ID": de_session_id,
                "AES_KEY": de_session_password
            }
            self.command_socket.permission = PermissionEnum.USER

        else:
            # 2.验证远程sha256值是否与本地匹配: 发送本地的password_sha256值到远程
            # 如果密码不为空, 则无需进行密钥交换, 只需验证密钥即可
            password_sha256 = hashlib.sha256(self.password.encode('utf-8')).hexdigest()
            command = {
                "data": {
                    "password_hash": password_sha256
                }
            }
            result = self.session.sendCommand(socket_=self.data_socket, mark=mark, command=command)

            try:
                data = json.loads(result).get('data')
            except Exception as e:
                print(e)
                return False

            remote_password_sha384: str = data.get('password_hash')
            remote_id_cry_b64: str = data.get('id')

            try:
                remote_id_cry = base64.b64decode(remote_id_cry_b64)
                remote_id = CryptoTools(self.password).aes_ctr_decrypt(remote_id_cry)
            except Exception as e:
                print(e)
                return False

            # 5.验证本地sha384值是否与远程匹配匹配: 接收对方的密码sha384值, 如果通过返回id和验证状态
            password_sha384: str = hashlib.sha384(self.password.encode('utf-8')).hexdigest()
            encry_local_password: bytes = CryptoTools(self.password).aes_ctr_encrypt(self.id)
            base64_encry_local_password: str = base64.b64encode(encry_local_password).decode()

            if remote_password_sha384 == password_sha384:
                # 验证通过
                command = {
                    "data": {
                        "status": 'success',
                        "id": base64_encry_local_password
                    }
                }
                self.session.sendCommand(socket_=self.data_socket, mark=mark, command=command, output=False)

                address = self.command_socket.getpeername()[0]
                self.verify_manage[address] = {
                    "REMOTE_ID": remote_id,
                    "AES_KEY": self.password,
                    "PERMISSION": PermissionEnum.USER.value
                }
                self.command_socket.permission = PermissionEnum.USER
                return True

            elif remote_password_sha384 == Status.DATA_RECEIVE_TIMEOUT:
                # todo: 服务端密码验证失败(超时)
                command = {
                    "data": {
                        "status": 'fail',
                        "id": self.id
                    }
                }
                self.session.sendCommand(socket_=self.data_socket, mark=mark, command=command, output=False)

            else:
                # todo: 服务端密码验证失败(或得到错误参数)
                command = {
                    "data": {
                        "status": 'fail',
                        "id": self.id
                    }
                }
                self.session.sendCommand(socket_=self.data_socket, mark=mark, command=command, output=False)

            self.command_socket.shutdown(socket.SHUT_RDWR)
            self.command_socket.close()
            return False


class RecvCommand(CommandSetExpand):
    """
    异步收发指令
    """

    def __init__(self, command_socket, data_socket, key: str):
        super().__init__(command_socket, data_socket, key)
        self.command_socket = command_socket
        self.data_socket = data_socket
        self.close = False

    def closeCommand(self):
        self.close = True

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
            if self.close:
                return
            command = self.command_socket.recv(1024).decode('utf-8')
            if len(command) < 16:
                continue
            mark, command = command[:8], command[8:]  # 8字节的mark头信息和指令

            try:
                command = CryptoTools(self.key).aes_ctr_decrypt(command)
            except Exception as e:
                print(e)

            try:
                command = json.loads(command)
            except ValueError as e:
                print(e)
                continue
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
        if self.command_socket.permission <= 0:
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
