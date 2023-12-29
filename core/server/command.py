import base64
import hashlib
import json
import logging
import os
import socket
import subprocess
import threading
import time

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from xxhash import xxh3_128

from core.tools import CryptoTools, Status, CommandSet, PermissionEnum, TimeDictInit, HashTools, SocketSession, Session
from .cache import indexReadCache
from .scan import Scan


class BaseCommandSet(Scan):
    """
    数据传输套接字：主要用于文件收发的方法实现
    所有方法的command参数传入皆为指令中值的列表

    例如：/_com:data:file(folder):get:filepath|size|hash|mode:_
    需传入[filepath, size, hash, mode]
    """

    def __init__(self, command_socket: socket, data_socket: socket, key: str = None):
        super().__init__()

        # 数据包传输分块大小(bytes)
        self.block: int = 1024

        # 传递套接字实例对象
        self.command_socket: socket = command_socket
        self.data_socket: socket = data_socket

        # 加密密钥
        self.key: str = key

        # 本机ip地址
        self.address: str = self.command_socket.getpeername()[0]

        # 启用TimeDict
        self.timedict = TimeDictInit(data_socket, command_socket, self.key)
        self.closeTimeDict = False

        # 启用索引缓存
        self.indexReadCache = indexReadCache

    def postFile(self, data_: dict, mark: str):
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
33,37,43
        :param data_:
        :param mark:
        :return:
        """
        remote_space_name = str(data_.get('spacename'))
        local_space = self.userdata.get(remote_space_name)
        remote_file_relative_path: str = str(data_.get('file_path'))
        remote_file_size: int = data_.get('file_size', 0)
        remote_file_hash: str = str(data_.get('file_hash'))
        mode: int = data_.get('mode')
        filemark = str(data_.get('filemark'))  # 用于接下来的文件传输的mark
        nonce_length: int = 8
        reply_mark = mark

        def sendStatus(status_: str):
            """
            2.返回错误状态
            :param status_:
            :return:
            """
            _command: dict = {
                "data": {
                    "exists": 0,
                    "file_size": 0,
                    "file_hash": 0,
                    "file_date": 0,
                    "status": status_  # 返回文件特殊状态
                }
            }

            with SocketSession(self.timedict, data_socket=self.data_socket, mark=reply_mark,
                               encrypt_password=self.key) as session:
                session.send(_command, output=False)

        # 接收数据初始化
        try:
            self.timedict.createRecv(filemark)
        except ValueError as e:
            print(e)
            sendStatus('createRecvError')
            return

        parameters = {
            'local_space': local_space,
            'remote_file_relative_path': remote_file_relative_path,
            'file_size': remote_file_size,
            'file_hash': remote_file_hash,
            'mode': mode,
            'filemark': filemark  # 用于信息的交换答复
        }

        for param, value in parameters.items():
            if not value:
                logging.warning(f'Core function recvFile: Missing parameter [{param}]!')
                return

        status = 'ok'
        if not local_space:
            # 本地同步空间不存在
            sendStatus('WrongSpace')
            return

        local_space_path = local_space.get('path')

        remote_file_abs_path = os.path.join(local_space_path, remote_file_relative_path)
        if not local_space_path:
            # 未在同步空间之内，发送拒绝通知。
            sendStatus('FileIsNotInSpace')
            return

        if len(filemark) == 8 and isinstance(remote_file_size, int) and isinstance(mode, int) and len(
                remote_file_hash) == 32:
            logging.warning('Core function recvFile: parameter error!')
            sendStatus('ParameterError')
            return

        # 读取索引
        exists, local_file_size, local_file_hash, local_file_date = False, None, None, None
        index = self.indexReadCache.getIndex(os.path.join(local_space_path, '.sync\\info\\files.json'))
        if not index:
            sendStatus('IndexError')
            return
        else:
            if os.path.exists(remote_file_abs_path):
                file_data = index['data'].get(remote_file_relative_path)
                local_file_size = file_data.get('size')
                local_file_hash = file_data.get('hash')
                local_file_date = file_data.get('file_edit_date')
                exists = True

        # 将所需文件信息返回到客户端
        command: dict = {
            "data": {
                "exists": exists,
                "file_size": local_file_size,
                "file_hash": local_file_hash,
                "file_date": local_file_date,
                "status": status  # 返回文件特殊状态
            }
        }

        with SocketSession(self.timedict, data_socket=self.data_socket, mark=reply_mark,
                           encrypt_password=self.key) as command_session:
            command_session.send(command, output=False)

        data_block = self.block - len(filemark) - nonce_length

        match mode:
            case 0:
                # 如果不存在文件，则创建文件。否则不执行操作。
                if exists:
                    return False
                read_data = remote_file_size
                with open(remote_file_abs_path, mode='ab') as f:
                    while read_data > 0:
                        read_data -= data_block
                        data = self.timedict.getRecvData(filemark)
                        f.write(data)
            case 1:
                # 如果不存在文件，则创建文件。否则重写文件。
                if exists:
                    os.remove(remote_file_abs_path)
                read_data = remote_file_size
                with open(remote_file_abs_path, mode='ab') as f:
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
                    return False

                if not status:
                    return False
                # 对方客户端确认未传输完成，继续接收文件=
                with open(remote_file_abs_path, mode='ab') as f:
                    difference = remote_file_size - local_file_size
                    read_data = 0
                    while read_data <= difference:
                        data = self.timedict.getRecvData(filemark)
                        f.write(data)
                        read_data += self.block
                    return True

    def getFile(self, data_: dict, mark: str):
        """
        发送文件至客户端
        mode = 0;
        直接发送所有数据。

        mode = 1;
        根据客户端发送的文件哈希值，判断是否是意外中断传输的文件，如果是则继续传输。

        :param data_:
        :param mark:
        :return:
        """
        reply_mark: str = mark
        file_relpath: str = data_.get('path')
        remote_file_hash: str = data_.get('local_file_hash', 0)
        remote_size: int = data_.get('local_file_size', 0)
        filemark: str = data_.get('filemark')
        local_space: dict = self.userdata.get(data_.get('spacename'))
        local_space_path: str = local_space.get('path')
        file_abspath: str = os.path.join(local_space_path, file_relpath)

        def sendStatus(status_: str):
            """
            2.返回错误状态
            :param status_:
            :return:
            """
            _command: dict = {
                "data": {
                    "exists": 0,
                    "file_size": 0,
                    "file_hash": 0,
                    "file_date": 0,
                    "status": status_  # 返回文件特殊状态
                }
            }

            with SocketSession(self.timedict, data_socket=self.data_socket, mark=reply_mark,
                               encrypt_password=self.key) as session:
                session.send(_command, output=False)

        if not filemark:
            logging.error('Core function sendFile: Missing parameter [filemark]!')
            sendStatus('ParameterError')
            return
        elif not local_space:
            logging.error(
                f'Core function sendFile: Host {self.address} attempted to write to a non user space path and has been blocked!!')
            sendStatus('SpaceError')
            return
        elif not file_relpath:
            logging.error('Core function sendFile: Missing parameter [file_relpath]!')
            sendStatus('ParameterError')
            return

        data_block = 1024 - len(filemark) - 8

        # 读取索引
        index = self.indexReadCache.getIndex(os.path.join(local_space_path, '.sync\\info\\files.json'))

        if os.path.exists(file_abspath):
            file_index = index['data'].get(file_relpath)
            local_file_size = file_index.get('size')
            local_file_hash = file_index.get('hash')
        else:
            local_file_size = 0
            local_file_hash = 0

        def sendData(m_filemark):
            with SocketSession(self.timedict, self.data_socket, mark=m_filemark,
                               encrypt_password=self.key) as m_session:
                while True:
                    m_f_data = f.read(data_block)
                    if not m_f_data:
                        break
                    m_f_data = bytes(filemark, 'utf-8') + m_f_data
                    m_session.send(m_f_data)

        with SocketSession(self.timedict, data_socket=self.data_socket, mark=reply_mark,
                           encrypt_password=self.key) as command_session:
            # 向客户端回复本地文件状态
            command = {
                "data": {
                    "local_file_size": local_file_size,
                    "local_file_hash": local_file_hash
                }
            }
            command_session.send(command, output=False)
            if not local_file_size:
                return

            def update_hash(file, block_size: int, total_blocks: int) -> xxh3_128:
                """
                更新文件哈希值
                :param file:
                :param block_size:
                :param total_blocks:
                :return:
                """
                disk_cache: dict = {
                    'start_time': time.time(),
                    'end_time': None,
                    'size': local_file_size,
                    'output': None
                }
                file_xxh = xxh3_128()
                read_blocks = 0
                while read_blocks < total_blocks:
                    file_data = file.read(block_size)
                    file_xxh.update(file_data)
                    read_blocks += 1

                disk_cache['output']: float = local_file_size / (time.time() - disk_cache.get('start_time'))

                return file_xxh

            if remote_size < local_file_size:
                # 检查是否需要续写文件
                with open(file_abspath, mode='rb') as f:
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
                        sendData(filemark)
                        return True
                    else:
                        return False
            elif remote_size > local_file_size:
                # 重写远程文件
                with open(file_abspath, mode='rb') as f:
                    sendData(filemark)
                return True
            else:
                # 检查哈希值是否相同
                if remote_file_hash == local_file_hash:
                    with open(file_abspath, mode='rb') as f:
                        sendData(filemark)
                    return True
                else:
                    return False

    def postFolder(self, data_: dict):
        """
        接收路径并创建文件夹
        """
        path = data_.get('path')
        space = self.userdata.get(data_.get('spacename'))
        if not path:
            logging.warning(f'Client {self.address} : Missing parameter [path] for execution [postFolder]')
            return False
        if not space:
            logging.warning(f'Client {self.address} : Missing parameter [space_path] for execution [postFolder]')
            return False

        space_path = space.get('path')
        folder_path = os.path.join(space_path, path)

        if not os.path.exists(folder_path):
            os.makedirs(path)
        return True

    def getFolder(self, data_: dict, mark: str):
        """
        获取文件夹信息
        如果服务端存在文件夹，以及其索引，则返回索引
        如果不存在则向客户端返回状态
        """
        file_relpath = data_.get('path')
        space = self.userdata.get(data_.get('spacename'))
        file_abspath = os.path.join(space.get('path'), file_relpath)
        if not file_relpath:
            logging.warning(f'Client {self.address} : Missing parameter [path] for execution [getFolder]')
            return False
        elif not space:
            logging.warning(f'Client {self.address} : Missing parameter [spacename] for execution [getFolder]')
            return False

        with SocketSession(self.timedict, data_socket=self.data_socket, mark=mark,
                           encrypt_password=self.key) as command_session:

            if os.path.exists(file_abspath):
                paths = []
                for home, folders, files in os.walk(file_abspath):
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

        spacename: str = data_.get('spacename')
        json_example: str = data_.get('json')
        if not spacename and not json_example:
            return False

        with SocketSession(self.timedict, data_socket=self.data_socket, mark=mark,
                           encrypt_password=self.key) as command_session:
            def sendStatus(status: str):
                _command = {
                    "data": {
                        "status": status
                    }
                }
                command_session.send(_command, output=False)

            if spacename not in self.config['userdata']:
                sendStatus('remoteSpaceNameNoExist')
                return False
            path = self.userdata[spacename].get('path')
            files_index_path = os.path.join(path, '.sync\\info\\files.json')
            if not os.path.exists(files_index_path):
                sendStatus('IndexNoExist')
                return False

            with open(files_index_path, mode='r+', encoding='utf-8') as f:
                try:
                    data = json.load(f)
                except Exception as error:
                    print(error)
                    logging.warning(f'Failed to load index file: {files_index_path}')
                    sendStatus('remoteIndexError')
                    return False

                try:
                    json_example_ = json.loads(json_example)
                except json.JSONDecodeError as e:
                    logging.error(
                        f'JSON parsing error at position {e.doc}, the incorrect content is {e.doc[e.pos:e.pos + 10]}')
                    sendStatus('jsonExampleError')
                    return

                except Exception as e:
                    logging.error(f'JSON parsing error: {e}')
                    sendStatus('jsonExampleError')
                    return

                data['data'].update(json_example_)
                f.seek(0)
                f.truncate()
                json.dump(data, f, indent=4)

            sendStatus('remoteIndexUpdated')
            return True

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

    def postStopMark(self, data_: dict, mark: str) -> str:
        """
        停止某个mark队列的执行
        :param data_:
        :param mark:
        :return:
        """
        data_mark = data_.get('mark')
        if not data_mark:
            return ''


class CommandSetExpand(BaseCommandSet):
    """
    对于基本命令的拓展集
    """

    def __init__(self, command_socket: socket, data_socket: socket, key: str):
        super().__init__(command_socket, data_socket, key)
        self.session = Session(self.timedict)
        self.cry_aes = CryptoTools(self.password)

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
                    try:
                        self.command_socket.shutdown(socket.SHUT_RDWR)
                    except OSError as e:
                        print(e)
                        logging.debug(e)
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
                remote_id = self.cry_aes.aes_ctr_decrypt(remote_id_cry)
            except Exception as e:
                print(e)
                return False

            # 5.验证本地sha384值是否与远程匹配匹配: 接收对方的密码sha384值, 如果通过返回id和验证状态
            password_sha384: str = hashlib.sha384(self.password.encode('utf-8')).hexdigest()
            encry_local_password: bytes = self.cry_aes.aes_ctr_encrypt(self.id)
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

            try:
                self.command_socket.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                print(e)
                logging.debug(e)
            self.command_socket.close()
            return False

    def syncFile(self, data_: dict, mark: str) -> bool:
        """
        在服务端收到文件后，并将文件索引进行更新
        自动判断文件操作模式：
            1.当远程文件存在时判断是否为需断点继传文件，是则继续写入。
            2.当远程文件存在并判断为并非需要断点继传文件，则重写该文件。
            3.当远程文件不存在时则创建文件。
            4.当远程文件存在时重写该文件。
        :return: 执行状态
        """
        path = data_.get('path')
        spacename = data_.get('spacename')
        remote_file_size = data_.get('file_size')
        remote_file_hash = data_.get('file_hash')
        remote_file_date = data_.get('file_date')

        for para in [path, spacename, remote_file_size, remote_file_hash, remote_file_date]:
            if not para:
                return False

        local_file_size = os.path.getsize(path)
        local_file_hash = HashTools.getFileHash(path)
        local_file_date = os.path.getmtime(path)

        with SocketSession(self.timedict, data_socket=self.data_socket, mark=mark,
                           encrypt_password=self.key) as session:

            if local_file_hash == remote_file_hash:
                # 文件相同不予传输
                status = {
                    'data': {
                        'status': 'sameFile'
                    }
                }
                session.send(status)
                return True

            elif local_file_size > remote_file_size:
                # 本地文件大于远程文件，发送停止传输原因
                status = {
                    'data': {
                        'file_size': local_file_size,
                        'file_hash': local_file_hash,
                        'file_date': local_file_date,
                        'status': 'localFileTooLarge'
                    }
                }
                session.send(status)
                return True

            elif local_file_size < remote_file_size:
                # 远程文件大于本地文件开始检查相同大小xxhash128是否相同
                # todo:
                status = {
                    'data': {
                        'file_size': local_file_size,
                        'file_hash': local_file_hash,
                        'file_date': local_file_date,
                        'status': 'remoteFileTooLarge'
                    }
                }
                session.send(status)
                return True

            if os.path.exists(path):
                with open(path, mode='rb') as f:
                    data = f.read(8192)


class RecvCommand(CommandSetExpand):
    """
    异步收发指令
    """

    def __init__(self, command_socket: socket, data_socket: socket, key: str):
        super().__init__(command_socket, data_socket, key)
        self.command_socket = command_socket
        self.data_socket = data_socket
        self.close: bool = False

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
        指令执行前的hook操作
        :return:
        """
        while True:
            if self.close:
                return
            command = self.command_socket.recv(1024)
            if len(command) < 16:
                continue
            mark, command = command[:8], command[8:]  # 8字节的mark头信息和指令

            command = CryptoTools(self.key).aes_ctr_decrypt(command)
            if not command:
                continue

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

            elif command_ == 'data' and type_ == 'syncfile' and method_ == 'post':
                self.dataPostSyncFile(data_, mark)
            elif command_ == 'comm' and type_ == 'stop' and method_ == 'post':
                self.commPostStop()

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
            thread = threading.Thread(target=self.getFile, args=(data_, mark))
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
            thread = threading.Thread(target=self.postFile, args=(data_, mark))
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

    def dataPostSyncFile(self, data_: dict, mark: str) -> bool:
        """
        "data": {
            "spacename": ... # 同步空间名称
            "path": ... # 文件路径名称
            "file_size": ... # 文件大小
            "file_hash": ... # 文件xxhash值
            "file_date": ... # 文件修改日期
        }

        :param data_:
        :param mark:
        :return:
        """
        if self.command_socket.permission >= 10:
            thread = threading.Thread(target=self.syncFile, args=(data_, mark))
            thread.daemon = True
            thread.start()
            logging.debug(f'Client {self.address}: dataPostSyncFile executing')
            return True
        else:
            logging.warning(f'Client {self.address}: Cancel receiving [SyncFile] due to insufficient permissions!')
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

    def commPostStop(self, data_: dict, mark: str) -> bool:
        """
        停止某个mark队列的指令执行
        data:{
            "mark": ...
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
