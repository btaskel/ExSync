import base64
import hashlib
import json
import logging
import socket

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from core.option import Config
from core.proxy import Proxy
from core.tools import HashTools, SocketTools, CryptoTools, Status
from .command import CommandSend


class Client(Config, Proxy):
    def __init__(self, ip: str, port: int):
        super().__init__()
        self.__host_info: dict = {}
        self.client_command_socket = None
        self.client_data_socket = None

        self.ip: str = ip
        self.data_port: int = port if port else self.data_port
        self.command_port: int = port + 1 if port else self.command_port

        if self.config['server']['proxy'].get('enabled'):
            socket.socket = self.setProxyServer(self.config)

    def host_info(self, host_info: dict) -> bool:
        """
        输入与主机联系的属性资料, 用于确认连接状态
        {
            'client_mark': client_mark,
            'ip': ip,
            'id': id,
            'AES_KEY': aes_key,
        }
        :param host_info:
        :return:
        """
        if isinstance(host_info, dict) and len(host_info) >= 1:
            self.__host_info = host_info
            return True
        return False

    def createCommandSocket(self):
        """
        创建客户端的指令套接字
        :return: 指令Socket
        """
        self.client_command_socket = socket.socket(self.socket_family, socket.SOCK_STREAM)
        self.client_command_socket.settimeout(4)
        return self.client_command_socket

    def connectRemoteCommandSocket(self) -> bool:
        """
        尝试连接ip_list,连接成功返回连接的ip，并且增加进connected列表
        连接至对方的server-command_socket
        """

        def connectVerify(debug_status: bool = False) -> bool:
            """
            有密码验证
            :param debug_status:
            :return:
            """
            # 4.本地发送sha384:发送本地密码sha384
            password_sha384: str = hashlib.sha384(self.password.encode('utf-8')).hexdigest()
            encrypt_local_id: bytes = CryptoTools(self.password).aes_gcm_encrypt(self.id)
            b64_encrypt_local_id: str = base64.b64encode(encrypt_local_id).decode('utf-8')

            _command = {
                "data": {
                    "password_hash": password_sha384,
                    "id": b64_encrypt_local_id
                }
            }

            out = SocketTools.sendCommandNoTimeDict(self.client_command_socket, command=_command)
            # 6.远程发送状态和id:获取通过状态和远程id 验证结束
            try:
                output = json.loads(out[8:]).get('data')
                remote_id = CryptoTools(self.password).aes_gcm_decrypt(base64.b64decode(output.get('id')))
                status_ = output.get('status')
            except TypeError as w:
                print(w)
                return False

            if status_ == 'success':
                # 验证成功
                self.__host_info['id'] = remote_id
                self.__host_info['AES_KEY'] = self.password
                return True

            elif status_ == 'fail':
                # 验证服务端密码失败
                debug_status and logging.error(f'Failed to verify server {self.ip} password!')
                return False

            elif status_ == Status.DATA_RECEIVE_TIMEOUT:
                # 验证服务端密码超时
                debug_status and logging.error(f'Verifying server {self.ip} password timeout!')
                return False

            else:
                # 验证服务端密码时得到未知参数
                debug_status and logging.error(
                    f'Unknown parameter obtained while verifying server {self.ip} password!')
                return False

        def connectVerifyNoPassword(pub_key: str, out: bool = False) -> bool:
            """
            无密码验证
            :param pub_key:
            :param out:
            :return:
            """
            try:
                rsa_pub = RSA.import_key(base64.b64decode(pub_key))
            except Exception as err:
                print(err)
                if out:
                    logging.error(
                        f'''When connecting to server {self.ip}, the other party's RSA public key is incorrect''')
                    return False
                return False
            cipher_pub = PKCS1_OAEP.new(rsa_pub)

            # 生成临时会话密码
            session_password = HashTools.getRandomStr(8)
            encry_session_password: bytes = cipher_pub.encrypt(session_password.encode('utf-8'))
            base64_encry_session_password: str = base64.b64encode(encry_session_password).decode('utf-8')

            # 获取加密当前主机id发送至对方
            encry_session_id: bytes = cipher_pub.encrypt(self.id.encode('utf-8'))
            base64_encry_session_id: str = base64.b64encode(encry_session_id).decode('utf-8')

            _command = {
                "data": {
                    "session_password": base64_encry_session_password,
                    "id": base64_encry_session_id
                }
            }

            _result = SocketTools.sendCommandNoTimeDict(self.client_command_socket, _command)

            try:
                _data: dict = json.loads(_result[8:]).get('data')
                remote_id = _data.get('id')
            except TypeError as a:
                print(a)
                return False
            try:
                remote_id = CryptoTools(session_password).b64_gcm_decrypt(remote_id)
            except Exception as e:
                print(e)
                return False

            # 保存远程id到本地-无密码验证
            self.__host_info['id'] = remote_id
            self.__host_info['AES_KEY'] = session_password
            return True

        def direct() -> bool:
            """
            AES_KEY不为空, 则预验证通过, 直接进行连接
            :return: 连接认证成功返回True，否则为False
            """
            status = self.client_command_socket.connect_ex((self.ip, self.command_port))
            if status == 0:
                # 连接成功

                return True
            elif status == 10061:
                # 超时
                logging.info(
                    f'''Connect to {self.__host_info['ip']}:A timeout error occurred while confirming the verification status of the linked device!''')
                return False
            else:
                # 其它错误
                logging.info(
                    f'''Connect to {self.__host_info['ip']}:An unknown error occurred while confirming the verification status of the linked device!''')
                return False

        def check() -> bool:
            """
            AES_KEY为空, 则预验证未通过, 进行验证连接
            :return: 连接认证成功返回True，否则为False
            """

            count = 3  # 连接失败重试次数
            for i in range(count):
                logging.debug(f'Connecting to server {self.ip} for the {i}th time')
                if self.client_command_socket.connect_ex((self.ip, self.command_port)) != 0:
                    continue
                # 1.本地发送验证指令:发送指令开始进行验证
                command = {
                    "command": "comm",
                    "type": "verifyconnect",
                    "method": "post",
                    "data": {"version": str(self.config.get('version'))}
                }
                result = SocketTools.sendCommandNoTimeDict(self.client_command_socket, command)
                # 3.远程发送sha256值:验证远程sha256值是否与本地匹配
                try:
                    data = json.loads(result[8:]).get('data')
                except Exception as e:
                    print(e)
                    try:
                        self.client_command_socket.shutdown(socket.SHUT_RDWR)
                    except OSError as e:
                        print(e)
                        logging.debug(e)
                    self.client_command_socket.close()
                    continue
                public_key = data.get('public_key')
                remote_password_sha256 = data.get('password_hash')

                if remote_password_sha256 == hashlib.sha256(self.password.encode('utf-8')).hexdigest():
                    if connectVerify((i == count)):
                        # 验证通过
                        return True
                    else:
                        return False

                elif not remote_password_sha256 and public_key:
                    # 对方密码为空，示意任何设备均可连接, 首先使用RSA发送一个随机字符串给予对方
                    logging.info(f'Target server {self.ip} has no password set.')
                    if connectVerifyNoPassword(public_key, (i == count)):
                        # 验证通过
                        return True
                    else:
                        continue

                elif remote_password_sha256 == Status.DATA_RECEIVE_TIMEOUT:
                    # 验证客户端密码哈希超时
                    if i == count:
                        logging.error(f'Connection to server {self.ip} timed out!')
                        return False
                    else:
                        continue

                else:
                    # 验证客户端密码哈希得到未知参数
                    if i == count:
                        logging.error(
                            f'Unknown parameter obtained while verifying server {self.ip} password hash value!')
                        return False
                    else:
                        continue
            try:
                self.client_command_socket.shutdown(socket.SHUT_RDWR)
            except OSError as e:
                print(e)
                logging.debug(e)
            self.client_command_socket.close()
            return False

        if not self.client_command_socket:
            logging.debug('Client_Command_Socket not created.')
            return False

        aes_key = self.__host_info.get('AES_KEY')
        return direct() if aes_key else check()

    def createClientDataSocket(self):
        """
        创建并连接client_data_socket - server_command_socket
        :return: client_data_socket
        """
        if not self.client_command_socket:
            raise AttributeError('未进行Command_socket连接，无法创建Data_socket')
        self.client_data_socket = socket.socket(self.socket_family, socket.SOCK_STREAM)
        self.client_data_socket.bind((self.local_ip, 0))
        status = self.client_data_socket.connect_ex((self.ip, self.data_port))
        if status == 0:
            # 会话验证成功
            return self.client_data_socket

        elif status == 10061:
            # 超时关闭连接
            return Status.CONNECT_TIMEOUT

        else:
            # 会话验证失败
            return Status.SESSION_FALSE

    def createCommand(self):
        """
        创建指令控制对象
        :return: 指令控制对象
        """
        return CommandSend(self.client_data_socket, self.client_command_socket, self.__host_info.get('AES_KEY'))

    def closeAllSocket(self):
        """结束与服务端的所有会话"""
        try:
            self.client_data_socket.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            print(e)
            logging.debug(e)
        self.client_data_socket.close()
        try:
            self.client_command_socket.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            print(e)
            logging.debug(e)
        self.client_command_socket.close()
        return True
