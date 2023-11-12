import base64
import hashlib
import logging
import socket
from ast import literal_eval

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from core.client.command import CommandSend
from core.config import readConfig
from core.server.proxy import Proxy
from core.tools.encryption import CryptoTools
from core.tools.status import Status
from core.tools.tools import HashTools, SocketTools


class Config(readConfig):
    def __init__(self):
        super().__init__()
        self.config = readConfig.readJson()
        self.local_ip: str = self.config['server']['addr'].get('ip')
        self.encode_type: str = self.config['server']['setting'].get('encode')
        self.password: str = self.config['server']['addr'].get('password')


class Client(CommandSend, Proxy):
    def __init__(self, ip: str, port: int, verified: bool = False):
        super().__init__()
        self.__host_info: dict = {}
        self.client_command_socket = None
        self.client_data_socket = None
        self.verified: bool = verified

        self.ip: str = ip
        self.id: str = self.config['server']['addr'].get('id')
        self.data_port: int = port
        self.command_port: int = port + 1
        self.encode: str = self.config['server']['setting'].get('encode', 'utf-8')

        if self.config['server']['proxy'].get('enabled'):
            socket.socket = self.setProxyServer(self.config)

    def host_info(self, host_info: dict) -> bool:
        """
        输入与主机联系的属性资料, 用于确认连接状态
        {
            'client_mark': client_mark,
            'ip': ip,
            'id': self.host_id,
            'AES_KEY': aes_key
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
        self.client_command_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return self.client_command_socket

    def connectRemoteCommandSocket(self):
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
            password_sha384 = hashlib.sha384(self.password.encode('utf-8')).hexdigest()
            encrypt_local_id = CryptoTools(self.password).aes_ctr_encrypt(self.id).decode('utf-8')
            command = {
                "data": {
                    "password_hash": password_sha384,
                    "id": encrypt_local_id
                }
            }
            out = SocketTools.sendCommandNoTimeDict(self.client_command_socket, command=command)
            try:
                output = literal_eval(out[8:])
                remote_id = CryptoTools(self.password).aes_ctr_decrypt(base64.b64decode(output.get('id')))
            except Exception as w:
                print(w)
                return False
            status_ = output.get('status')

            # 6.远程发送状态和id:获取通过状态和远程id 验证结束
            if status_ == 'success':
                # 验证成功
                self.__host_info['id'] = remote_id
                return True

            elif status_ == 'fail':
                # 验证服务端密码失败
                debug_status and logging.error(f'Failed to verify server {self.local_ip} password!')
                return False

            elif status_ == Status.DATA_RECEIVE_TIMEOUT:
                # 验证服务端密码超时
                debug_status and logging.error(f'Verifying server {self.local_ip} password timeout!')
                return False

            else:
                # 验证服务端密码时得到未知参数
                debug_status and logging.error(
                    f'Unknown parameter obtained while verifying server {self.local_ip} password!')
                return False

        def connectVerifyNoPassword(pub_key: str, out: bool = False) -> bool:
            """
            无密码验证
            :param pub_key:
            :param out:
            :return:
            """
            try:
                rsa_pub = RSA.import_key(pub_key)
            except Exception as err:
                print(err)
                if out:
                    logging.error(
                        f'''When connecting to server {self.local_ip}, the other party's RSA public key is incorrect''')
                    return False
                return False
            cipher_pub = PKCS1_OAEP.new(rsa_pub)
            message = HashTools.getRandomStr(8).encode('utf-8')
            ciphertext = cipher_pub.encrypt(message)
            SocketTools.sendCommandNoTimeDict(self.client_command_socket, ciphertext, output=False)
            return True

        if not self.client_command_socket:
            logging.debug('Client_Command_Socket not created.')
            return Status.UNKNOWN_ERROR

        aes_key = self.__host_info.get('AES_KEY')
        if aes_key:
            # AES_KEY不为空, 则验证通过, 直接进行连接

            self.client_command_socket.settimeout(2)
            status = self.client_command_socket.connect_ex((self.ip, self.command_port))
            if status == 0:
                # 连接成功
                # with AESSession(aes_key) as aes:
                #     aes_message = aes.aes_ctr_encrypt('hello')
                #     SocketTools.sendCommandNoTimeDict(self.client_socket, )
                # todo:

                data = self.client_command_socket.recv(1024)
                cry = CryptoTools(aes_key)
                cry.aes_ctr_decrypt(data)
                if not data or data == 'validationFailed':
                    return

            elif status == 10061:
                # 超时
                return Status.CONNECT_TIMEOUT
            else:
                # 其它错误
                return Status.UNKNOWN_ERROR
        else:
            # AES_KEY 为空, 进行验证连接.
            self.client_command_socket.settimeout(2)

            count = 3  # 连接失败重试次数
            for i in range(count):
                logging.debug(f'Connecting to server {self.ip} for the {i}th time')
                if self.client_command_socket.connect_ex((self.local_ip, self.command_port)) != 0:
                    continue
                # 1.本地发送验证指令:发送指令开始进行验证
                result = SocketTools.sendCommandNoTimeDict(self.client_command_socket,
                                                           '''{
                                                               "command": "comm",
                                                               "type": "verifyconnect",
                                                               "method": "post",
                                                               "data": {"version": "%s"}
                                                           }'''.replace('\x20', '') % self.config.get('version'))
                # 3.远程发送sha256值:验证远程sha256值是否与本地匹配
                try:
                    data = literal_eval(result[8:]).get('data')
                except Exception as e:
                    print(e)
                    self.client_command_socket.shutdown(socket.SHUT_RDWR)
                    self.client_command_socket.close()
                    continue
                public_key = data.get('public_key')
                remote_password_sha256 = data.get('password_hash')
                if remote_password_sha256 == hashlib.sha256(self.password.encode('utf-8')).hexdigest():
                    debug = (i == count)

                    if connectVerify(debug):
                        # 验证通过
                        return True
                    else:
                        continue

                elif not remote_password_sha256 and public_key:
                    # 对方密码为空，示意任何设备均可连接, 首先使用RSA发送一个随机字符串给予对方
                    logging.info(f'Target server {self.local_ip} has no password set.')
                    debug = (i == count)
                    if connectVerifyNoPassword(public_key, debug):
                        # 验证通过
                        return True
                    else:
                        continue

                elif remote_password_sha256 == Status.DATA_RECEIVE_TIMEOUT:
                    # 验证客户端密码哈希超时
                    if i == count:
                        logging.error(f'Connection to server {self.local_ip} timed out!')
                        return Status.CONNECT_TIMEOUT
                    else:
                        continue

                else:
                    # 验证客户端密码哈希得到未知参数
                    if i == count:
                        logging.error(
                            f'Unknown parameter obtained while verifying server {self.local_ip} password hash value!')
                        return Status.PARAMETER_ERROR
                    else:
                        continue

            self.client_command_socket.shutdown(socket.SHUT_RDWR)
            self.client_command_socket.close()
            return False

    def createClientDataSocket(self):
        """
        创建并连接client_data_socket - server_command_socket
        """
        if self.client_command_socket:
            self.client_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

    # def commandSet(self, key:str):
    #     """
    #
    #     :param key: 指令与数据加密密钥
    #     :return: 指令集对象
    #     """
    #     if self.client_data_socket and self.client_command_socket:
    #         command = CommandSend(self.client_data_socket, self.client_command_socket, key)
    #         return command
    #     return None

    def closeAllSocket(self):
        """结束与服务端的所有会话"""
        self.client_data_socket.shutdown(socket.SHUT_RDWR)
        self.client_data_socket.close()
        self.client_command_socket.shutdown(socket.SHUT_RDWR)
        self.client_command_socket.close()
        return True
