import concurrent.futures
import logging
import os
import random
import string
import uuid

import xxhash

from server.config import readConfig
from server.tools.encryption import CryptoTools
from server.tools.status import Status


def createFile(files_path, content):
    """快速创建文件"""
    if not os.path.exists(files_path):
        with open(files_path, mode='w', encoding='utf-8') as f:
            f.write(content)


def relToAbs(file_path):
    """默认将相对路径转换为绝对路径"""
    try:
        if os.path.isabs(file_path):
            return file_path
        else:
            return os.path.abspath(file_path)
    except Exception as e:
        print(e)
        logging.error(f'File path error: {file_path}')


def is_uuid(uuid_str):
    """判断一个字符串是否为UUID"""
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False


class HashTools:
    @staticmethod
    def getFileHash(path: str, block: int = 65536):
        """获取文件的128位 xxhash值"""
        hasher = xxhash.xxh3_128()

        with open(path, mode="rb") as f:
            while True:
                data = f.read(block)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def getFileHash_32(path: str, block: int = 65536):
        """获取文件的32位 xxhash值"""
        hasher = xxhash.xxh32()

        with open(path, mode="rb") as f:
            while True:
                data = f.read(block)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def getRandomStr(number=6):
        """
        随机获取N个 26个大小写字母
        默认: 6位
        """
        characters = string.ascii_letters + '1234567890'
        return "".join(random.sample(characters, number))


class SocketTools:
    """工具包：发送指令，接收指令"""

    @staticmethod
    def sendCommand(timedict, socket_, command: str, output: bool = True, timeout: int = 2, mark: str = None,
                    encrypt_password: str = None):
        """
        发送指令并准确接收返回数据

        例： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。
         timedict : 首先客户端设置timedict的值作为自身接收数据暂存区。
         socket_ : 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
         command : 设置发送的指令。
         output : 设置是否等待接下来的返回值。
         timeout : 默认超时时间，如果超过则返回DATA_RECEIVE_TIMEOUT。
         mark : 本次答复所用的标识（主动发起请求的一方默认为None，会自动生成一个8长度的字符串作为答复ID）
         encrypt_password : 如果此项填写, 则发送数据时会对数据进行加密, 否则为明文(安全的局域网下可以不填写以提高传输性能)。

        1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
        2. 在发送指令的前方追加[答复ID]，编码发送。
        3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。

        :param encrypt_password:
        :param mark:
        :param timedict:
        :param timeout:
        :param output:
        :param socket_:
        :param command:
        :return:
        """
        mark_value = mark
        if not mark_value:
            while True:
                characters = string.ascii_letters + '1234567890'
                mark_value = "".join(random.sample(characters, 8))
                if timedict.hasKey(mark_value):
                    continue
                else:
                    break

        timedict.createRecv(mark_value)
        try:
            socket_encode = readConfig.readJson()['server']['addr']['encode']
        except Exception as e:
            raise KeyError('读取Config时错误：', e)
        if output:
            try:
                data = mark_value + command
                if encrypt_password:
                    cry = CryptoTools(encrypt_password)
                    data = cry.aes_ctr_encrypt(data)
                else:
                    data = data.encode(socket_encode)
                socket_.send(data)
                with concurrent.futures.ThreadPoolExecutor() as excutor:
                    future = excutor.submit(timedict.getRecvData(mark_value).decode(socket_encode))
                    try:
                        # 没有超时2000ms则返回接收值
                        result = future.result(timeout=timeout)
                        if mark is None:
                            return mark_value, result
                        return result
                    except concurrent.futures.TimeoutError:
                        # 超时返回错误
                        return Status.DATA_RECEIVE_TIMEOUT
            except Exception as e:
                print(e)
                return False
        else:
            try:
                socket_.send((mark_value + command).encode(socket_encode))
                if mark is None:
                    return mark_value
            except Exception as e:
                raise TimeoutError('Socket错误: ', e)
            return True

    @staticmethod
    def sendCommandNoTimeDict(socket_, command: str, output: bool = True, timeout: int = 2):
        """
        取消使用TimeDict收发数据, 用于非异步数据传输. 如无必要建议使用sendCommand()

        如果 output = True 则sendCommand()将会等待一个返回值，默认超时2s。
        :param timeout:
        :param output:
        :param socket_:
        :param command:
        :return:
        """
        try:
            socket_encode = readConfig.readJson()['server']['addr']['encode']
        except Exception as e:
            raise KeyError('读取Config时错误：', e)
        if output:
            try:
                socket_.send(command.encode(socket_encode))
                with concurrent.futures.ThreadPoolExecutor() as excutor:
                    future = excutor.submit(socket_.recv(1024))
                    try:
                        # 没有超时2000ms则返回接收值
                        result = future.result(timeout=timeout)
                        return result
                    except concurrent.futures.TimeoutError:
                        # 超时返回错误
                        return Status.DATA_RECEIVE_TIMEOUT
            except Exception as e:
                print(e)
                return False
        else:
            try:
                socket_.send(command.encode(socket_encode))
            except Exception as e:
                raise TimeoutError('Socket错误: ', e)
            return True


class SocketSession(SocketTools):
    """
    使用with快速创建一个会话, 可以省去每次填写sendCommand()部分形参的时间
    mark: 如果指定mark值则会按照当前mark继续会话；否则自动生成mark值创建会话
    data_socket & command_socket:
        SocketSession会根据传入了哪些形参而确定会话方法
        1: 当data, command都未传入, 将抛出异常;
        2: 当data传入, command为空, 将会只按data_socket进行收发，不会经过对方的指令处理;
        3: 当command传入, data为空，将会按照sendCommandNoTimedict()进行对话(特殊用途);
        4: 当data, command都传入, 第一条会通过command_socket发送至对方的指令处理,
            接下来的会话将会使用data_socket进行处理(适用于指令环境下);

    """

    def __init__(self, timedict, data_socket=None, command_socket=None, timeout: int = 2, mark: str = None,
                 encrypt_password: str = None):
        self.__timedict = timedict
        self.__data_socket = data_socket
        self.__command_socket = command_socket
        self.__timeout = timeout
        self.__encrypt_password = encrypt_password
        self.mark = mark
        self.count = 0

        if not self.__data_socket and not self.__command_socket:
            # Error
            raise ValueError('SocketSession: data_socket和command_socket未传入')

        elif self.__command_socket and self.__data_socket:
            # 从command_socket 发送指令(此后的所有数据从data_socket发送和接收)
            self.method = 0

        elif not self.__command_socket and self.__data_socket:
            # 从data_socket发送与接收数据(经过timedict标识收发)
            self.method = 1

        else:
            # 从command_socket 发送与接收数据(不经过timedict 保存数据)
            self.method = 2

        if self.mark is None:
            while True:
                characters = string.ascii_letters + '1234567890'
                self.mark = "".join(random.sample(characters, 8))
                if timedict.hasKey(self.mark):
                    continue
                else:
                    break

    def send(self, command: str, output: bool = True):
        """发送命令"""
        match self.method:
            case 0:
                _socket = self.__command_socket if self.count == 0 else self.__data_socket
                if output:
                    self.sendCommand(timedict=self.__timedict, socket_=_socket, command=command, mark=self.mark,
                                     output=output, timeout=self.__timeout, encrypt_password=self.__encrypt_password)
                else:
                    return self.sendCommand(timedict=self.__timedict, socket_=_socket, command=command, mark=self.mark,
                                            output=output, timeout=self.__timeout,
                                            encrypt_password=self.__encrypt_password)

            case 1:
                if output:
                    self.sendCommand(timedict=self.__timedict, socket_=self.__data_socket, command=command,
                                     mark=self.mark,
                                     output=output, timeout=self.__timeout, encrypt_password=self.__encrypt_password)
                else:
                    return self.sendCommand(timedict=self.__timedict, socket_=self.__data_socket, command=command,
                                            mark=self.mark, output=output, timeout=self.__timeout,
                                            encrypt_password=self.__encrypt_password)

            case 2:
                if output:
                    self.sendCommandNoTimeDict(self.__command_socket, command, output, timeout=self.__timeout)
                else:
                    return self.sendCommandNoTimeDict(self.__command_socket, command, output, timeout=self.__timeout)

        self.count += 1

    def recv(self) -> str:
        """接收数据"""
        return self.__timedict.getRecvData(mark=self.mark)

    def __enter__(self):
        return self

    def __exit__(self):
        # 清理会话
        self.__timedict.delKey(self.mark)


if __name__ == '__main__':
    # timedict = TimeDict()
    # timedict.set('a', 10)
    # time.sleep(10)
    # print(timedict.get('a'))
    # print(HashTools.getRandomStr())
    with SocketSession(None, None, None, 1) as session:
        session.send(1)
    print(session)
