import concurrent.futures
import hashlib
import json
import logging
import os
import random
import string
import uuid
from socket import socket

import xxhash

from core.tools.encryption import CryptoTools
from core.tools.status import Status
from core.tools.timedict import TimeDictInit


def relToAbs(file_path: str):
    """
    默认将相对路径转换为绝对路径
    :param file_path: 文件路径
    :return:
    """
    try:
        if os.path.isabs(file_path):
            return file_path
        else:
            return os.path.abspath(file_path)
    except Exception as e:
        print(e)
        logging.error(f'File path error: {file_path}')


def is_uuid(uuid_str: str) -> bool:
    """
    判断一个字符串是否为UUID
    :param uuid_str: UUID对象
    :return: 布尔值
    """
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError:
        return False


class HashTools:
    @staticmethod
    def getFileHash(path: str, block: int = 65536) -> str:
        """
        获取文件的128位 xxhash值
        :param path: 文件路径
        :param block: 数据分块大小
        :return: 128位 xxhash值
        """
        hasher = xxhash.xxh3_128()

        with open(path, mode="rb") as f:
            while True:
                data = f.read(block)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def getFileSHA265(path: str) -> str:
        """
        获取文件的256位sha hash值
        :param path: 文件索引
        :return: sha256
        """
        hasher = hashlib.sha256()
        with open(path, mode='rb') as f:
            while True:
                data = f.read(65536)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def getFileHash_32(path: str, block: int = 65536) -> str:
        """
        获取文件的32位 xxhash值
        :param path: 文件路径
        :param block: 数据分块大小
        :return: 32位 xxhash值
        """
        hasher = xxhash.xxh32()

        with open(path, mode="rb") as f:
            while True:
                data = f.read(block)
                if not data:
                    break
                hasher.update(data)
        return hasher.hexdigest()

    @staticmethod
    def getRandomStr(length: int = 6) -> str:
        """
        随机获取N个 26个大小写字母
        默认: 6位
        :param length: 随机字符串长度
        :return: 随机字符串
        """
        characters = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.sample(characters, length))


class SocketTools:
    """工具包：发送指令，接收指令"""

    @staticmethod
    def sendCommand(timedict: TimeDictInit, socket_: socket, command: dict, output: bool = True, timeout: int = 2,
                    mark: str = None, encrypt_password: str = None) -> str:
        """
        发送指令并准确接收返回数据

        例： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。

        1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
        2. 在发送指令的前方追加[答复ID]，编码发送。
        3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。

        :param encrypt_password: 如果此项填写, 则发送数据时会对数据进行加密, 否则为明文(安全的局域网下可以不填写以提高传输性能)。
        :param mark: 次答复所用的标识（主动发起请求的一方默认为None，会自动生成一个8长度的字符串作为答复ID）
        :param timedict: 首先客户端设置timedict的值作为自身接收数据暂存区。
        :param timeout: 默认超时时间，如果超过则返回DATA_RECEIVE_TIMEOUT。
        :param output: 设置是否等待接下来的返回值。
        :param socket_: 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
        :param command: 设置发送的指令, 如果为字典类型则转换为json发送。
        :return: 如果Output=True在发送数据后等待对方返回一条数据; 否则仅发送
        """
        mark_value = str(mark)
        if not mark_value or len(mark_value) != 8:
            while True:
                characters = string.ascii_letters + '1234567890'
                mark_value = "".join(random.sample(characters, 8))
                if timedict.hasKey(mark_value):
                    continue
                else:
                    break

        timedict.createRecv(mark_value)

        try:
            command = json.dumps(command)
        except ValueError as e:
            print(e)
            return ''
        data = mark_value + command

        if encrypt_password:
            data = CryptoTools(encrypt_password).aes_gcm_encrypt(data)
            if not data:
                raise ValueError('sendCommand: 发送时加密失败')
        else:
            data = data.encode('utf-8')
        if len(data) > 4096:
            raise ValueError(f'发送命令时超过1K bytes: {mark_value + command}')

        if not output:
            socket_.send(data)
            if not mark:
                return mark_value

        socket_.send(data)
        with concurrent.futures.ThreadPoolExecutor() as executor:
            if encrypt_password:
                getRecv = timedict.getRecvData(mark_value)
            else:
                getRecv = timedict.getRecvData(mark_value)
            future = executor.submit(getRecv.decode, 'utf-8')
            try:
                # 没有超时2000ms则返回接收值
                result = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                # 超时返回错误
                return Status.DATA_RECEIVE_TIMEOUT.value
            return result

    @staticmethod
    def sendCommandNoTimeDict(socket_: socket, command: dict, output: bool = True, encrypt_password: str = None) -> str:
        """
        取消使用TimeDict收发数据, 用于非异步数据传输. 如无必要建议使用sendCommand()

        :param encrypt_password: 如果此项填写, 则发送数据时会对数据进行加密, 否则为明文(安全的局域网下可以不填写以提高传输性能)。
        :param output: 如果 output = True 则sendCommand()将会等待一个返回值，默认超时2s。设置是否等待接下来的返回值。
        :param socket_: 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
        :param command: 设置发送的指令。
        :return:
        """
        crypto = CryptoTools(encrypt_password)

        try:
            command = json.dumps(command)
        except Exception as e:
            print(e)
            raise ValueError('sendCommandNoTimeDict: 格式化指令时失败')

        if encrypt_password:
            if len(command) > 4056:  # 8mark + 16nonce + 16tag = 40head
                raise ValueError('sendCommandNoTimeDict: 指令发送时大于1008个字节')
            elif len(command) < 40:
                raise ValueError('sendCommandNoTimeDict: 指令发送时无字节')
            data = crypto.aes_gcm_encrypt(HashTools.getRandomStr(8) + command)
        else:
            if len(command) > 4088:
                raise ValueError('sendCommandNoTimeDict: 指令发送时大于1016个字节')
            elif len(command) < 40:
                raise ValueError('sendCommandNoTimeDict: 指令发送时无字节')
            data = (HashTools.getRandomStr(8) + command).encode('utf-8')

        try:
            socket_.send(data)
        except OSError as e:
            logging.debug(e)
            raise TimeoutError('send timeout')

        if output:
            try:
                data = socket_.recv(4096)
            except OSError as e:
                logging.debug(e)
                raise TimeoutError('recv timeout')

            if len(data) <= 8:
                raise ValueError('sendCommandNoTimeDict: 获取的data数据少于8个字节，无法分离出mark与数据内容')
            return data.decode('utf-8')
        else:
            if encrypt_password:
                data = crypto.aes_gcm_encrypt(data)
                return data.decode('utf-8')
            else:
                return data.decode('utf-8')


class Session:
    def __init__(self, timedict: TimeDictInit, key: str = None):
        self.timedict = timedict
        self.key = key

    def sendCommand(self, socket_: socket, command: dict, output: bool = True, timeout: int = 2, mark: str = None,
                    encrypt: bool = True):
        """
        发送指令并准确接收返回数据

        例： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。

        1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
        2. 在发送指令的前方追加[答复ID]，编码发送。
        3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。

        :param encrypt: 如果此项填写, 则发送数据时会对数据进行加密, 否则为明文(安全的局域网下可以不填写以提高传输性能)。
        :param mark: 次答复所用的标识（主动发起请求的一方默认为None，会自动生成一个8长度的字符串作为答复ID）
        :param timeout: 默认超时时间，如果超过则返回DATA_RECEIVE_TIMEOUT。
        :param output: 设置是否等待接下来的返回值。
        :param socket_: 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
        :param command: 设置发送的指令, 如果为字典类型则转换为json发送。
        :return: 如果Output=True在发送数据后等待对方返回一条数据; 否则仅发送
        """

        #
        # self.timedict.createRecv(mark)
        #
        # command = json.dumps(command)
        # data = mark + command
        #
        # if encrypt:
        #     try:
        #         data = CryptoTools(self.key).aes_gcm_encrypt(data)
        #     except Exception as e:
        #         print(e)
        #         return
        # else:
        #     data = data.encode('utf-8')
        # if len(data) > 4096:
        #     raise ValueError(f'发送命令时超过1K bytes: {mark + command}')
        #
        # if output:
        #     socket_.send(data)
        #     reply = self.timedict.getRecvData(mark).decode('utf-8')
        #     if not reply:
        #         raise TimeoutError('NoReply')
        # else:
        #     socket_.send(data)
        if not mark or len(mark) != 8:
            raise ValueError('Session : MarkError')

        self.timedict.createRecv(mark)

        try:
            command = json.dumps(command)
        except Exception as e:
            print(e)
            return ''

        if encrypt:
            if len(command) > 4056:  # 8mark + 16nonce + 16tag = 40head
                raise ValueError('_sendTimeDict: 指令发送时大于1008个字节')
            elif len(command) < 40:
                raise ValueError('_sendTimeDict: 指令发送时无字节')
            data = CryptoTools(self.key).aes_gcm_encrypt(mark + command)
        else:
            if len(command) > 4088:
                raise ValueError('_sendTimeDict: 指令发送时大于1016个字节')
            elif len(command) < 40:
                raise ValueError('_sendTimeDict: 指令发送时无字节')
            data = (HashTools.getRandomStr(8) + command).encode('utf-8')

        try:
            socket_.send(data)
        except OSError as e:
            logging.debug(e)
            raise TimeoutError('SendTimeout')

        if output:
            getRecv = self.timedict.getRecvData(mark)
            if not getRecv:
                raise ValueError('getRecvTimeout')
            return getRecv.decode('utf-8')
        else:
            return ''


class SocketSession(SocketTools):
    """
    使用with快速创建一个会话, 可以省去每次填写sendCommand()部分形参的时间
    data_socket & command_socket:
        SocketSession会根据传入了哪些形参而确定会话方法
        1: 当data, command都未传入, 将抛出异常;
        2: 当data传入, command为空, 将会只按data_socket进行收发，不会经过对方的指令处理;
        3: 当command传入, data为空，将会按照sendCommandNoTimedict()进行对话(特殊用途);
        4: 当data, command都传入, 第一条会通过command_socket发送至对方的指令处理,
            接下来的会话将会使用data_socket进行处理(适用于指令环境下);

    """

    def __init__(self, timedict: TimeDictInit, data_socket: socket = None, command_socket: socket = None,
                 mark: str = None, timeout: int = None, encrypt_password: str = None):
        """
        :param timedict: TimeDict实例
        :param data_socket: 数据Socket
        :param command_socket: 指令Socket
        :param mark:如果指定mark值则会按照当前mark继续会话；否则自动生成mark值创建会话
        :param timeout: 超时答复时间
        :param encrypt_password: 密码
        """
        self.__timedict: TimeDictInit = timedict
        self.__data_socket: socket = data_socket
        self.__command_socket: socket = command_socket
        self.__aes_ctr: CryptoTools = CryptoTools(encrypt_password)
        self.mark: str = mark
        self.count: int = 0

        if timeout:
            self.__data_socket.settimeout(timeout)
            self.__command_socket.settimeout(timeout)

        if not self.mark or len(self.mark) != 8:
            raise ValueError('SocketSession: Mark标识缺少')

        if not self.__data_socket and not self.__command_socket:
            raise ValueError('SocketSession: data_socket和command_socket未传入')

        elif self.__command_socket and self.__data_socket:
            # 从command_socket 发送指令(此后的所有数据从data_socket发送和接收)
            self.method: int = 0

        elif not self.__command_socket and self.__data_socket:
            # 从data_socket发送与接收数据(经过timedict标识收发)
            self.method = 1

        else:
            # 从command_socket 发送与接收数据(不经过timedict 保存数据)
            self.method = 2

    def recv(self) -> bytes:
        """
        接收数据
        :return: 指定mark队列的数据
        """
        return self.__timedict.getRecvData(mark=self.mark)

    def getSessionCount(self) -> int:
        """
        :return: 当前会话次数
        """
        return self.count

    def send(self, message: dict or bytes, output: bool = True) -> str:
        """
        发送命令
        :param message: 指令内容
        :param output: 是否返回内容
        :return:
        """
        if not self.__timedict:
            return self._sendNoTimeDict(message, output)

        else:
            if isinstance(message, bytes):
                if self.__aes_ctr:
                    if len(message) > 4056:  # 8mark + 16nonce + 16tag = 40head
                        raise ValueError('sendCommandNoTimeDict: 指令发送时大于1008个字节')
                    elif len(message) < 40:
                        raise ValueError('sendCommandNoTimeDict: 指令发送时无字节')
                    data = self.__aes_ctr.aes_gcm_encrypt(bytes(self.mark, 'utf-8') + message)
                else:
                    if len(message) > 4088:
                        raise ValueError('sendCommandNoTimeDict: 指令发送时大于1016个字节')
                    elif len(message) < 40:
                        raise ValueError('sendCommandNoTimeDict: 指令发送时无字节')
                    data = bytes(self.mark, 'utf-8') + message
                self.__data_socket.send(data)
                return ''

            match self.method:

                case 0:
                    # 从command_socket 发送指令(此后的所有数据从data_socket发送和接收)
                    _socket = self.__command_socket if not self.count else self.__data_socket
                    return self._sendTimeDict(socket_=_socket, command=message, output=output)

                case 1:
                    # 从data_socket发送与接收数据(经过timedict标识收发)
                    return self._sendTimeDict(socket_=self.__data_socket, command=message, output=output)

                case 2:
                    # 从command_socket 发送与接收数据(不经过timedict 保存数据)
                    return self.sendCommandNoTimeDict(self.__command_socket, command=message, output=output)
            self.count += 1

    def _sendNoTimeDict(self, message: dict or bytes, output: bool = True) -> str:
        """
        取消使用TimeDict收发数据, 用于非异步数据传输.

        :param output: 如果 output = True 则sendCommand()将会等待一个返回值，默认超时2s。设置是否等待接下来的返回值。
        :param message: 设置发送的信息。
        :return:
        """
        try:
            command = json.dumps(message)
        except ValueError as e:
            print(e)
            return ''

        match self.method:
            case 0:
                # 从command_socket 发送指令(此后的所有数据从data_socket发送和接收)
                socket_ = self.__command_socket if not self.count else self.__data_socket
            case 1:
                # 从data_socket发送与接收数据(经过timedict标识收发)
                socket_ = self.__data_socket
            case 2:
                # 从command_socket 发送与接收数据(不经过timedict 保存数据)
                socket_ = self.__command_socket
            case _:
                raise ValueError('SocketSession: 得到的Socket不支持现有的任何发送方法')

        # if self.__aes_ctr:
        #     if len(command) > 1008:
        #         raise ValueError('sendCommandNoTimeDict: 指令发送时大于1008个字节')
        #
        #     data = self.__aes_ctr.aes_ctr_encrypt(self.mark + command)
        # else:
        #     if len(command) > 1016:
        #         raise ValueError('sendCommandNoTimeDict: 指令发送时大于1016个字节')
        #     data = (HashTools.getRandomStr(8) + command).encode('utf-8')

        if self.__aes_ctr:
            if len(command) > 4056:  # 8mark + 16nonce + 16tag = 40head
                raise ValueError('_sendNoTimeDict: 指令发送时大于1008个字节')
            elif len(command) < 40:
                raise ValueError('_sendNoTimeDict: 指令发送时无字节')
            data = self.__aes_ctr.aes_gcm_encrypt(HashTools.getRandomStr(8) + command)
        else:
            if len(command) > 4088:
                raise ValueError('_sendNoTimeDict: 指令发送时大于1016个字节')
            elif len(command) < 40:
                raise ValueError('_sendNoTimeDict: 指令发送时无字节')
            data = (HashTools.getRandomStr(8) + command).encode('utf-8')

        if output:
            try:
                socket_.send(data)
            except OSError as e:
                logging.debug(e)
                raise TimeoutError('SendTimeout')
            try:
                data = socket_.recv(4096)
            except OSError as e:
                logging.debug(e)
                raise TimeoutError('RecvTimeout')

            if not data:
                raise ValueError('RecvError')
            return data.decode('utf-8')
        else:
            socket_.send(data)

    def _sendTimeDict(self, socket_: socket, command: dict, output: bool = True) -> str:
        """
        发送指令并准确接收返回数据

        例： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。

        1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
        2. 在发送指令的前方追加[答复ID]，编码发送。
        3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。

        :param output: 设置是否等待接下来的返回值。
        :param socket_: 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
        :param command: 设置发送的指令, 如果为字典类型则转换为json发送。
        :return: 如果Output=True在发送数据后等待对方返回一条数据; 否则仅发送
        """

        self.__timedict.createRecv(self.mark)

        try:
            command = json.dumps(command)
        except Exception as e:
            print(e)
            return ''

        if self.__aes_ctr:
            if len(command) > 4056:  # 8mark + 16nonce + 16tag = 40head
                raise ValueError('_sendTimeDict: 指令发送时大于1008个字节')
            elif len(command) < 40:
                raise ValueError('_sendTimeDict: 指令发送时无字节')
            data = self.__aes_ctr.aes_gcm_encrypt(self.mark + command)
        else:
            if len(command) > 4088:
                raise ValueError('_sendTimeDict: 指令发送时大于1016个字节')
            elif len(command) < 40:
                raise ValueError('_sendTimeDict: 指令发送时无字节')
            data = (HashTools.getRandomStr(8) + command).encode('utf-8')

        if output:
            try:
                socket_.send(data)
            except OSError as e:
                logging.debug(e)
                raise TimeoutError('SendTimeout')
            if self.__aes_ctr:
                getRecv = self.__timedict.getRecvData(self.mark)
            else:
                getRecv = self.__timedict.getRecvData(self.mark)
            if not getRecv:
                raise ValueError('getRecvTimeout')
            return getRecv.decode('utf-8')
        else:
            try:
                socket_.send(data)
            except OSError as e:
                logging.debug(e)
                raise TimeoutError('SendTimeout')
            return ''

    # @staticmethod
    # def verifySendData(src_data: str or bytes, aes_ctr: CryptoTools) -> bytes:
    #     if aes_ctr:
    #         if len(src_data) > 4056:  # 8mark + 16nonce + 16tag = 40head
    #             raise ValueError('sendCommandNoTimeDict: 指令发送时大于1008个字节')
    #         elif len(src_data) < 40:
    #             raise ValueError('sendCommandNoTimeDict: 指令发送时无字节')
    #         data = aes_ctr.aes_gcm_encrypt(HashTools.getRandomStr(8) + src_data)
    #     else:
    #         if len(src_data) > 4088:
    #             raise ValueError('sendCommandNoTimeDict: 指令发送时大于1016个字节')
    #         elif len(src_data) < 40:
    #             raise ValueError('sendCommandNoTimeDict: 指令发送时无字节')
    #         data = (HashTools.getRandomStr(8) + src_data).encode('utf-8')
    #     return data

    def __enter__(self):
        return self

    def __exit__(self):
        # 清理会话
        if self.__timedict:
            self.__command_socket.settimeout(4)
            self.__data_socket.settimeout(4)
        self.__timedict.delKey(self.mark)


if __name__ == '__main__':
    # timedict = TimeDict()
    # timedict.set('a', 10)
    # time.sleep(10)
    # print(timedict.get('a'))
    # print(HashTools.getRandomStr())
    # with SocketSession(None, None, None, 1) as session:
    #     session.send({})
    # print(session)
    print(HashTools.getFileSHA265('d:\\demo.jpg'))
