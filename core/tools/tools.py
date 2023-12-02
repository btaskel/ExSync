import concurrent.futures
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


def createFile(file_path: str, content: str) -> bool:
    """
    快速创建文件
    :param file_path: 文件路径
    :param content: 文件内容
    :return:
    """
    if not os.path.exists(file_path):
        with open(file_path, mode='w', encoding='utf-8') as f:
            f.write(content)
        return True
    else:
        return False


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
            data = CryptoTools(encrypt_password).aes_ctr_encrypt(data)
            if not data:
                raise ValueError('sendCommand: 发送时加密失败')
        else:
            data = data.encode('utf-8')
        if len(data) > 1024:
            raise ValueError(f'发送命令时超过1K bytes: {mark_value + command}')

        if not output:
            try:
                socket_.send(data)
                if not mark:
                    return mark_value
            except Exception as e:
                raise TimeoutError('Socket错误: ', e)
            return ''

        socket_.send(data)
        with concurrent.futures.ThreadPoolExecutor() as excutor:
            if encrypt_password:
                getRecv = timedict.getRecvData(mark_value)
            else:
                getRecv = timedict.getRecvData(mark_value)
            future = excutor.submit(getRecv.decode('utf-8'))
            try:
                # 没有超时2000ms则返回接收值
                result = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                # 超时返回错误
                return Status.DATA_RECEIVE_TIMEOUT.value
            return result

    @staticmethod
    def sendCommandNoTimeDict(socket_: socket, command: dict, output: bool = True, timeout: int = 2,
                              encrypt_password: str = None) -> str:
        """
        取消使用TimeDict收发数据, 用于非异步数据传输. 如无必要建议使用sendCommand()

        :param encrypt_password: 如果此项填写, 则发送数据时会对数据进行加密, 否则为明文(安全的局域网下可以不填写以提高传输性能)。
        :param timeout: 默认超时时间，如果超过则返回DATA_RECEIVE_TIMEOUT。
        :param output: 如果 output = True 则sendCommand()将会等待一个返回值，默认超时2s。设置是否等待接下来的返回值。
        :param socket_: 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
        :param command: 设置发送的指令。
        :return:
        """
        try:
            command = json.dumps(command)
        except ValueError as e:
            print(e)
            raise ValueError('sendCommandNoTimeDict: 格式化指令时失败')

        if not output:
            socket_.send(command.encode('utf-8'))
        if encrypt_password:
            if len(command) > 1008:
                raise ValueError('sendCommandNoTimeDict: 指令发送时大于1008个字节')

            data = CryptoTools(encrypt_password).aes_ctr_encrypt(HashTools.getRandomStr(8) + command)
        else:
            if len(command) > 1016:
                raise ValueError('sendCommandNoTimeDict: 指令发送时大于1016个字节')
            data = (HashTools.getRandomStr(8) + command).encode('utf-8')

        socket_.send(data)
        with concurrent.futures.ThreadPoolExecutor() as excutor:
            data = socket_.recv(1024)
            if len(data) <= 8:
                raise ValueError('sendCommandNoTimeDict: 获取的data数据少于8个字节，无法分离出mark与数据内容')
            data = data[8:]
            if encrypt_password:
                future = excutor.submit(CryptoTools(encrypt_password).aes_ctr_decrypt(data))
            else:
                future = excutor.submit(data)
            try:
                # 没有超时2000ms则返回接收值
                result = future.result(timeout=timeout)
                return result
            except concurrent.futures.TimeoutError:
                # 超时返回错误
                return Status.DATA_RECEIVE_TIMEOUT.value


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
        mark_value = str(mark)
        if not mark_value or len(mark_value) != 8:
            while True:
                characters = string.ascii_letters + '1234567890'
                mark_value = "".join(random.sample(characters, 8))
                if self.timedict.hasKey(mark_value):
                    continue
                else:
                    break

        self.timedict.createRecv(mark_value)

        try:
            command = json.dumps(command)
        except ValueError as e:
            print(e)
            return ''
        data = mark_value + command

        if encrypt:
            try:
                data = CryptoTools(self.key).aes_ctr_encrypt(data)
            except Exception as e:
                print(e)
                return
        else:
            data = data.encode('utf-8')
        if len(data) > 1024:
            raise ValueError(f'发送命令时超过1K bytes: {mark_value + command}')

        if not output:
            socket_.send(data)
            if not mark:
                return mark_value

        try:
            socket_.send(data)
            with concurrent.futures.ThreadPoolExecutor() as excutor:
                future = excutor.submit(self.timedict.getRecvData(mark_value).decode('utf-8'))
                try:
                    # 没有超时2000ms则返回接收值
                    result = future.result(timeout=timeout)
                    if not mark:
                        return mark_value, result
                    return result
                except concurrent.futures.TimeoutError:
                    # 超时返回错误
                    return Status.DATA_RECEIVE_TIMEOUT
        except Exception as e:
            print(e)
            return Status.UNKNOWN_ERROR


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
                 mark: str = None, timeout: int = 2, encrypt_password: str = None):
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
        self.__timeout: int = timeout
        self.__aes_ctr: CryptoTools = CryptoTools(encrypt_password)
        self.mark: str = mark
        self.count: int = 0

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

        if not self.mark:
            while True:
                characters = string.ascii_letters + '1234567890'
                self.mark = "".join(random.sample(characters, 8))
                if timedict.hasKey(self.mark):
                    continue
                else:
                    break

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
        if self.__timedict:
            return self._send_TimeDict(message, output)
        return self._send_NoTimeDict(message, output)

    def _send_TimeDict(self, message: dict or bytes, output: bool = True) -> str:
        if isinstance(message, bytes):
            self._sendData(self.__data_socket, message, mark=self.mark)
            return ''

        match self.method:
            case 0:
                # 从command_socket 发送指令(此后的所有数据从data_socket发送和接收)
                _socket = self.__command_socket if not self.count else self.__data_socket
                if output:
                    return self._sendCommand(socket_=_socket, command=message, output=output, timeout=self.__timeout)
                else:
                    self._sendCommand(socket_=_socket, command=message, output=output, timeout=self.__timeout)

            case 1:
                # 从data_socket发送与接收数据(经过timedict标识收发)
                if output:
                    return self._sendCommand(socket_=self.__data_socket, command=message, output=output,
                                             timeout=self.__timeout)
                else:
                    self._sendCommand(socket_=self.__data_socket, command=message, output=output,
                                      timeout=self.__timeout)

            case 2:
                # 从command_socket 发送与接收数据(不经过timedict 保存数据)
                if output:
                    return self.sendCommandNoTimeDict(self.__command_socket, message, output, timeout=self.__timeout)
                else:
                    self.sendCommandNoTimeDict(self.__command_socket, message, output, timeout=self.__timeout)

        self.count += 1

    def _sendData(self, data_socket: socket, data: bytes or str, mark: str):
        """

        :param data_socket: Data socket
        :param data: 数据流
        :param mark: 数据标识
        :return:
        """
        # 检查形参
        if not mark:
            raise ValueError('sendData: 没有传入mark值')

        if isinstance(data, bytes):
            data = bytes(mark, 'utf-8') + data
        elif isinstance(data, str):
            data = (mark + data).encode('utf-8')
        else:
            raise TypeError('sendData: 无法识别发送的数据类型！')
        if not mark:
            raise ValueError('sendData: 没有Mark！')

        # 是否加密
        if self.__aes_ctr:
            data = self.__aes_ctr.aes_ctr_encrypt(data)
            data_socket.send(data)
            return
        else:
            data_socket.send(data)

    def _send_NoTimeDict(self, message: dict or bytes, output: bool = True) -> str:
        """
        取消使用TimeDict收发数据, 用于非异步数据传输. 如无必要建议使用sendCommand()

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

        if self.__aes_ctr:
            if len(command) > 1008:
                raise ValueError('sendCommandNoTimeDict: 指令发送时大于1008个字节')

            data = self.__aes_ctr.aes_ctr_encrypt(self.mark + command)
        else:
            if len(command) > 1016:
                raise ValueError('sendCommandNoTimeDict: 指令发送时大于1016个字节')
            data = (HashTools.getRandomStr(8) + command).encode('utf-8')

        socket_.send(data)

        if output:
            try:
                with concurrent.futures.ThreadPoolExecutor() as excutor:
                    future = excutor.submit(socket_.recv(1024))
                    try:
                        # 没有超时2000ms则返回接收值
                        result = future.result(timeout=self.__timeout)
                        return result
                    except concurrent.futures.TimeoutError:
                        # 超时返回错误
                        return Status.DATA_RECEIVE_TIMEOUT.value
            except Exception as e:
                print(e)
                return ''

    def _sendCommand(self, socket_: socket, command: dict, output: bool = True, timeout: int = 2) -> str:
        """
        发送指令并准确接收返回数据

        例： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。

        1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
        2. 在发送指令的前方追加[答复ID]，编码发送。
        3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。

        :param timeout: 默认超时时间，如果超过则返回DATA_RECEIVE_TIMEOUT。
        :param output: 设置是否等待接下来的返回值。
        :param socket_: 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
        :param command: 设置发送的指令, 如果为字典类型则转换为json发送。
        :return: 如果Output=True在发送数据后等待对方返回一条数据; 否则仅发送
        """

        if not self.mark or len(self.mark) != 8:
            while True:
                characters = string.ascii_letters + '1234567890'
                mark_value = "".join(random.sample(characters, 8))
                if self.__timedict.hasKey(mark_value):
                    continue
                else:
                    break

        self.__timedict.createRecv(self.mark)

        try:
            command = json.dumps(command)
        except ValueError as e:
            print(e)
            return ''
        data = self.mark + command

        if self.__aes_ctr:
            data = self.__aes_ctr.aes_ctr_encrypt(data)
            if not data:
                raise ValueError('sendCommand: 发送时加密失败')
        else:
            data = data.encode('utf-8')
        if len(data) > 1024:
            raise ValueError(f'发送命令时超过1K bytes: {self.mark + command}')

        if not output:
            socket_.send(data)
            if not self.mark:
                return self.mark

        socket_.send(data)
        with concurrent.futures.ThreadPoolExecutor() as excutor:
            if self.__aes_ctr:
                getRecv = self.__timedict.getRecvData(self.mark)
            else:
                getRecv = self.__timedict.getRecvData(self.mark)
            future = excutor.submit(getRecv.decode('utf-8'))
            try:
                # 没有超时2000ms则返回接收值
                result = future.result(timeout=timeout)
            except concurrent.futures.TimeoutError:
                # 超时返回错误
                return Status.DATA_RECEIVE_TIMEOUT.value
            return result

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
    # with SocketSession(None, None, None, 1) as session:
    #     session.send({})
    # print(session)
    print(HashTools.getFileHash('d:\\CDR2019.zip'))
