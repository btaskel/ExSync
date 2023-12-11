import random
import string
import threading
import time
from socket import socket

from core.tools.encryption import CryptoTools


class TimeDict:
    """
    可以理解为一个小型的redis
    默认情况下每次扫描间隔(scan)是4秒，如果有元素存在(release)超过4秒则予以删除
    TimeDict : 在客户端/服务端分别运作一个timedict实例，timedict会一直接收来自dataSocket的数据，并默认保存到自身4秒（超时则遍历删除）。
    """

    def __init__(self, release: int = 4, scan: int = 4):
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)

        """
        TimeDict存储字典
        """
        self.__dict: dict = {}

        """
        最大存活时间
        """
        self.release_time: int = int(release)

        """
        关闭标志
        """
        self.close_flag: bool = False

        """
        间隔时间：周期性扫描删除过期键值对
        """
        self.scan: float = float(scan)

        """
        启动周期扫描线程
        """
        thread = threading.Thread(target=self.__release)
        thread.start()

    def set(self, key: str, value: bytes = None):
        """
        设置键值对
        :param value: 值
        :param key: 键
        :return:
        """
        with self.lock:
            mark_ls: list = self.__dict[key]
            if key in self.__dict:
                # 每一队列最多(1024 * 65535)
                if len(mark_ls) < 65535:
                    mark_ls.append(value)
                    mark_ls[0] = time.time()
            else:
                self.__dict[key] = [time.time()]
            self.condition.notify_all()

    def get(self, key: str, pop: bool = True, timeout: int = 2) -> bytes:
        """
        获取键值对
        结构：[数据流修改时间刻, 数据流...]
        :param key: 获取的键
        :param pop: 是否弹出数据流
        :param timeout: 超时时间, 如果无法获取到则会阻塞到有数据再继续返回, 如果超过2000ms则解除阻塞
        :return:
        """
        with self.lock:
            if not pop:
                if len(self.__dict[key]) > 2:
                    return self.__dict.get(key)[1]
                else:
                    return b''
            else:
                result = self.__dict[key]
                while len(result) <= 2:
                    if not self.condition.wait(timeout):
                        return b''
                return result.pop(1)

    def delKey(self, key: str):
        """
        删除键
        :param key: 要删除的键
        :return:
        """
        with self.lock:
            self.__dict.pop(key)

    def hasKey(self, key: str) -> bool:
        """
        判断键是否已经存在
        :param key:
        :return:
        """
        with self.lock:
            if key in self.__dict:
                return True
            else:
                return False

    def close(self):
        with self.lock:
            self.close_flag = True
            self.condition.notify_all()

    def __release(self):
        """
        周期性扫描过期键值对并删除
        :return:
        """
        while True:
            with self.lock:
                # 如果关闭标志被设置，删除字典并返回
                if self.close_flag:
                    del self.__dict
                    return

                # 创建一个空列表来存储要删除的键
                keys_to_delete = []

                # 遍历字典中的每一个键值对
                for key, value in self.__dict.items():
                    # 获取值中的时间戳
                    time_stamp = value[0]

                    # 如果当前时间与时间戳的差大于释放时间，将键添加到要删除的键的列表中
                    if time.time() - time_stamp > self.release_time:
                        keys_to_delete.append(key)

                # 遍历要删除的键的列表，从字典中删除这些键
                for key in keys_to_delete:
                    self.__dict.pop(key)

            # 等待一段时间再进行下一次扫描
            time.sleep(self.scan)


class TimeDictInit(TimeDict):
    """
    数据/指令持续接收，并分流

    closeRecv : 关闭当前看客户端与服务端的timedict
    enableEncry : 开启当前服务端timedict的即时解密
    disableEncry : 关闭当前服务端timedict即时解密
    """

    def __init__(self, data_socket: socket, command_socket: socket, key: str):
        super().__init__()
        self.data_socket = data_socket
        self.command_socket = command_socket
        self.key: str = key
        self.close_all: bool = False
        self.encry: bool = False

        # 启动数据接收线程
        threads = [self._recvData]
        for thread in threads:
            t = threading.Thread(target=thread)
            t.start()

    def _recvData(self):
        """

        持续接收数据等待接下来的方法处理数据，同时遵循TimeDict的元素生命周期
        以mark头来区分数据流，如果接收到发现数据流的标识不存在则丢弃数据流
        EXSync的mark头为数据流的前8位

        :return:
        """
        crypto = CryptoTools(self.key)
        while True:
            if not self.close_all:
                result: bytes = self.data_socket.recv(1024)
                # 确保接收到的数据有效
                if len(result) <= 16:
                    continue
                # 分流数据内容
                decrypt_data = crypto.aes_ctr_decrypt(result)
                if decrypt_data:
                    result = decrypt_data

                mark: str = result[:8].decode('utf-8')
                data: bytes = result[8:]

                if self.hasKey(mark):
                    self.set(mark, data)
            else:
                self.close()
                return

    def getMark(self, length: int = 8) -> str:
        """
        随机获取N个 26个大小写字母，并检查是否已经在timedict中存在
        用于减少数据传输分流误差
        :param length: 字符串长度（默认8位）
        :return: mark
        """
        while True:
            characters = string.ascii_letters + '1234567890'
            mark = "".join(random.sample(characters, length))
            if not self.hasKey(mark):
                return mark

    def getRecvData(self, mark: str, timeout: int = 2) -> bytes:
        """
        :param timeout: 超时时间
        :param mark: 取出指定mark队列第一个值，并且将其弹出
        :return:
        """
        return self.get(mark, pop=True, timeout=timeout)

    def createRecv(self, mark: str):
        """
        'aes-128-ctr'
        创建一个数据流接收队列
        :param mark: mark头
        :return:
        """
        if 4 < len(mark) < 8:
            self.set(mark)
        else:
            raise ValueError(f'Mark: {mark} set error!!')

    def closeRecv(self):
        """
        销毁所有数据并停止持续接收数据
        :return:
        """
        self.close_all = True
