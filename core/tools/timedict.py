import logging
import random
import string
import threading
import time

from core.tools.encryption import CryptoTools


class TimeDict:
    """
    可以理解为一个小型的redis
    默认情况下每次扫描间隔(scan)是4秒，如果有元素存在(release)超过4秒则予以删除
    TimeDict : 在客户端/服务端分别运作一个timedict实例，timedict会一直接收来自dataSocket的数据，并默认保存到自身4秒（超时则遍历删除）。
    """

    def __init__(self, release: int = 4, scan: int = 4):
        self.__dict: dict = {}
        self.lock = threading.Lock()
        try:
            self.release_time: int = int(release)
            self.scan: float = float(scan)
        except Exception as e:
            print(e)
            self.release_time: int = 4
            self.scan: int = 4

        self.close_flag: bool = False
        thread = threading.Thread(target=self.__release)
        thread.start()

    def set(self, key: str, value: bytes = None, encryption: str = None):
        """
        设置键值对
        :param value: 值
        :param key: 键
        :param encryption: 加密方式
        :return:
        """
        with self.lock:
            if key in self.__dict:
                # raise KeyError(f'timedict: 增加mark {key} 失败！')
                self.__dict[key].append(value)
                self.__dict[key][0] = time.time()
            else:
                self.__dict[key] = [time.time(), encryption]

    def get(self, key: str, pop: bool = True, timeout: int = 2) -> bytes:
        """
        获取键值对
        如果pop=True则获取完元素立即弹出该元素(如果元素内容被读取完毕，则返回False)
        如果无法获取到则会阻塞到有数据再继续返回, 如果超过2000ms则解除阻塞
        结构：[数据流修改时间刻, 加密方式, 数据流...]
        :param key: 获取的键
        :param pop: 是否弹出数据流
        :param timeout: 超时时间
        :return:
        """
        with self.lock:
            if not pop:
                if len(self.__dict[key]) > 2:
                    return self.__dict.get(key)[2:]
                else:
                    return b''
            tic = time.time()
            while True:
                result = self.__dict[key]
                if len(result) > 2:
                    return result.pop(2)
                time.sleep(0.0005)
                if time.time() - tic > timeout:
                    return b''

    def getCryType(self, mark: str) -> str:
        """
        获取数据流的加密类型
        :param mark:要获取的键
        :return:
        """
        if self.hasKey(mark):
            return self.__dict.get(mark)[1]
        return ''

    def delKey(self, key: str):
        """
        删除键
        :param key: 要删除的键
        :return:
        """
        self.__dict.pop(key)

    def hasKey(self, key: str) -> bool:
        """判断键是否已经存在"""
        with self.lock:
            if key in self.__dict:
                return True
            else:
                return False

    def close(self):
        self.close_flag = True

    def __release(self):
        """周期性扫描过期键值对并删除"""
        while True:
            if self.close_flag:
                del self.__dict
                return
            time.sleep(self.scan)
            keys_to_delete = []
            with self.lock:
                for key, value in self.__dict.items():
                    try:
                        if time.time() - value[0] > self.release_time:
                            keys_to_delete.append(key)
                    except Exception as e:
                        print(e)
                        logging.warning(f'TimeDict: release key {key} error!')
                for key in keys_to_delete:
                    self.__dict.pop(key)


class TimeDictInit(TimeDict):
    """
    数据/指令持续接收，并分流

    closeRecv : 关闭当前看客户端与服务端的timedict
    enableEncry : 开启当前服务端timedict的即时解密
    disableEncry : 关闭当前服务端timedict即时解密
    """

    def __init__(self, data_socket, command_socket, key: str):
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

        如果在开启加密时, 发送方累计超过十次发送无效数据, 则停止接收数据
        :return:
        """
        count: int = 0
        crypto = CryptoTools(self.key)
        while True:
            if not self.close_all:
                result = self.data_socket.recv(1024)
                # 确保接收到的数据有效
                if len(result) <= 16:
                    continue
                try:
                    # 分流数据内容
                    try:
                        result = crypto.aes_ctr_decrypt(result)
                    except ValueError:
                        pass
                    try:
                        mark: str = result[:8].decode('utf-8')
                    except ValueError:
                        continue
                    data: bytes = result[8:]

                    if self.hasKey(mark):
                        self.set(mark, data)
                except Exception as e:
                    print(e)
                    count += 1
                    if count >= 20:
                        # 获取到20次的, 连续的未知数据, 断开连接
                        self.close_all = True
            else:
                self.close()
                return

    # def _recvCommand(self):
    #     """
    #     接收远程指令
    #     持续接收数据等待接下来的方法处理指令，同时遵循TimeDict的元素生命周期
    #     以mark头来区分数据流，如果接收到发现数据流的标识不存在则丢弃数据流
    #     EXSync的mark头为数据流的前8位
    #     """
    #
    #     while True:
    #         if self.close:
    #             self.timedict.close()
    #             return
    #         else:
    #             result = self.command_socket.recv(1024)
    #             try:
    #                 mark, data = result[:8], result[8:]
    #                 if self.timedict.hasKey(mark):
    #                     self.timedict.set(mark, data)
    #             except:
    #                 pass

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
        # if decrypt_password and self.getCryType(mark) == 'aes-128-ctr':
        #     try:
        #         result = CryptoTools(decrypt_password).aes_ctr_decrypt(result)
        #     except Exception as e:
        #         print(e)
        #         return
        #     return result
        # else:
        #     return result

    # def getCommand(self, mark: str, decrypt_password: str = None) -> dict:
    #     """
    #     :param mark: 取出指定mark队列第一个值，并且将其弹出
    #     :param decrypt_password: 如果此项填写，则取出时将进行解密
    #     :return:
    #     """
    #     result = self.get(mark, pop=True)
    #     if decrypt_password and self.getCryType(mark) == 'aes-128-ctr':
    #         try:
    #             result = CryptoTools(decrypt_password).aes_ctr_decrypt(result)
    #         except Exception as e:
    #             print(e)
    #             return
    #         result = result
    #     return json.loads(result)

    def createRecv(self, mark: str, encryption: str = None):
        """
        'aes-128-ctr'
        创建一个数据流接收队列
        :param mark: mark头
        :param encryption: 密钥
        :return:
        """
        if 4 < len(mark) < 8:
            self.set(mark, encryption=encryption)
        else:
            raise ValueError(f'Mark: {mark} set error!!')

    def closeRecv(self):
        """销毁所有数据并停止持续接收数据"""
        self.close_all = True
