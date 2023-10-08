import random
import string
import threading
import time


class TimeDict:
    """
    可以理解为一个小型的redis
    默认情况下每次扫描间隔(scan)是4秒，如果有元素存在(release)超过4秒则予以删除
    TimeDict : 在客户端/服务端分别运作一个timedict实例，timedict会一直接收来自dataSocket的数据，并默认保存到自身4秒（超时则遍历删除）。
    """

    def __init__(self, release=4, scan=4):
        self.dict = {}
        self.lock = threading.Lock()
        try:
            self.release_time = int(release)
            self.scan = float(scan)
        except Exception as e:
            print(e)
            self.release_time = 4
            self.scan = 4

        self.close_flag = False
        thread = threading.Thread(target=self.__release)
        thread.start()

    def set(self, key, value=None):
        """设置键值对"""
        with self.lock:
            if key in self.dict:
                self.dict[key].insert(-1, value)
                self.dict[key][-1] = time.time()
            elif key in self.dict and value is not None:
                self.dict[key] = [value, time.time()]
            else:
                self.dict[key] = [time.time()]

    def get(self, key, pop=True, timeout=2):
        """
        获取键值对
        如果pop=True则获取完元素立即弹出该元素(如果元素内容被读取完毕，则返回False)
        如果无法获取到则会阻塞到有数据再继续返回, 如果超过2000ms则解除阻塞
        """
        with self.lock:
            if pop:
                tic = time.time()
                while True:
                    if time.time() - tic > timeout:
                        return
                    result = self.dict[key]
                    if len(result) > 1:
                        return result.pop(0)
                    time.sleep(0.002)
            else:
                return self.dict.get(key, False)[0:-1]

    def delKey(self, key):
        """删除键"""
        return self.dict.pop(key)

    def hasKey(self, key):
        """判断键是否已经存在"""
        with self.lock:
            if key in self.dict:
                return True
            else:
                return False

    def close(self):
        self.close_flag = True

    def __release(self):
        """周期性扫描过期键值对并删除"""
        while True:
            if self.close_flag:
                del self.dict
                return
            time.sleep(self.scan)
            keys_to_delete = []
            with self.lock:
                for key, value in self.dict.items():
                    if time.time() - value[-1] > self.release_time:
                        keys_to_delete.append(key)
                for key in keys_to_delete:
                    self.dict.pop(key)


class TimeDictInit(TimeDict):
    """
    数据/指令持续接收，并分流
    """

    def __init__(self, data_socket, command_socket):
        super().__init__()
        self.data_socket = data_socket
        self.command_socket = command_socket
        self.close_all = False

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
        """

        while True:
            if self.close_all:
                self.close()
                return
            else:
                result = self.data_socket.recv(1024)
                try:
                    mark, data = result[:8], result[8:]
                    if self.hasKey(mark):
                        self.set(mark, data)
                except:
                    pass

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

    def getRecvData(self, mark):
        """取出指定mark队列第一个值，并且将其弹出"""
        return self.get(mark, pop=True)

    def createRecv(self, mark):
        """创建一个数据流接收队列"""
        self.set(mark)

    def closeRecv(self):
        """销毁所有数据并停止持续接收数据"""
        self.close_all = True


class TimeDictTools:
    """
    TimeDict的操作封装工具
    """

    def __init__(self, timedict):
        self.timedict = timedict

    def getMark(self, length=8):
        """
        随机获取N个 26个大小写字母，并检查是否已经在timedict中存在
        用于减少数据传输分流误差
        默认: 8位
        """
        while True:
            characters = string.ascii_letters + '1234567890'
            mark = "".join(random.sample(characters, length))
            if self.timedict.hasKey(mark):
                continue
            else:
                return mark
