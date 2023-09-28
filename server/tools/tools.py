import concurrent.futures
import logging
import os
import random
import string
import threading
import time
import uuid

import xxhash

from server.config import readConfig
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
    def getFileHash(path, block=65536):
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
    def getFileHash_32(path, block=65536):
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

    def hasKey(self, key):
        with self.lock:
            if key in self.dict:
                result = True
            else:
                result = False
            return result

    def close(self):
        self.close_flag = True

    def __release(self):
        """周期性扫描过期键值对并删除"""
        while True:
            if self.close_flag:
                return
            time.sleep(self.scan)
            keys_to_delete = []
            with self.lock:
                for key, value in self.dict.items():
                    if time.time() - value[-1] > self.release_time:
                        keys_to_delete.append(key)
                for key in keys_to_delete:
                    del self.dict[key]


class TimeDictInit:
    """
    数据/指令持续接收，并分流
    """

    def __init__(self, data_socket, command_socket):
        self.data_socket = data_socket
        self.command_socket = command_socket
        self.close = False
        self.timedict = TimeDict()

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
            if self.close:
                self.timedict.close()
                return
            else:
                result = self.data_socket.recv(1024)
                try:
                    mark, data = result[:8], result[8:]
                    if self.timedict.hasKey(mark):
                        self.timedict.set(mark, data)
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
        return self.timedict.get(mark, pop=True)

    def createRecv(self, mark):
        """创建一个数据流接收队列"""
        self.timedict.set(mark)

    def closeRecv(self):
        """销毁所有数据"""
        self.close = True


class SocketTools:
    """工具包：发送指令，接收指令"""

    def __init__(self):
        super().__init__()

    @staticmethod
    def sendCommand(timedict, socket_, command, output=True, timeout=2, mark=None):
        """
        发送指令并准确接收返回数据

        例子： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。
         timedict : 首先客户端设置timedict的值作为自身接收数据暂存区。
         socket_ : 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
         command : 设置发送的指令。
         output : 设置是否等待接下来的返回值。
         timeout : 默认超时时间，如果超过则返回DATA_RECEIVE_TIMEOUT。
         mark : 本次答复所用的标识（主动发起请求的一方默认为None，会自动生成一个8长度的字符串作为答复ID）

        1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
        2. 在发送指令的前方追加[答复ID]，编码发送。
        3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。

        :param mark:
        :param timedict:
        :param timeout:
        :param output:
        :param socket_:
        :param command:
        :return:
        """
        if not mark:
            mark = HashTools.getRandomStr(8)
        timedict.createRecv(mark)
        try:
            socket_encode = readConfig.readJson()['server']['addr']['encode']
        except Exception as e:
            raise KeyError('读取Config时错误：', e)
        if output:
            try:
                socket_.send((mark + command).encode(socket_encode))
                with concurrent.futures.ThreadPoolExecutor() as excutor:
                    future = excutor.submit(timedict.getRecvData(mark).decode(socket_encode))
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

    @staticmethod
    def sendCommandNoTimeDict(socket_, command, output=True, timeout=2):
        """
        取消使用TimeDict收发数据
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
            command_ = command.split(':')
            try:
                socket_.send(command.encode(socket_encode))
                with concurrent.futures.ThreadPoolExecutor() as excutor:
                    future = excutor.submit(socket_.recv(command_.decode(socket_encode)))
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


if __name__ == '__main__':
    # timedict = TimeDict()
    # timedict.set('a', 10)
    # time.sleep(10)
    # print(timedict.get('a'))
    print(HashTools.getRandomStr())
