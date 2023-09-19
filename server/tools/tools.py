import concurrent.futures
import logging
import os
import random
import string
import threading
import time

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

    持续接收数据等待接下来的方法处理数据，同时遵循TimeDict的元素生命周期
    以mark头来区分数据流，如果接收到发现数据流的标识不存在则丢弃数据流
    EXSync的mark头为数据流的前8位
    """

    def __init__(self, data_socket, command_socket):
        self.data_socket = data_socket
        self.command_socket = command_socket
        self.close = False
        self.timedict = TimeDict()

        threads = [self._recvCommand, self._recvData]
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

    # @staticmethod
    # def recv(socket_, command_, socket_encode):
    #     """等待接收指令,指令会进行格式验证,通过则返回值"""
    #     while True:
    #         result = socket_.recv(1024).decode(socket_encode).split(':')
    #         # 命令收发验证
    #         if result[1] == command_[1] and result[2] == command_[2] and result[3] == 'post' and \
    #                 result[4].split('|')[0] == command_[4].split('|')[0]:
    #             return result[4].split('|')[1]

    @staticmethod
    def sendCommand(timedict, socket_, command, output=True, timeout=2, mark=None):
        """
        发送指令: 例如”/_com:comm:sync:get:password_hash|local_hash:_“
        返回值：对方密码哈希值
        如果 output = True 则sendCommand()将会等待一个返回值，默认超时2s。

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
                    future = excutor.submit(timedict.getRecvData(mark))
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

    @staticmethod
    def replyCommand(value, global_vars, filemark, sleep=0.1):
        """
        等待指定次数的答复内容
        value: 第value次答复次数的内容
        global_vars: 答复存储的字典
        filemark: 标识头
        返回：
        """
        count = global_vars[filemark]['count']
        result = None
        if count < value:
            while count < value:
                time.sleep(sleep)
                result = global_vars[filemark]
        elif count == value:
            result = global_vars[filemark]
        else:
            return Status.REPLY_ERROR
        return result


if __name__ == '__main__':
    # timedict = TimeDict()
    # timedict.set('a', 10)
    # time.sleep(10)
    # print(timedict.get('a'))
    print(HashTools.getRandomStr())
