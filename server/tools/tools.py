import concurrent.futures
import os
import random
import string
import time

import xxhash

from server.config import readConfig
from server.tools.status import Status


def createFile(files_path, content):
    """快速创建文件"""
    if not os.path.exists(files_path):
        with open(files_path, mode='w', encoding='utf-8') as f:
            f.write(content)


class HashTools:
    @staticmethod
    def getFileHash(path, block=65536):
        """获取文件的128 xxhash值"""

        hasher = xxhash.xxh3_128()

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

        characters = string.ascii_letters
        return "".join(random.sample(characters, number))


class SocketTools:
    """工具包：发送指令，接收指令"""

    def __init__(self):
        self.flag = False

    @staticmethod
    def recv(socket_, command_, socket_encode):
        """等待接收指令,指令会进行格式验证,通过则返回值"""
        while True:
            result = socket_.recv(1024).decode(socket_encode).split(':')
            # 命令收发验证
            if result[1] == command_[1] and result[2] == command_[2] and result[3] == 'post' and \
                    result[4].split('|')[0] == command_[4].split('|')[0]:
                return result[4].split('|')[1]

    @staticmethod
    def sendCommand(socket_, command, output=True, timeout=2):
        """
        发送指令: 例如”/_com:comm:sync:get:password_hash|local_hash:_“
        返回值：对方密码哈希值
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
                    future = excutor.submit(SocketTools.recv(socket_, command_, socket_encode))
                    try:
                        # 没有超时2000ms则返回接收值
                        result = future.result(timeout=timeout)
                        return result
                    except concurrent.futures.TimeoutError:
                        # 超时返回错误
                        return Status.DATA_RECEIVE_TIMEOUT

            except Exception as e:
                raise TimeoutError('Socket错误：', e)

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
