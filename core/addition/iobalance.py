import os
import threading
import time

import psutil

from core.tools import HashTools


class IOBalance:
    """
    IO均衡器：当磁盘资源空闲时会执行一些指定函数
    """

    @staticmethod
    def balance(func, args=(), kwargs=None, t: int = 600, value: int = 10485760):
        """
        硬盘负载均衡：在硬盘闲置下来后会执行传入的函数
        :param kwargs:
        :param args: 函数所需的形参
        :param func: 当硬盘空闲时所执行的函数
        :param t: 间隔 t 秒执行函数
        :param value: 在硬盘空闲 time 秒内，有 value 个字节没有写入/读取时，执行函数
        :return:
        """

        if kwargs is None:
            kwargs = {}

        def task():
            while True:
                read_threshold = value
                write_threshold = value
                initial_disk_io = psutil.disk_io_counters()
                time.sleep(t)
                current_disk_io = psutil.disk_io_counters()
                read_bytes = current_disk_io.read_bytes - initial_disk_io.read_bytes
                write_bytes = current_disk_io.write_bytes - initial_disk_io.write_bytes
                if read_bytes < read_threshold and write_bytes < write_threshold:
                    func(*args, **kwargs)

        thread = threading.Thread(target=task, )
        thread.start()


class AutoDisk:
    """
    通过多次使用记录分析当前硬盘的读写速度/读写延迟并记录
    """

    def __init__(self, config: dict):
        self.config: dict = config
        self.cache_path: str = os.path.join(os.getcwd(), 'data\\config\\cache.json')
        self._table: dict = {}
        self._queue: list = []

        self.__release()


    # def autoTimeout(self, size: int, record: bool = True) -> bool:
    #     """
    #     根据长时间的硬盘读写情况分析出应该等待多长时间执行下一步解除阻塞
    #     :param record: 是否添加到分析结果中
    #     :param size: 文件大小(Bytes)
    #     :return: 是否超时
    #     """

    def __release(self):
        while True:
            if self._queue:
                key, value = list(self._queue.pop().items())[0]
                with open(os.path.join(os.getcwd(), 'data\\config\\cache.json'), mode='r+') as f:
                    # todo: 写入cache文件
                    pass
            time.sleep(0.1)

    def recordTime(self, size: int, method: str = 'r') -> str:
        """
        开始记录 size 个字节, 读取/写入 的每秒字节量
        :param size:
        :param method:
        :return: mark
        """
        mark = HashTools.getRandomStr(4)
        while mark in self._table:
            mark = HashTools.getRandomStr(4)
        self._table[mark] = {
            'start_time': time.time(),
            'size': size,
            'method': method.lower()
        }
        return mark

    def disRecordTime(self, mark: str):
        """
        停止记录指定的mark记录，并将结果写入缓存
        :param mark: mark值
        :return:
        """
        table: dict = self._table.get(mark)
        size: int = table.get('size')
        start_time: float = table.get('start_time')
        method: str = table.get('method')
        end_time: float = time.time()

        byte_per_second = size / (end_time - start_time)
        self._queue.append({method: byte_per_second})


if __name__ == '__main__':
    def test(text):
        print(f'测试: {text}')


    IOBalance.balance(test, ('测试文字',))
