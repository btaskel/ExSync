import json
import os
import threading
import time

import psutil

from core.option import InitCache


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


# class AutoDisk(InitCache):
#     """
#     通过多次使用记录分析当前硬盘的读写速度/读写延迟并记录
#     """
#
#     def __init__(self, config: dict):
#         super().__init__()
#         self.config: dict = config
#         self.cache_path: str = os.path.join(os.getcwd(), 'data\\config\\cache.json')
#         self._table: dict = {}
#         self._queue: list = []
#
#         self.cache = self.loadCache()
#         threading.Thread(target=self.__release).start()
#
#     # def autoTimeout(self, size: int, record: bool = True) -> bool:
#     #     """
#     #     根据长时间的硬盘读写情况分析出应该等待多长时间执行下一步解除阻塞
#     #     :param record: 是否添加到分析结果中
#     #     :param size: 文件大小(Bytes)
#     #     :return: 是否超时
#     #     """
#
#     def __release(self):
#         """
#         定期处理队列中的数据
#         :return:
#         """
#         while True:
#             if self._queue:
#                 key, value = list(self._queue.pop().items())[0]
#
#                 read_list: dict = self.cache['disk_activity_record'].get('read')
#                 write_list: dict = self.cache['disk_activity_record'].get('write')
#
#                 # 如果为read记录，则写入到read列表；write亦然
#                 disk_activity_record_type = 'read' if key == 'r' else 'write'
#                 with open(self.cache.get('path'), mode='r+') as f:
#                     try:
#                         data = json.load(f)
#                     except json.JSONDecodeError as e:
#                         logging.error(
#                             f'JSON parsing error at position {e.doc}, the incorrect content is {e.doc[e.pos:e.pos + 10]}')
#                     except Exception as e:
#                         logging.error(f'JSON parsing error: {e}')
#                     if disk_activity_record_type == 'read':
#                         if len(read_list) >= 50:
#                             data['disk_activity_record'][disk_activity_record_type].pop(0)
#                     else:
#                         if len(write_list) >= 50:
#                             data['disk_activity_record'][disk_activity_record_type].pop(0)
#                     data['disk_activity_record'][disk_activity_record_type].append(value)
#                     json.dump(data, f, indent=4)
#
#             time.sleep(0.1)
#
#     def recordTime(self, size: int, method: str = 'r') -> str:
#         """
#         开始记录 size 个字节, 读取/写入 的每秒字节量
#         :param size:
#         :param method:
#         :return: mark
#         """
#         mark = HashTools.getRandomStr(4)
#         while mark in self._table:
#             mark = HashTools.getRandomStr(4)
#         self._table[mark] = {
#             'start_time': time.time(),
#             'size': size,
#             'method': method.lower()
#         }
#         return mark
#
#     def disRecordTime(self, mark: str):
#         """
#         停止记录指定的mark记录，并将结果写入缓存
#         :param mark: mark值
#         :return:
#         """
#         table: dict = self._table.get(mark)
#         size: int = table.get('size')
#         start_time: float = table.get('start_time')
#         method: str = table.get('method')
#         end_time: float = time.time()
#
#         byte_per_second = size / (end_time - start_time)
#         self._queue.append({method: byte_per_second})

class ReadDiskInfo(InitCache):
    def __init__(self):
        super().__init__()

    def getDiskCongestionInfo(self, method: str) -> float:
        """
        获取磁盘拥塞信息
        :param method: r/w 获取读写拥塞方法
        :return: 合适的读取/写入时间等待时间
        """
        cache_file = self.loadCache()
        if method == 'r':
            r_list: list = cache_file['disk_activity_record']['r']
            if len(r_list) > 3:
                max_r, min_r = max(r_list), min(r_list)
                r_list.remove(max_r)
                r_list.remove(min_r)
            return sum(r_list) / len(r_list)

        elif method == 'w':
            w_list: list = cache_file['disk_activity_record']['w']
            if len(w_list) > 3:
                max_w, min_w = max(w_list), min(w_list)
                w_list.remove(max_w)
                w_list.remove(min_w)
            return sum(w_list) / len(w_list)

        else:
            raise TypeError('ReadDisk method参数错误！')


readDiskInfo = ReadDiskInfo()


class Record(InitCache):
    """
    通过多次使用记录分析当前硬盘的读写速度/读写延迟并记录
    """

    def __init__(self, config: dict, size: int, method: str):
        """
        :param config: 配置文件实例
        :param size: 当前操作的文件大小
        :param method: 操作文件的方法
        """
        super().__init__()
        self.config: dict = config
        self.cache_path: str = os.path.join(os.getcwd(), 'data\\config\\cache.json')
        self._table: dict = {}
        self.cache = self.loadCache()

        self.start_time: float = time.time()
        self.size: int = size
        self.method: str = method

    # def autoTimeout(self, size: int, record: bool = True) -> bool:
    #     """
    #     根据长时间的硬盘读写情况分析出应该等待多长时间执行下一步解除阻塞
    #     :param record: 是否添加到分析结果中
    #     :param size: 文件大小(Bytes)
    #     :return: 是否超时
    #     """

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        停止记录指定的mark记录，并将结果写入缓存
        :return:
        """
        size: int = self.size
        start_time: float = self.start_time
        method: str = self.method
        end_time: float = time.time()

        read_list: dict = self.cache['disk_activity_record'].get('read')
        write_list: dict = self.cache['disk_activity_record'].get('write')

        # 如果为read记录，则写入到read列表；write亦然
        disk_activity_record_type = 'read' if method == 'r' else 'write'
        cache_file = self.loadCache()
        if disk_activity_record_type == 'read':
            if len(read_list) >= 50:
                cache_file['disk_activity_record'][disk_activity_record_type].pop(0)
        else:
            if len(write_list) >= 50:
                cache_file['disk_activity_record'][disk_activity_record_type].pop(0)
        cache_file['disk_activity_record'][disk_activity_record_type].append(size / (end_time - start_time))
        with open(self.cache_path, mode='r+', encoding='utf-8') as f:
            json.dump(cache_file, f, indent=4)


if __name__ == '__main__':
    def test(text):
        print(f'测试: {text}')


    IOBalance.balance(test, ('测试文字',))
