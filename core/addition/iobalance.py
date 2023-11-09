import threading
import time

import psutil


class IOBalance:
    """
    IO均衡器：当磁盘资源空闲时会执行一些指定函数
    """

    @staticmethod
    def balance(func, args=(), kwargs=None, t=600, value=10485760):
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


if __name__ == '__main__':
    def test(text):
        print(f'测试: {text}')


    IOBalance.balance(test, ('测试文字',))
