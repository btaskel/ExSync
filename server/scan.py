import socket
import threading

import xxhash
from ping3 import ping

from server.config import readConfig
from server.tools.tools import SocketTools


class Scan(readConfig):
    """
    对局域网/指定网段进行扫描和添加设备
    """

    def __init__(self):
        super().__init__()
        self.config = readConfig.readJson()
        self.ip_list = []

        # 端口类型
        self.data_port = self.config['server']['addr']['port']
        self.command_port = self.config['server']['addr']['port'] + 1
        self.listen_port = self.config['server']['addr']['port'] + 2

        self.password = self.config["server"]["addr"]["password"]

        # 读取编码类型
        if self.config['server']['setting']['encode']:
            self.encode_type = self.config['server']['setting']['encode']
        else:
            self.encode_type = 'utf-8'

    def start(self):
        """
        添加
        """
        global_ = {}
        for key, value in self.config["server"]["scan"].items():
            global_[key] = value

        if global_['enabled']:
            if global_['type'].lower() == 'lan':
                """
                LAN模式：逐一扫描局域网并自动搜寻具有正确密钥的计算机
                """

                def scan(j):
                    for c_value in range(j * 15 + 1, j * 15 + 16):
                        if len(self.ip_list) < self.config['server']['scan']['max']:
                            ip = f'192.168.1.{c_value}'
                            if ping(ip, timeout=1):
                                self.ip_list.append(ip)
                        else:
                            # 排除列表
                            remove_ip = ['192.168.1.1', socket.gethostbyname(socket.gethostname())]
                            for j in remove_ip:
                                self.ip_list.remove(j)
                            return self.ip_list

                threads = []
                for i in range(17):
                    t_ = threading.Thread(target=scan, args=(i,))
                    t_.start()
                    threads.append(t_)

                for thread in threads:
                    thread.join()

            elif global_['type'].lower() == 'white':
                """
                白名单模式：在此模式下只有添加的ip才能连接
                """
                for value in self.config['server']['scan']['device']:
                    self.ip_list.append(value)

            elif global_['type'].lower() == 'black':
                """
                黑名单模式：在此模式下被添加的ip将无法连接
                """
                for value in self.config['server']['scan']['device']:
                    self.ip_list.append(value)

        remove_ip = ['192.168.1.1', socket.gethostbyname(socket.gethostname())]
        for j in remove_ip:
            self.ip_list.remove(j)
        return self.ip_list

    def testDevice(self):
        """
        主动嗅探并验证ip列表是否存在活动的设备
        如果存在活动的设备判断密码是否相同
        :return: devices
        """
        self.g['devices'] = []
        ip_list = self.start()

        for ip in ip_list:
            test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test.settimeout(0.3)
            # 连接设备的指定端口
            if test.connect_ex((ip, self.command_port)) == 0:

                # 如果密码为空，则任何客户端均可以连接
                if self.password == "":
                    version = SocketTools.sendCommand(test, '/_com:comm:sync:get:version:_')
                    if version == self.config['version']:
                        self.g['devices'].append(ip)
                else:
                    # 密码不为空，则开始验证
                    version = SocketTools.sendCommand(test, '/_com:comm:sync:get:version:_')
                    if version == self.config['version']:
                        password_hash = SocketTools.sendCommand(test, '/_com:comm:sync:post:password|hash:_')
                        # 如果 远程密码哈希=本地密码哈希 则验证成功
                        if password_hash == xxhash.xxh3_128(self.password).hexdigest():
                            # 如果密码哈希值验证成功，则验证密码
                            self.g['devices'].append(ip)

            test.shutdown(socket.SHUT_RDWR)
            test.close()
        return self.g['devices']


if __name__ == '__main__':
    pass
