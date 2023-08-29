import logging
import os
import re
import socket

import xxhash

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
        ip_list = []
        global_ = {}
        for key, value in self.config["server"]["scan"].items():
            global_[key] = value

        if global_['enabled']:
            if global_['type'].lower() == 'lan':
                """
                LAN模式：逐一扫描局域网并自动搜寻具有正确密钥的计算机
                """

                # 获取局域网所在的网段
                result = os.popen('ipconfig /all').read()
                pattern = re.compile(r'IPv4.*?(\d+\.\d+\.\d+)\.\d+')
                print(pattern)
                match = pattern.search(result)
                if not match:
                    print('无法获取局域网所在的网段')
                    return
                net = match.group(1)

                # 清空当前所有的 arp 映射表
                os.popen('arp -d *')

                # 循环遍历当前网段所有可能的 IP 与其 ping 一遍建立 arp 映射表
                for i in range(1, 256):
                    os.popen(f'ping {net}.{i} -n 1 -w 1')

                # 读取缓存的映射表获取所有与本机连接的设备的 MAC 地址
                result = os.popen('arp -a').read()
                pattern = re.compile(
                    r'(\d+\.\d+\.\d+\.\d+)\s+([\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2})')
                ips = pattern.findall(result)
                for ip, mac in ips:
                    ip_list.append(ip)
                logging.debug('LAN: Search for IP completed')
                return ip_list

            elif global_['type'].lower() == 'white':
                """
                白名单模式：在此模式下只有添加的ip才能连接
                """
                for value in self.config['server']['scan']['device']:
                    ip_list.append(value)
                logging.info('White List: Search for IP completed')

            elif global_['type'].lower() == 'black':
                """
                黑名单模式：在此模式下被添加的ip将无法连接
                """
                for value in self.config['server']['scan']['device']:
                    ip_list.append(value)
                logging.info('Black List: Search for IP completed')

        remove_ip = ['192.168.1.1', socket.gethostbyname(socket.gethostname())]
        if ip_list:
            for j in remove_ip:
                ip_list.remove(j)
        return ip_list

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
            # test.settimeout(1)
            # 连接设备的指定端口
            print((ip, self.command_port))
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
    scan = Scan()
    scan.start()
