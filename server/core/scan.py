import hashlib
import logging
import os
import re
import socket
from ast import literal_eval

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from server.config import readConfig
from server.tools.status import Status
from server.tools.tools import SocketTools, HashTools


class Scan(readConfig):
    """
    对局域网/指定网段进行扫描和添加设备
    """

    def __init__(self):
        super().__init__()
        self.config = readConfig.readJson()
        self.ip_list = []
        self.data_port = self.config['server']['addr']['port']
        self.command_port = self.config['server']['addr']['port'] + 1
        self.listen_port = self.config['server']['addr']['port'] + 2
        self.password = self.config["server"]["addr"]["password"]
        self.id = self.config['server']['addr']['id']
        # 读取编码类型
        if self.config['server']['setting']['encode']:
            self.encode_type = self.config['server']['setting']['encode']
        else:
            self.encode_type = 'utf-8'
        self.verified_devices = set()

        """
        验证结果管理

        在等待客户端和服务端连接后，会保存验证信息和Key,
        TestSocket关闭, 并等待客户端与服务端的连接建立, 
        会与socket_manage产生关联

        verify_manage = {
            "1.1.1.1": {
                "AES_KEY": "123456"
                "MARK": "aBcDeFGh"
            }
        }
        """
        self.verify_manage = {}

    def scanStart(self):
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

    def testDevice(self, ip_list):
        """
        主动验证：主动嗅探并验证ip列表是否存在活动的设备
        如果存在活动的设备判断密码是否相同
        :return: devices
        """

        for ip in ip_list:
            if ip not in self.verify_manage:
                test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test.settimeout(1)
                # 连接设备的指定端口
                if test.connect_ex((ip, self.command_port)) == 0:
                    version = self.g['verify_version']
                    result = SocketTools.sendCommandNoTimeDict(test, '''{"command": "comm","type": "verifyconnect",
                    "method": "post","data": {"version": %s}}'''.replace('\x20', '') % version)

                    # 验证sha256值是否匹配
                    try:
                        dict_result = literal_eval(result).get('data')
                        remote_password_sha256 = dict_result.get('password_hash')
                        public_key = dict_result.get('public_key')
                    except Exception as e:
                        print(e)
                        test.shutdown(socket.SHUT_RDWR)
                        test.close()
                        continue

                    if remote_password_sha256 == hashlib.sha256(self.password.encode('utf-8')).hexdigest():

                        # 发送sha384
                        password_sha384 = hashlib.sha384(self.password.encode()).hexdigest()
                        result = SocketTools.sendCommandNoTimeDict(test, command='''
                        {
                            "data": {
                            "password_hash": "%s"
                            }
                        }
                        '''.replace('\x20', '') % password_sha384)
                        try:
                            data = literal_eval(result).get('data')
                            status = data.get('status')
                            remote_id = data.get('id')
                        except Exception as e:
                            print(e)
                            logging.error(f'Unknown status returned while scanning server {ip}')
                            test.shutdown(socket.SHUT_RDWR)
                            test.close()
                            continue

                        if status == 'success':
                            # 验证成功
                            self.verified_devices.add(ip)
                            self.verify_manage[test.getpeername()[0]] = {
                                "id": remote_id,
                                "AES_KEY": self.password
                            }

                        elif status == 'fail':
                            # todo: 验证服务端密码失败
                            pass

                        elif status == Status.DATA_RECEIVE_TIMEOUT:
                            # todo: 验证服务端密码超时
                            pass

                        else:
                            # todo: 验证服务端密码时得到未知参数
                            pass

                        test.shutdown(socket.SHUT_RDWR)
                        test.close()
                        continue

                    elif remote_password_sha256 == 'None' and public_key:
                        # 对方密码为空，示意任何设备均可连接
                        # 首先使用RSA发送一个随机字符串给予对方
                        rsa_pub = RSA.import_key(public_key)

                        cipher_pub = PKCS1_OAEP.new(rsa_pub)

                        session_password = HashTools.getRandomStr(8)

                        # 即将发送的加密数据
                        message = ('''
                        {
                            "data": {
                                "session_password": "%s",
                                "id": "%s"
                            }
                        }
                        '''.replace('\x20', '') % (session_password, self.id)).encode('utf-8')

                        ciphertext = cipher_pub.encrypt(message)

                        SocketTools.sendCommandNoTimeDict(test, ciphertext, output=False)

                        self.verified_devices.add(ip)
                        self.verify_manage[test.getpeername()[0]] = {
                            "REMOTE_MARK": 1,
                            "AES_KEY": session_password
                        }

                    elif remote_password_sha256 == Status.DATA_RECEIVE_TIMEOUT:
                        # todo: 验证客户端密码哈希超时
                        pass

                    else:
                        # todo: 验证客户端密码哈希得到未知参数
                        pass

                    test.shutdown(socket.SHUT_RDWR)
                    test.close()
                    continue

            return self.verified_devices
