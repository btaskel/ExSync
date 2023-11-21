import base64
import hashlib
import json
import logging
import os
import re
import socket

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from core.config import Config
from core.tools.encryption import CryptoTools
from core.tools.status import Status
from core.tools.tools import SocketTools, HashTools


class Scan(Config):
    """
    对局域网/指定网段进行扫描和添加设备
    """

    def __init__(self):
        super().__init__()
        self.ip_list: list = []
        self.verified_devices: set = set()

        """
        验证结果管理

        在等待客户端和服务端连接后，会保存验证信息和Key,
        TestSocket关闭, 并等待客户端与服务端的连接建立, 
        会与socket_manage产生关联

        verify_manage = {
            "1.1.1.1": {
                "AES_KEY": "123456"
                "REMOTE_ID": "aBcDeFGh"
            }
        }
        """
        self.verify_manage = {}

    def scanStart(self) -> list:
        """
        添加
        """
        ip_list = []
        scan = self.config["server"]["scan"]

        if scan['type'].lower() == 'lan':
            """
            LAN模式：逐一扫描局域网并自动搜寻具有正确密钥的计算机
            """

            # 获取局域网所在的网段
            result = os.popen('ipconfig /all').read()
            pattern = re.compile(r'IPv4.*?(\d+\.\d+\.\d+)\.\d+')
            match = pattern.search(result)
            if not match:
                print('无法获取局域网所在的网段')
                return []
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

        elif scan['type'].lower() == 'white':
            """
            白名单模式：在此模式下只有添加的ip才能连接
            """
            for value in self.config['server']['scan']['device']:
                ip_list.append(value)
            logging.info('Pre scan: White List: Search for IP completed')

        elif scan['type'].lower() == 'black':
            """
            黑名单模式：在此模式下被添加的ip将无法连接
            """
            for value in self.config['server']['scan']['device']:
                ip_list.append(value)
            logging.info('Pre scan: Black List: Search for IP completed')

        remove_ip = ['192.168.1.1', socket.gethostbyname(socket.gethostname())]
        if ip_list:
            for j in remove_ip:
                ip_list.remove(j)
            for j in self.verified_devices:
                ip_list.remove(j)
        return ip_list

    def testDevice(self, ip_list: list) -> set:
        """
        主动验证：主动嗅探并验证ip列表是否存在活动的设备
        如果存在活动的设备判断密码是否相同
        :return: devices
        """

        for ip in ip_list:
            if ip in self.verify_manage:
                continue
            test = socket.socket(self.socket_family, socket.SOCK_STREAM)
            test.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            test.settimeout(2)
            # 连接设备的指定端口
            if test.connect_ex((ip, self.command_port)) != 0:
                test.shutdown(socket.SHUT_RDWR)
                test.close()
                continue
            # 1.本地发送验证指令:发送指令开始进行验证
            version = self.config.get('version')
            command = {
                "command": "comm",
                "type": "verifyconnect",
                "method": "post",
                "data": {
                    "version": version
                }
            }
            result = SocketTools.sendCommandNoTimeDict(test, command)

            # 3.远程发送sha256值:验证远程sha256值是否与本地匹配
            try:
                dict_result = json.loads(result[8:]).get('data')  # 去除mark头
            except Exception as e:
                print(e)
                test.shutdown(socket.SHUT_RDWR)
                test.close()
                continue
            remote_password_sha256 = dict_result.get('password_hash')
            public_key = dict_result.get('public_key')

            if remote_password_sha256 == hashlib.sha256(self.password.encode('utf-8')).hexdigest():  # 密码不为空，验证是否与本地密码相同

                # 4.本地发送sha384:发送本地密码sha384
                password_sha384 = hashlib.sha384(self.password.encode('utf-8')).hexdigest()  # 获取密码的sha384
                encrypt_local_id = CryptoTools(self.password).aes_ctr_encrypt(self.id)  # 获取self.id的加密值
                b64_encrypt_local_id: str = base64.b64encode(encrypt_local_id).decode('utf-8')
                command = {
                    "data": {
                        "password_hash": password_sha384,
                        "id": b64_encrypt_local_id
                    }
                }
                result = SocketTools.sendCommandNoTimeDict(test, command=command)
                # 6.远程发送状态和id:获取通过状态和远程id 验证结束
                try:
                    data = json.loads(result).get('data')
                    status = data.get('status')
                    remote_id = CryptoTools(self.password).aes_ctr_decrypt(base64.b64decode(data.get('id')))
                except Exception as e:
                    print(e)
                    logging.error(f'Pre scan: Unknown status returned while scanning server {ip}')
                    test.shutdown(socket.SHUT_RDWR)
                    test.close()
                    continue

                if status == 'success':
                    # 验证成功
                    self.verified_devices.add(ip)
                    self.verify_manage[test.getpeername()[0]] = {
                        "REMOTE_ID": remote_id,
                        "AES_KEY": self.password
                    }

                elif status == 'fail':
                    # 验证服务端密码失败
                    logging.info(f'Pre scan: Verification failed when connecting to server {ip}')

                elif status == Status.DATA_RECEIVE_TIMEOUT:
                    # 验证服务端密码超时
                    logging.info(f'Pre scan: Timed out connecting to server {ip}')

                test.shutdown(socket.SHUT_RDWR)
                test.close()
                continue

            elif not remote_password_sha256 and public_key:
                # 对方密码为空，示意任何设备均可连接
                try:
                    rsa_pub = RSA.import_key(base64.b64decode(public_key))  # 首先使用RSA发送一个随机字符串给予对方
                except Exception as err:
                    print(err)
                    logging.error(
                        f'''Pre scan: When connecting to server {ip}, the other party's RSA public key is incorrect''')
                    test.shutdown(socket.SHUT_RDWR)
                    test.close()
                    continue
                cipher_pub = PKCS1_OAEP.new(rsa_pub)

                # 字符串 -> byte(utf-8) -> encry -> base64 -> str
                session_password: str = HashTools.getRandomStr(8)
                session_password_encry: bytes = cipher_pub.encrypt(session_password.encode('utf-8'))
                session_password_encry_base64: bytes = base64.b64encode(session_password_encry)

                encry_session_id: bytes = cipher_pub.encrypt(self.id.encode('utf-8'))
                base64_encry_session_id: bytes = base64.b64encode(encry_session_id)

                _command = {
                    "data": {
                        "session_password": session_password_encry_base64.decode(),
                        "id": base64_encry_session_id.decode()
                    }
                }

                result = SocketTools.sendCommandNoTimeDict(test, _command)

                try:
                    data: dict = json.loads(result).get('data')
                except Exception as e:
                    print(e)
                    test.shutdown(socket.SHUT_RDWR)
                    test.close()
                    continue

                remote_id = data.get('id')
                if not remote_id:
                    logging.info('Pre scan: Failed to receive server ID.')
                    test.shutdown(socket.SHUT_RDWR)
                    test.close()
                    continue

                try:
                    remote_id = CryptoTools(session_password).b64_ctr_decrypt(remote_id)
                except Exception as e:
                    print(e)
                    test.shutdown(socket.SHUT_RDWR)
                    test.close()
                    continue

                self.verified_devices.add(ip)
                self.verify_manage[ip] = {
                    "REMOTE_ID": remote_id,
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
