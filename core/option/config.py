import json
import logging
import os
import random
import socket
import string
import sys


class ApiConfig:
    """
    基本配置信息
    """
    # 设置请求头
    headers = {
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                      ' (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36'
    }

    logs = '/-/refs/master/logs_tree/?format=json&offset=0'


def getRandomString(length=8):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))


class readConfig:
    """
    读取配置信息
    """

    @staticmethod
    def readJson() -> dict:
        """
        读取config
        :return:
        """
        config: dict = {}
        path = os.path.join(os.getcwd(), 'data\\config\\config.json')
        with open(path, mode='r', encoding='utf-8') as f:
            try:
                json_file = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(
                    f'JSON parsing error at position {e.doc}, the incorrect content is {e.doc[e.pos:e.pos + 10]}')
            except Exception as e:
                logging.error(f'JSON parsing error: {e}')

            # log-loglevel
            log = json_file.get('log')
            if not log:
                print('eeee')
                config['log'] = {'loglevel': 'info'}
            elif not log.get('loglevel'):
                config['log'] = {'loglevel': 'info'}
            else:
                config['log'] = log

            if log.get('loglevel').lower() in ['debug', 'info', 'warning', 'error', 'none']:
                config['log']['loglevel'] = json_file['log']['loglevel']
            else:
                config['log']['loglevel'] = 'info'

            # addr = json_file['server']['addr']
            server = json_file.get('server')
            if not server:
                config['server'] = {}
                config['server']['addr'] = {}
            elif server and not server.get('addr'):
                config['server']['addr'] = {}
            else:
                config['server'] = json_file.get('server')

            addr = config['server']['addr']
            # server-addr-id
            if addr.get('id'):
                if len(config.get('id')) < 4:
                    logging.warning('If the device ID length is less than 4, there may be a security risk.')
            else:
                logging.info('The device ID is already random, which will hide your device.')
                # config['server']['addr']['id'] = ''.join(random.sample(string.ascii_letters, 10))
                config['server']['addr']['id'] = None

            # server-addr-ip
            if addr.get('ip'):
                try:
                    # 判断是否为ipv4
                    socket.inet_pton(socket.AF_INET, addr['ip'])
                    config['server']['addr']['ip_type'] = 'ipv4'
                except socket.error:
                    try:
                        # 判断是否为ipv6
                        socket.inet_pton(socket.AF_INET6, addr['ip'])
                        config['server']['addr']['ip_type'] = 'ipv6'
                    except socket.error:
                        logging.error('The host IP address is not ipv4 or ipv6!')
                        sys.exit(1)
            else:
                logging.error('The host IP address is not filled in and has been defaulted to 0.0.0.0!')
                config['server']['addr']['ip'] = '0.0.0.0'
                config['server']['addr']['ip_type'] = 'ipv4'

            # server-addr-port
            if not isinstance(addr.get('port'), int) and 65536 < addr.get('port') < 1024:
                logging.error('Port number setting error! Has been defaulted to 5001!')
                config['server']['addr']['port'] = 5001

            # server-addr-password
            if not addr.get('password'):
                logging.error('Password not set! Your device may be in a dangerous state!')
                sys.exit(1)
            elif len(addr.get('password')) < 4:
                logging.error('Password length is less than 4! Should be between 4 and 48 characters!')
                sys.exit(1)
            elif len(addr.get('password')) > 48:
                logging.error('The password length is greater than 48! Should be between 4 and 48 characters!')
                sys.exit(1)

            if server.get('setting'):
                config['server']['setting'] = server.get('setting')
            else:
                config['server']['setting'] = {}

            setting = config['server']['setting']

            # server-setting-encode
            if not setting.get('encode') and setting.get('encode').lower() != 'gbk' or setting.get(
                    'encode').lower() != 'utf-8':
                logging.info('Invalid encoding, defaults to UTF-8.')

            # server-setting-IOBalance
            if not isinstance(setting.get('iobalance'), bool):
                config['server']['setting']['iobalance'] = False

            if server.get('scan'):
                config['server']['scan'] = server.get('scan')
            else:
                config['server']['scan'] = {}

            scan = config['server']['scan']

            # server-scan-enabled
            if not isinstance(scan.get('enabled'), bool):
                config['server']['scan']['enabled'] = True

            # server-scan-type
            if scan.get('type') not in ['lan', 'white', 'black']:
                config['server']['scan']['type'] = 'lan'

            # server-scan-max
            if isinstance(scan.get('max'), int) and scan.get('max') < 1:
                config['server']['scan']['max'] = 5

            # server-scan-device
            if not isinstance(scan.get('devices'), list):
                config['server']['scan']['devices'] = []

            if server.get('proxy'):
                config['server']['proxy'] = server['proxy']
            else:
                config['server']['proxy'] = {}
            proxy = config['server']['proxy']

            # server-proxy-enabled
            if not isinstance(proxy.get('enabled'), bool):
                config['server']['proxy']['enabled'] = False

            # server-proxy-hostname
            if not isinstance(proxy.get('hostname'), str):
                config['server']['proxy']['hostname'] = '127.0.0.1'

            # server-proxy-port
            if not isinstance(proxy.get('port'), int) and 65536 < proxy.get('port') < 1024:
                logging.error('Proxy port error! Restore default: 5001 !')
                config['server']['proxy']['port'] = 5001

            # server-proxy-username
            if not isinstance(proxy.get('username'), str):
                config['server']['proxy']['username'] = None

            # server-proxy-password
            config['server']['proxy']['username'] = proxy.get('username')

            if json_file.get('userdata'):
                config['userdata'] = json_file.get('userdata')
            else:
                config['userdata'] = {}

            # userdata
            count = 1
            dc = {}
            for userdata in config['userdata']:
                spacename = userdata.get('spacename', '')
                if not spacename:
                    logging.error(f'The {count} th sync space is named empty! This space will not start!')
                    sys.exit(1)
                elif spacename in dc:
                    logging.error(f'Duplicate naming of synchronization space {spacename}!')
                    sys.exit(1)
                elif 20 < len(spacename) < 2:
                    logging.error(
                        f'The length of the synchronization space {spacename} name should be between 2 and 20 characters!')
                dc[spacename] = dc.get(spacename, 0) + 1
                if not os.path.exists(userdata.get('path', '')):
                    logging.error(f'The sync space path named {spacename} is invalid, it will not work!')
                    sys.exit(1)
                if not isinstance(userdata.get('interval'), int):
                    config['userdata'][userdata]['interval'] = 30
                    logging.error(
                        f'The time interval setting for {spacename} is incorrect and has been reset to 30 seconds!')
                if not isinstance(userdata.get('autostart'), bool):
                    config['userdata'][userdata]['autostart'] = True
                count += 1

            # version
            config['version'] = json_file.get('version')

        return config

    @staticmethod
    def jsonData() -> dict:

        json_str = {
            "log": {
                "loglevel": "info"
            },
            "server": {
                "addr": {
                    "id": getRandomString(8),
                    "ip": "127.0.0.1",
                    "port": 5002,
                    "password": getRandomString(10)
                },
                "setting": {
                    "encode": "utf-8",
                    "iobalance": False,
                    "encryption": "AES_ECB"
                },
                "scan": {
                    "enabled": True,
                    "type": "lan",
                    "max": 5,
                    "devices": [
                        "127.0.0.1:5001"
                    ]
                },
                "plugin": {
                    "enabled": True,
                    "blacklist": []
                },
                "proxy": {
                    "enabled": False,
                    "hostname": "localhost",
                    "port": 0,
                    "username": None,
                    "password": None
                }
            },
            "userdata": [
                {
                    "spacename": "",
                    "path": "",
                    "interval": 30,
                    "autostart": True,
                    "active": True,
                    "devices": [""]
                }
            ],

            "version": 0.01
        }
        return json_str

    @staticmethod
    def createJson():
        """
        创建json文件
        :return:
        """
        path = os.path.join(os.getcwd(), 'config', 'config.json')
        json_str = readConfig.jsonData()
        with open(path, mode='w', encoding='utf-8') as f:
            json.dump(json_str, f, indent=4)


class InitCache:
    def __init__(self, path: str = None):
        """
        :param path: cache文件路径
        """
        if not path or not os.path.exists(path):
            self.path = os.path.join(os.getcwd(), 'data\\config\\cache.json')
        else:
            self.path = path

        self.data = {
            "disk_activity_record": {
                "read": [],
                "write": []
            }
        }

    def createCache(self) -> bool:
        """
        创建缓存文件
        :return:
        """

        with open(self.path, mode='w+', encoding='utf-8') as f:
            try:
                json.dump(self.data, f, indent=4)
            except Exception as e:
                print(e)
                return False
        return True

    def loadCache(self) -> dict:
        """
        加载缓存文件
        :return:
        """
        if not os.path.exists(self.path):
            self.createCache()
        with open(self.path, mode='r+', encoding='utf-8') as f:
            try:
                data: dict = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(
                    f'JSON parsing error at position {e.doc}, the incorrect content is {e.doc[e.pos:e.pos + 10]}')
            except Exception as e:
                logging.error(f'JSON parsing error: {e}')

        cache_obj = {
            'path': self.path
        }

        # disk_activity_record
        disk_activity_record: dict = data.get('disk_activity_record')
        if disk_activity_record:
            read = disk_activity_record.get('read')
            if read:
                cache_obj['disk_activity_record']['read'] = read
            else:
                logging.warning('Cache : The hard disk cache record is turned off, which may cause performance loss!')
                cache_obj['disk_activity_record']['read'] = []

            write = disk_activity_record.get('write')
            if write:
                cache_obj['disk_activity_record']['write'] = write
            else:
                logging.warning('Cache : The hard disk cache record is turned off, which may cause performance loss!')
                cache_obj['disk_activity_record']['write'] = []
        else:
            cache_obj['disk_activity_record'] = {
                'read': [],
                'write': []
            }
            with open(self.path, mode='w', encoding='utf-8') as f:
                json.dump(self.data, f, indent=4)
        return cache_obj


class Config(readConfig):
    def __init__(self):
        super().__init__()
        self.config = readConfig.readJson()

        self.local_ip: str = self.config['server']['addr'].get('ip')
        self.password: str = self.config['server']['addr'].get('password')
        self.ip_type: str = self.config['server']['addr'].get('ip_type')
        self.id: str = self.config['server']['addr'].get('id')
        self.data_port: int = self.config['server']['addr'].get('port')
        self.command_port: int = self.config['server']['addr'].get('port') + 1
        self.listen_port: int = self.config['server']['addr'].get('port') + 2

        self.encode: str = self.config['server']['setting'].get('encode', 'utf-8')

        # 设置ip类型(ipv4 / ipv6)
        self.socket_family: int = socket.AF_INET if self.ip_type == 'ipv4' else socket.AF_INET6

        self.cache_path: str = os.path.join(os.getcwd(), 'data\\config\\cache.json')


if __name__ == '__main__':
    # r = readConfig()
    # config = r.readJson()
    # for userdata in config['userdata']:
    #     print(userdata)
    pass
