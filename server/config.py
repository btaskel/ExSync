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

    def __init__(self):
        self.g = {
            'verify_version': 0.1
        }

    # 全局变量管理
    def __setitem__(self, key, value):
        self.g[key] = value

    def __getitem__(self, item):
        return self.g[item]

    def __delitem__(self, key):
        del self.g[key]

    @staticmethod
    def readJson():
        config = {}
        with open('.\\config\\config.json', mode='r', encoding='utf-8') as f:
            json_file = json.loads(f.read())

            # log-loglevel
            if json_file['log']['loglevel'].lower() in ['debug', 'info', 'warning', 'error', 'none']:
                config['log']['loglevel'] = json_file['log']['loglevel']
            else:
                config['log']['loglevel'] = 'info'

            addr = json_file['server']['addr']
            # server-addr-id
            if addr['id'] is None:
                logging.info('The device ID is already random, which will hide your device.')
                # config['server']['addr']['id'] = ''.join(random.sample(string.ascii_letters, 10))
                config['server']['addr']['id'] = None

            # server-addr-ip
            if addr['ip']:
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
            if not isinstance(addr['port'], int) and 65536 < addr['port'] < 1024:
                logging.error('Port number setting error! Has been defaulted to 5001!')
                config['server']['addr']['port'] = 5001

            # server-addr-password
            if not addr['password']:
                logging.error('Password not set! Your device may be in a dangerous state!')
                sys.exit(1)
            elif len(addr['password']) < 4:
                logging.error('Password length is less than 4! Should be between 4 and 48 characters!')
                sys.exit(1)
            elif len(addr['password']) > 48:
                logging.error('The password length is greater than 48! Should be between 4 and 48 characters!')
                sys.exit(1)

            setting = json_file['server']['setting']
            # server-setting-encode
            if not setting['encode'] and setting['encode'] != 'gbk' or setting['encode'] != 'utf-8':
                logging.info('Invalid encoding, defaults to UTF-8.')

            # server-setting-IOBalance
            if not isinstance(setting['iobalance'], bool):
                config['server']['setting']['iobalance'] = False

            scan = config['server']['scan']
            # server-scan-enabled
            if not isinstance(scan['enabled'], bool):
                config['server']['scan']['enabled'] = True

            # server-scan-type
            if not scan['type'] == 'lan' or scan['type'] == 'white' or scan['type'] == 'black':
                config['server']['scan']['type'] = 'lan'

            # server-scan-max
            if isinstance(scan['max'], int) and scan['max'] < 1:
                config['server']['scan']['max'] = 5

            # server-scan-device
            if not isinstance(scan['device'], list):
                config['server']['scan']['device'] = []

            proxy = config['server']['proxy']
            # server-proxy-enabled
            if not isinstance(proxy['enabled'], bool):
                config['server']['proxy']['enabled'] = False

            # server-proxy-hostname
            if not isinstance(proxy['hostname'], str) or proxy['hostname'] == '':
                config['server']['proxy']['hostname'] = '127.0.0.1'

            # server-proxy-port
            if not isinstance(proxy['port'], int) and 65536 < proxy['port'] < 1024:
                logging.error('Proxy port error! Restore default: 1080 !')
                config['server']['proxy']['port'] = 5001

            # userdata
            count = 1
            dc = {}
            for userdata in config['userdata']:
                spacename = userdata.get('spacename', '')
                if spacename == '':
                    logging.error(f'The {count} th sync space is named empty! This space will not start!')
                    sys.exit(1)
                if spacename in dc:
                    logging.error(f'Duplicate naming of synchronization space {spacename}!')
                    sys.exit(1)
                dc[spacename] = dc.get(spacename, 0) + 1
                if not os.path.exists(userdata.get('path', '')):
                    logging.error(f'The sync space path named {spacename} is invalid, it will not work!')
                if not isinstance(userdata.get('interval'), int):
                    config['userdata'][userdata]['interval'] = 30
                    logging.error(
                        f'The time interval setting for {spacename} is incorrect and has been reset to 30 seconds!')
                if not isinstance(userdata.get('autostart'), bool):
                    config['userdata'][userdata]['autostart'] = True
                count += 1

        return config

    @staticmethod
    def jsonData():

        json_str = {
            "log": {
                "loglevel": ""
            },
            "server": {
                "addr": {
                    "id": None,
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
                    "device": [
                        "127.0.0.1:5001"
                    ]
                },
                "proxy": {
                    "enabled": False,
                    "hostname": "localhost",
                    "port": 0
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
        json_str = readConfig.jsonData()
        with open('.\\config\\config.json', mode='w', encoding='utf-8') as f:
            json.dump(json_str, f, indent=4)


if __name__ == '__main__':
    # r = readConfig()
    # config = r.readJson()
    # for userdata in config['userdata']:
    #     print(userdata)
    pass
