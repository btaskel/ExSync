import json


class ApiConfig:
    """
    基本配置信息
    """
    # 设置请求头
    headers = {
        'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/'
                      '537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36'
    }

    logs = '/-/refs/master/logs_tree/?format=json&offset=0'


class readConfig:
    """
    读取配置信息
    """

    def __init__(self):
        self.g = {}

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
            if addr['id'] is None or len(addr['id']) < 30:
                config['server']['addr']['id'] = addr['id']

            # server-addr-ip
            pass

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
                    "password": "111222333"
                },
                "setting": {
                    "encode": "utf-8",
                    "iobalance": False
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
