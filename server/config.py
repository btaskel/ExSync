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
    # 设置默认缓存文件大小 MB
    index_cache = 1


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
        with open('..\\config\\config.json', mode='r', encoding='utf-8') as f:
            return json.loads(f.read())

    @staticmethod
    def createJson():
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
                    "encode": "utf-8"
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
                    "interval": 0

                }
            ],

            "version": 0.01
        }

        with open('..\\config\\config.json', mode='w', encoding='utf-8') as f:
            json.dump(json_str, f, indent=4)

    # @staticmethod
    # def getJson(self):
    #     return


if __name__ == '__main__':
    r = readConfig()
    r.readJson()
