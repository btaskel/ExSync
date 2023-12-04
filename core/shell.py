import argparse
import logging
import sys

from core.config import readConfig


class Commands:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-log_level", type=int, choices=range(1, 6), default=3,
                            help="设置EXSync的日志等级参数 1~5 数字越大日志越详细")
        parser.add_argument("-version", help="输出当前EXSync版本")

        args = parser.parse_args()

        built_in_config = readConfig.jsonData()

        if args.version:
            self.printVersion(built_in_config.get('version', 'Unknown'))
        self.checkPython()

    @staticmethod
    def setLogLevel(level: str):
        match level.lower():
            case 'debug':
                level = logging.DEBUG
            case 'info':
                level = logging.INFO
            case 'warning':
                level = logging.WARNING
            case 'error':
                level = logging.ERROR
            case 'critical':
                level = logging.CRITICAL
            case _:
                level = logging.INFO

        # 创建一个FileHandler实例
        handler = logging.FileHandler('debug.log', encoding='utf-8')

        # 设置日志格式
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y/%m/%d %I:%M:%S ')
        handler.setFormatter(formatter)

        # 获取根日志记录器，并添加FileHandler
        logger = logging.getLogger()
        logger.addHandler(handler)

        # 设置日志级别
        logger.setLevel(level)

    @staticmethod
    def checkPython():
        version = sys.version_info
        if version[0] == 3 and version[1] < 11:
            print('python版本小于3.11')
            logging.error('Python version error.')
            sys.exit(1)

        elif version[0] != 3:
            print('您不能使用除python 3以外的python版本')
            logging.error('Python version error.')
            sys.exit(1)

    @staticmethod
    def printVersion(version):
        print(f'当前版本为: {version}')


if __name__ == '__main__':
    pass
