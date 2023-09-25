import argparse
import logging
import sys
from server.config import readConfig

class Init:
    def __init__(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("-log_level", type=int, choices=range(1, 6), default=3,
                            help="设置EXSync的日志等级参数 1~5 数字越大日志越详细")
        parser.add_argument("-version", help="输出当前EXSync版本")

        args = parser.parse_args()

        built_in_config = readConfig.jsonData()

        self.initLogging(args.log_level)
        if args.version:
            self.printVersion(built_in_config.get('version','Unknown'))
        self.checkPython()

    @staticmethod
    def initLogging(level):
        if level == 5:
            level = logging.DEBUG
        elif level == 4:
            level = logging.INFO
        elif level == 3:
            level = logging.WARNING
        elif level == 2:
            level = logging.ERROR
        elif level == 1:
            level = logging.CRITICAL
        else:
            level = logging.INFO

        logging.basicConfig(
            filename='debug.log',
            level=level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y/%m/%d %I:%M:%S '
        )
        logging.debug('debug message')

    @staticmethod
    def checkPython():
        version = sys.version_info
        if version[0] == '3' and version[1] < 11:
            print('python版本小于3.11')
            logging.error('Python version error.')
            sys.exit(1)

        elif version[0] != '3':
            print('您不能使用除python 3以外的python版本')
            logging.error('Python version error.')
            sys.exit(1)

    @staticmethod
    def printVersion(version):
        print(f'当前版本为: {version}')


if __name__ == '__main__':
    pass
