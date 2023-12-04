import logging
import sys


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

    logging.basicConfig(
        filename='debug.log',
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y/%m/%d %I:%M:%S '
    )
    logging.debug('debug message')


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


def printVersion(version):
    print(f'当前版本为: {version}')
