import logging
import sys


def initLogging(level):
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


# def getArgs():
#     optlist, args = getopt.getopt(sys.argv[1:], shortopts, longopts)
#     print(optlist)


if __name__ == '__main__':
    pass
