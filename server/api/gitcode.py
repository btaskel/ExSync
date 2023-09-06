import os
from datetime import datetime

import requests
from bs4 import BeautifulSoup

from ..config import ApiConfig


class GitcodeAPI(ApiConfig):
    """
    GitcodeAPI
    初始化实例时需要传入指定仓库的URL，
    """

    def __init__(self, url):
        self.headers = ApiConfig.headers
        self.logs = ApiConfig.logs
        self.url = url

    def getInfo(self, url=None):
        """
        获取指定Gitcode仓库信息：
        :return:（存在文件返回True 否则返回 False） | 文件名/文件夹、文件/文件夹类型、提交信息（提交ID、提交信息、父ID、
        作者更新日期、作者、邮箱、提交日期、提交人、提交人邮箱）、提交路径、提交的标题HTML
        """

        if not url:
            url = self.url
        # 判断URL是否为Gitcode
        validate = url.split('https://')[1].split('.net')[0]
        if not validate == 'gitcode':
            raise 'URL并不是Gitcode类型'

        result = self.__urlInit(url)
        url_logs = result['url_logs']

        try:
            html = requests.get(url_logs, headers=self.headers)
        except Exception as e:
            print(e, f'请求错误：{url}或许是网络连接失败')
            return 1

        soup = BeautifulSoup(html.text, "html.parser")

        try:
            file_list = eval(str(soup))
        except Exception as e:
            raise ValueError(f'getInfo解析失败：{e}目标似乎不是gitcode仓库')

        if not len(file_list) == 0:
            return True, file_list
        else:
            return False, file_list

    @staticmethod
    def getFileSize(file_url):
        """
        获取仓库中的文件大小
        参数：目标文件URL
        :return:文件大小（比特）
        """
        response = requests.head(file_url)
        file_size = response.headers['Content-Length']
        return file_size

    def getUpdateDate(self):
        """
        获取指定仓库的最新更新日期
        :return:最新更新时的日期
        """

        info_ = self.getInfo()[1]
        skip = False
        time_list = []
        for i in info_:
            # 如果不为Gitcode的URL则跳出循环
            if not i:
                skip = True
                break
            dict_ = eval(str(i))

            # 获取文件时间
            committed_date = eval(str(dict_['commit']))['committed_date']
            update_date = datetime.strptime(committed_date,
                                            "%Y-%m-%dT%H:%M:%S.000+08:00")
            time_list.append(update_date)
        if skip:
            update = None
        else:
            update = sorted(time_list)[-1]
        return update

    def getFileContent(self, url):
        """
        用于获取＜1MB的文件内容
        :return:文件文本内容
        """
        try:
            html = requests.get(url, headers=self.headers)
        except Exception as e:
            raise e
        return BeautifulSoup(html.text, 'html.parser')

    def __urlInit(self, url):
        """
        这个函数用来初始化URL，让GitCode的URL格式化
        第一个参数：传入主页
        """
        if url.count('/') == 4:
            try:
                # https://gitcode.net/qq_41194307/client_lib
                url_domain = url
                url_path = ''
                url_type = ''

                url_logs = url_domain + self.logs

                return {
                    'url_domain': url_domain,
                    'url_type': url_type,
                    'url_path': url_path,

                    'url_logs': url_logs
                }

            except Exception as e:
                raise NameError(f'url并非目录结构：{e}(这可能是因为url不是gitcode而导致\n'
                                '也可能是你的url定位是在仓库主页导致)')
        else:
            try:
                # https://gitcode.net/qq_41194307/client_lib
                url_domain = url.split('/-/')[0]
                # tree or refs
                url_type = url.split('/-/')[1].split('/')[0]
                # master/ClientPlus/86
                url_path = url.split(url_type + '/')[1]

            except Exception as e:
                raise NameError(f'url并非目录结构：{e}(这可能是因为url不是gitcode而导致\n'
                                '也可能是你的url定位是在仓库主页导致)')

            url_logs = url_domain + '/-/refs/' + url_path + \
                       '/logs_tree/?format=json&offset=0' + self.logs

            return {
                'url_domain': url_domain,
                'url_type': url_type,
                'url_path': url_path,

                'url_logs': url_logs
            }


if __name__ == '__main__':
    g = GitcodeAPI('https://gitcode.net/qq_41194307/client_lib')
    print(g.getFileContent('https://gitcode.net/qq_41194307/client_lib/-/raw/master/qwe.txt'))
    # info = g.getIndexCache('resources/momaps/index/cache/')
    # print(info)
