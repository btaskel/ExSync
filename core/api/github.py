import json
import logging
import re

import requests


class Github:
    """
    https://cloud.tencent.com/developer/article/1875456
    """

    def __init__(self, url: str):
        self.url: str = url
        self.type: str = ''
        self.formatURL()

    def formatURL(self) -> bool:
        """
        格式化url
        :return: 找到匹配类型返回True; 否则False
        """
        patterns = {'repository': r'https://github\.com/(\w+)/(\w+)', 'user': r'https://github\.com/(\w+)'}
        for url_type, pattern in patterns.items():
            if re.search(pattern, self.url):
                self.type = url_type
                return True
        return False

    def getInfo(self) -> dict:
        """
        获取用户/仓库信息
        :return: 用户/仓库信息
        """
        if self.type == 'user':
            url_split = self.url.split('/')
            user_name = url_split[-1]
            url = 'https://api.github.com/users/' + user_name
        elif self.type == 'repository':
            url_split = self.url.split('/')
            user_name = url_split[-2]
            repository_name = url_split[-1]
            url = f'https://api.github.com/repos/{user_name}/{repository_name}'
        else:
            logging.warning(f'The attempted warehouse/user information does not exist!: {self.url}')  # 仓库/用户不存在
            return {}
        try:
            request = requests.get(url, timeout=(10, 10))  # 连接超时3 读取超时10
        except TimeoutError as e:
            print(e)
            return {}
        return json.loads(request.content.decode())

    def getRelease(self) -> dict:
        if self.type != 'repository':
            raise ValueError('更新的目标并非仓库')
        data = self.url.split('/')
        repository_name = data[-1]
        user_name = data[-2]
        url = f'https://api.github.com/repos/{user_name}/{repository_name}/releases'
        request = requests.get(url)
        data = json.loads(request.content)
        return data


if __name__ == '__main__':
    github = Github('https://github.com/SagerNet/sing-box')
    # print(github.getInfo())

    github.getRelease()
