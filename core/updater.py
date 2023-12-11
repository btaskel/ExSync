import enum
import os
from urllib.request import urlopen

import requests

from core.api import Github


class UpdateStatus(enum):
    No_updates = '没有更新'
    Detection_failed = '检测更新错误'
    Detection_successful = '检测更新成功'
    Download_failed = '下载失败'
    Download_successful = '下载成功'
    Installation_failed = '安装失败'
    Installation_successful = '安装成功'
    Proxy_failure = '代理失效'


class Updater(Github):
    """
    通用更新器
    """

    def __init__(self, url: str, channel: str, content_type: str):
        """
        :param channel: 更新渠道（release/pre-release）
        :param url: 更新目标仓库
        """
        super().__init__(url)
        self.url = url

        """
        下载的包类型, 会自动检测相应的关键字(关键字值之间使用/隔开)：
        例如：windows/x86/64
        bit:
            64
            32
            
        architecture:
            arm
            x86
            
        system:
            android
            linux
            windows
        """
        if '/' in content_type:
            result = []
            for char in content_type.split('/'):
                result.append(char.lower())

            if 'windows' in result:
                self.system = 'windows'

            elif 'android' in result:
                self.system = 'android'

            elif 'linux' in result:
                self.system = 'linux'

            if 64 in result:
                self.bit = 64
            elif 32 in result:
                self.bit = 32

            if 'arm' in result:
                self.arch = 'arm'
            elif 'x86' in result:
                self.arch = 'x86'

        self.content_type = content_type

        """
        在每次检测后，该变量会存储最后检测获取的url
        """
        self.latest_url = None

    def getArch(self, pack_name: str) -> bool:
        result = pack_name.lower()
        bit: int = 32
        arch: str = ''
        system: str = ''

        # arm 架构判断
        if 'armv8' in result or 'armv9' in result or 'arm64' in result:
            bit = 64
            arch = 'arm'

        elif 'armv7' in result or 'arm32' in result:
            bit = 32
            arch = 'arm'

        elif 'arm' in result:
            arch = 'arm'

        # x86架构判断
        if '64' in result:
            bit = 64

        elif '32' in result:
            bit = 32

        if 'windows' in result:
            system = 'windows'
        elif 'android' in result:
            system = 'android'
        elif 'linux' in result:
            system = 'linux'

        if self.arch == arch and self.system == system and self.bit == bit:
            return True
        else:
            return False

    def install_update(self):
        ...

    def download_update(self, url: str):
        """
        下载更新包
        :param url:
        :return:
        """
        if not self.url:
            return
        path = os.path.join(os.getcwd(), 'data\\update')
        if not os.path.exists(path):
            os.makedirs(path)
        self.download(url, os.path.join(path, 'update_pack.zip'))

    def update(self) -> dict:
        """
        检查更新
        :return:
        """
        if 'github.com' in self.url:
            result = self.github_update()
            self.url = result.get('dl_url')
            return result
        else:
            return {}

    def github_update(self) -> dict:
        """
        使用Github进行更新
        :return:
        """
        try:
            # 当前release版本
            data = self.getRelease()
        except ValueError as e:
            print(e)
            return {
                'status': UpdateStatus.Detection_failed
            }

        if not data:
            return {
                'status': UpdateStatus.No_updates
            }
        # 版本详情资源
        assets = data[0].get('assets')
        if not assets:
            return {
                'status': UpdateStatus.No_updates
            }

        for new_release in assets:
            if self.getArch(new_release.get('pack_name')):
                continue
            return {
                "status": UpdateStatus.Detection_successful,
                "body": data[0].get('body'),
                "dl_url": new_release.get('browser_download_url'),
                "pack_name": new_release.get('name')
            }

    def gitcode_update(self) -> int:
        """
        使用Gitcode进行更新
        :return:
        """
        pass

    @staticmethod
    def download(download_url: str, path: str) -> bool:
        """
        :param download_url:下载资源url
        :param path: 保存路径
        :return:
        """
        # 下载资源并保存
        try:
            file_size = int(urlopen(download_url).info().get('Content-Length', -1))  # 获取下载文件的总大小
            first_byte = 0
            if os.path.exists(path):
                first_byte = os.path.getsize(path)  # 获取已经下载部分文件的大小
            header = {"Range": f"bytes={first_byte}-{file_size}"}  # 设置下载头
            req = requests.get(download_url, headers=header, stream=True)  # 请求下载文件剩下的部分
            with open(path, mode='ab') as f:
                for chunk in req.iter_content(chunk_size=1024):
                    if chunk:
                        f.write(chunk)
            return True
        except Exception as e:
            print("资源更新_连接url或保存失败", e)
            return False


if __name__ == '__main__':
    update = Updater('https://github.com/SagerNet/sing-box', 1)
    update.update()
