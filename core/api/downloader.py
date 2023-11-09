import os
from urllib.request import urlopen

import requests


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
    pass
