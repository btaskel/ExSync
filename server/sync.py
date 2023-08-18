import json
import os
from datetime import datetime

import xxhash

from config import readConfig
from tools.tools import createFile


class SyncData(readConfig):
    """
    建立索引，并且扫描文件是否同步
    判断文件是否同步，或意外中断
    """

    def __init__(self):
        super().__init__()
        self.config = self.readJson()

    @staticmethod
    def hashFile(file_path):
        """
        获取文件的XXHash哈希值
        :param file_path:
        :return: hash
        """

        hash_object = xxhash.xxh3_128()
        with open(file_path, 'rb') as f:
            while True:
                data = f.read(8192)
                if not data:
                    break
                hash_object.update(data)
        return hash_object.hexdigest()

    @staticmethod
    def updateJson(folder_path, folder_table):
        """
        更新本地文件索引
        :param folder_path:
        :param folder_table:
        :return:
        """
        with open(folder_path, mode='r+', encoding='utf-8') as f:
            data = json.load(f)
            data["data"].update(folder_table["data"])
            f.seek(0)
            f.truncate()
            json.dump(data, f, indent=4)

    def initIndex(self, path):
        """
        本地ExSync索引初始化
        :param path:
        :return:
        """
        folders = ['.sync\\base', '.sync\\info']
        for folder in folders:
            path_ = os.path.join(path, folder)
            if not os.path.exists(path_):
                os.makedirs(path_)

        # 创建索引
        files_path = f'{path}\\.sync\\info\\files.json'
        folder_path = f'{path}\\.sync\\info\\folders.json'
        # 创建索引文件
        createFile(files_path, '{\n"data":{\n}\n}')
        createFile(folder_path, '{\n"data":{\n}\n}')

        return self.createIndex(path, folder_path, files_path)

    def createIndex(self, path, folder_path, files_path):
        """
        同步路径
        文件夹索引路径
        文件索引路径
        :param path:
        :param folder_path:
        :param files_path:
        :return:
        """
        abspath = os.path.abspath(path)
        for home, folders, files in os.walk(abspath):

            # 建立文件夹索引
            for folder in folders:
                folder = os.path.join(home, folder)
                # folder = os.path.join(home,)
                folder_table = {
                    "data": {
                        folder: {
                            "type": "folder",
                            "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "file_date": os.path.getmtime(folder),
                            "state": ""
                        }
                    }
                }
                SyncData.updateJson(folder_path, folder_table)

            # 建立文件索引
            for file in files:
                file = os.path.join(home, file)
                # folder = os.path.join(home,)
                file_table = {
                    "data": {
                        file: {
                            "type": "file",
                            "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "file_date": os.path.getmtime(file),
                            "hash": SyncData.hashFile(file),
                            "size": "",
                            "state": ""
                        }
                    }
                }
                SyncData.updateJson(files_path, file_table)

        return

    def updateIndex(self, path):

        ls = ['files.json', 'folders.json']
        abspath = os.path.abspath(path)
        for index in ls:
            index_file = f'{path}\\{index}'
            with open(index_file, mode='r+', encoding='utf-8') as f:
                index_dict = json.loads(f.read())

            # 遍历同步目录
            for home, folders, files in os.walk(abspath):
                for file in files:
                    file = os.path.join(abspath, file)

                    if file in index_dict['data']:
                        # 如果存在记录，则更新记录
                        file = os.path.join(home, file)
                        file_table = {
                            "data": {
                                file: {
                                    "type": "file",
                                    "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    "file_date": os.path.getmtime(file),
                                    "hash": SyncData.hashFile(file),
                                    "size": os.path.getsize(file),
                                    "state": ""
                                }
                            }
                        }
                        SyncData.updateJson(index_file, file_table)

                    else:
                        # 如果没有记录，则创建记录
                        # self.createIndex(index_file, )
                        pass

    def readIndex(self, path):
        pass


if __name__ == '__main__':
    p = '..\\test\\database\\.sync\\info'
    s = SyncData()
    # s.updateIndex(p)
    s.initIndex()