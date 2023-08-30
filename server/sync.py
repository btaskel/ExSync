import configparser
import json
import logging
import os
from datetime import datetime

import xxhash

from server.config import readConfig
from server.core import createSocket
from server.shell import initLogging
from server.tools.tools import createFile, relToAbs


class Index(readConfig):
    """
    建立索引，并且扫描文件是否需要同步
    首先传入：同步目录的路径
    """

    def __init__(self, path):
        super().__init__()
        initLogging(logging.DEBUG)
        self.config = self.readJson()
        # 同步目录的路径
        self.path = os.path.abspath(path)
        # run()

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

    def initIndex(self):
        """
        本地ExSync索引初始化
        :return:
        """
        folders = ['.sync\\base', '.sync\\info']
        for folder in folders:
            path_ = os.path.join(self.path, folder)
            if not os.path.exists(path_):
                os.makedirs(path_)

        # 创建索引
        files_path = f'{self.path}\\.sync\\info\\files.json'
        folder_path = f'{self.path}\\.sync\\info\\folders.json'
        space_config = f'{self.path}\\.sync\\config.ini'

        # 创建索引文件
        createFile(files_path, '{\n"data":{\n}\n}')
        createFile(folder_path, '{\n"data":{\n}\n}')

        config_file = configparser.ConfigParser()
        config_file['main'] = {
            'overwrite': False,
            'priority': '',

        }

        return self.createIndex(folder_path, files_path)

    def createIndex(self, folder_path=None, files_path=None):
        """
        同步路径
        folder_path：文件夹索引文件路径
        files_path：文件索引文件路径
        :param folder_path:
        :param files_path:zz
        :return:
        """
        # 如果没有指定路径，则默认选择此路径
        if not folder_path:
            folder_path = os.path.join(self.path, '.sync\\info\\folders.json')
        if not files_path:
            files_path = os.path.join(self.path, '.sync\\info\\files.json')

        abspath = os.path.abspath(self.path)
        for home, folders, files in os.walk(abspath):

            # 建立文件夹索引
            for folder in folders:
                folder = os.path.join(home, folder)
                logging.debug(f'Created index for {folder} folder.')
                folder_table = {
                    "data": {
                        folder: {
                            "type": "folder",
                            "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "file_date": datetime.fromtimestamp(os.path.getmtime(folder)).strftime(
                                "%Y-%m-%d %H:%M:%S"),
                            "state": ""
                        }
                    }
                }
                Index.updateJson(folder_path, folder_table)

            # 建立文件索引
            for file in files:
                file = os.path.join(home, file)
                # folder = os.path.join(home,)
                logging.debug(f'Created index for {file} file.')
                file_table = {
                    "data": {
                        file: {
                            "type": "file",
                            "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "file_date": datetime.fromtimestamp(os.path.getmtime(file)).strftime(
                                "%Y-%m-%d %H:%M:%S"),
                            "hash": Index.hashFile(file),
                            "size": "",
                            "state": ""
                        }
                    }
                }
                Index.updateJson(files_path, file_table)

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
                    print(file)

                    if file in index_dict['data']:
                        # 如果存在记录，则更新记录
                        file = os.path.join(home, file)
                        file_table = {
                            "data": {
                                file: {
                                    "type": "file",
                                    "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                    "file_date": datetime.fromtimestamp(os.path.getmtime(file)).strftime(
                                        "%Y-%m-%d %H:%M:%S"),
                                    "hash": Index.hashFile(file),
                                    "size": os.path.getsize(file),
                                    "state": ""
                                }
                            }
                        }
                        Index.updateJson(index_file, file_table)

                    else:
                        # 如果没有记录，则创建记录
                        # self.createIndex(index_file, )
                        pass

    def readIndex(self):
        """
        如果存在：读取并返回索引文件的json对象
        如果不存在：返回False
        """

        index_path = os.path.join(self.path, '.sync\\info\\')
        dirs = ['files.json', 'folders.json']
        for i in dirs:
            path = os.path.join(index_path, i)
            if not os.path.exists(path):
                return False

        with open(os.path.join(index_path, 'files.json'), mode='r') as f:
            files_json = json.load(f)
        with open(os.path.join(index_path, 'folders.json'), mode='r') as f:
            folders_json = json.load(f)
        return files_json, folders_json

    def analyseFiles(self, remote_data):
        """
        分析双方文件索引是否需要同步
        remote_data [file_index_path, folder_index_path]
        """

        result = self.readIndex()
        local_file_index = result[0]
        local_folder_index = result[1]
        with open(relToAbs(remote_data[0]), mode='r', encoding='utf-8') as f:
            remote_file_index = json.load(f)

        with open(relToAbs(remote_data[1]), mode='r', encoding='utf-8') as f:
            remote_folder_index = json.load(f)

        change_info = {}
        ls = [(local_file_index, remote_file_index),
              (local_folder_index, remote_folder_index)]

        for local_index, remote_index in ls:
            for local_key, local_value in local_index.items():
                if local_key in remote_index:
                    if local_value != remote_index[local_key]:
                        change_info[local_key] = 0
                else:
                    change_info[local_key] = 1
            for remote_key in remote_index:
                if remote_key not in local_index:
                    change_info[remote_key] = 2
        return change_info


class SyncData(Index):
    """
    数据同步
    """

    def __init__(self, path):
        super().__init__(path)
        initLogging(logging.DEBUG)

        self.server = createSocket()
        self.server.createDataSocket()
        self.server.createCommandSocket()
        self.server.createVerifySocket()
        self.client_socket = self.server.createClientCommandSocket()

    def syncFiles(self, method=0):
        """
        同步N方文件
        method = 0; 同步双方文件
        method = 1; 同步所有设备的文件
        """


if __name__ == '__main__':
    p = '.\\test\\space'
    s = Index(p)
    # s.updateIndex(p)
    s.initIndex()
