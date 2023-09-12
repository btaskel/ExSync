import configparser
import json
import logging
import os
import time
from datetime import datetime

import ntplib
import xxhash

from server.config import readConfig
from server.run import Control
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
    def updateJson(path, table):
        """
        更新本地文件索引
        :param path:
        :param table:
        :return:
        """
        with open(path, mode='r+', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(e)
                logging.warning(f'Failed to load index file: {path}')
            data['data'].update(table)
            f.truncate(0)
            json.dump(data, f, indent=4)

    @staticmethod
    def writeIndex(path, json_path):
        """更新单个文件的索引"""
        table = {
            "data": {
                path: {
                    "type": "folder",
                    "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "file_date": datetime.fromtimestamp(os.path.getmtime(path)).strftime(
                        "%Y-%m-%d %H:%M:%S"),
                    "state": ""
                }
            }
        }
        Index.updateJson(json_path, table)

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
                Index.writeIndex(folder, folder_path)

            # 建立文件索引
            for file in files:
                file = os.path.join(home, file)
                # folder = os.path.join(home,)
                logging.debug(f'Created index for {file} file.')
                Index.writeIndex(file, files_path)

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
                                    "file_edit_date": os.path.getmtime(file),
                                    "file_create_date": os.path.getctime(file),
                                    "file_read_date": os.path.getatime(file),
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
        0: 双方文件不同; 1: 本地文件不存在; 2: 远程文件不存在;
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
        return change_info, local_file_index, local_folder_index, remote_file_index, remote_folder_index


class SyncData(Index, Control):
    """
    数据同步
    """

    def __init__(self):
        super().__init__()
        initLogging(logging.DEBUG)
        self.devices = Control.getAllDevice()
        self.index_cache = []

    @staticmethod
    def updateSystemTime():
        """
        EXSync依赖系统时间进行文件同步
        同步系统时间
        """
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request("pool.ntp.org")
        time_str = response.tx_time
        ntp_date = time.strftime('%Y-%m-%d', time.localtime(time_str))
        ntp_time = time.strftime('%X', time.localtime(time_str))
        os.system('date {} && time {}'.format(ntp_date, ntp_time))
        logging.debug('Synchronized system time')

    def pushIndex(self, index_content, cache_length=10):
        """
        把将要发送的索引内容加入队列，当达到cache_length则向服务端发送
        相当于多路复用减少延迟的效果
        """

    def syncFiles(self, device, spacename):
        """
        device 同步的设备id
        """
        ls = []
        for i in ['files.json', 'folders.json']:
            index_path = Control.getIndex(device, spacename)
            ls.append(os.path.join(index_path, i))
        result = self.analyseFiles(ls)

        change_info, local_file_index, local_folder_index, remote_file_index, remote_folder_index = result[0], result[
            1], result[2], result[3], result[4]
        logging.info(f'syncFiles: {device} Synchronize files between both parties.')
        for key in change_info:
            if key == 0:
                # 文件时间不同, 开始进行判断
                tic = 5  # 文件修改时间在 tic 秒以内的文件，不进行同步
                local_file_start_time, local_file_end_time = float(
                    local_file_index['data'][key]['file_edit_date']) - tic, float(
                    local_file_index['data'][key]['file_edit_date']) + tic
                remote_file_start_time, remote_file_end_time = float(
                    remote_file_index['data'][key]['file_edit_date']) - tic, float(
                    remote_file_index['data'][key]['file_edit_date']) + tic
                # 如果文件修改的时间差在5s以内则进行同步
                if abs(remote_file_end_time - local_file_end_time) < tic and abs(
                        remote_file_start_time - local_file_start_time) < tic:

                    if local_file_index['data'][key]['file_edit_date'] < remote_file_index['data'][key][
                        'file_edit_date']:
                        # 更新文件至本地
                        Control.getFile(device, local_file_index['data'][key])
                        # todo: 更新本地索引

                    elif local_file_index['data'][key]['file_edit_date'] > remote_file_index['data'][key][
                        'file_edit_date']:
                        # 更新文件至远程
                        Control.postFile(device, local_file_index['data'][key])
                        Control.postIndex(device, spacename, remote_file_index['data'][key])

                    else:
                        # 无操作
                        pass

            elif key == 1:
                pass

            elif key == 2:
                pass

            # todo: 更新远程索引列表



if __name__ == '__main__':
    p = '.\\test\\space'
    s = Index(p)
    # s.updateIndex(p)
    s.initIndex()
