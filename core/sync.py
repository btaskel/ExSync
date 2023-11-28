import json
import logging
import os
import threading
import time
from datetime import datetime

import ntplib

from core.config import readConfig
from core.control import Control
from core.tools.tools import createFile, relToAbs, HashTools


class IndexBase(readConfig):
    def __init__(self):
        self.config = self.readJson()

    def pathToSpaceName(self, path: str) -> str:
        """
        根据路径获取当前spacename, 如果不存在返回空字符串
        :param path: spacename 所在路径
        :return: spacename 名称
        """
        userdata: dict = self.config.get('userdata')
        for space in userdata:
            if space.get('path') == path:
                return space.get('spacename')
        return ''

    def getSyncSpace(self, spacename: str) -> dict:
        """
        获取同步空间对象, 如果不存在返回空字典
        :param spacename: 同步空间名称
        :return: space对象
        """
        userdata: dict = self.config.get('userdata')
        for space in userdata:
            if spacename == space.get('spacename'):
                return space
        return {}

    @staticmethod
    def _updateJson(path: str, table: dict) -> bool:
        """
        更新本地文件索引
        :param path: 更新的索引文件路径
        :param table: 将更新 json 字符串的 dict 数据表
        :return:
        """
        with open(path, mode='r+', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except Exception as e:
                print(e)
                logging.warning(f'Failed to load index file: {path}')
                return False
            data['data'].update(table)
            f.seek(0)
            f.truncate(0)
            json.dump(data, f, indent=4)
        return True

    # def _writeIndex(self, path: str, json_path: str):
    #     """
    #     更新单个文件的索引
    #     :param path:
    #     :param json_path:
    #     :return:
    #     """
    #

    def _readIndex(self, spacename: str) -> tuple:
        """
        读取索引文件，返回 文件夹索引 与 文件索引 对象。
        :param spacename:
        :return: 如果存在：读取并返回索引文件的json对象；如果不存在：返回空元组
        """
        space = self.getSyncSpace(spacename)
        space_path: str = space.get('path')
        index_path = os.path.join(space_path, '.sync\\info\\')
        dirs = ['files.json', 'folders.json']
        for i in dirs:
            path = os.path.join(index_path, i)
            if not os.path.exists(path):
                return None, None

        with open(os.path.join(index_path, 'files.json'), mode='r') as f:
            files_json = json.load(f)
        with open(os.path.join(index_path, 'folders.json'), mode='r') as f:
            folders_json = json.load(f)
        return files_json, folders_json


class Index(IndexBase):
    """
    建立索引，并且扫描文件是否需要同步
    首先传入：同步目录的路径
    """

    def __init__(self):
        super().__init__()

    def initIndex(self, spacename: str) -> bool:
        """
        本地ExSync索引初始化
        :param spacename: 同步空间名称
        :return: 完成状态
        """
        space = self.getSyncSpace(spacename)
        space_path = space.get('path')

        if not space:
            return False

        folders = ['.sync\\base', '.sync\\info']
        for folder in folders:
            path_ = os.path.join(space_path, folder)
            if not os.path.exists(path_):
                os.makedirs(path_)

        # 创建索引
        files_path = f'{space_path}\\.sync\\info\\files.json'
        folder_path = f'{space_path}\\.sync\\info\\folders.json'

        if not createFile(files_path, '{\n"data":{\n}\n}') and not createFile(folder_path, '{\n"data":{\n}\n}'):
            return False

        return self.updateIndex(spacename)

    def updateIndex(self, spacename: str) -> bool:
        """
        更新指定路径的同步空间索引
        :param spacename: 同步空间名称
        :return:
        """
        space = self.getSyncSpace(spacename)
        space_path = space.get(spacename)
        if not space_path:
            return False

        # 文件索引更新
        index_path = os.path.join(space_path, 'files.json')
        for home, folders, files in os.walk(space_path):
            for file in files:
                file_path = os.path.join(home, file)
                file_table = {
                    "data": {
                        file_path: {
                            "type": "file",
                            "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            "file_edit_date": os.path.getmtime(file),
                            "file_create_date": os.path.getctime(file),
                            "file_read_date": os.path.getatime(file),
                            "hash": HashTools.getFileHash(file),
                            "size": os.path.getsize(file),
                            "state": ""
                        }
                    }
                }
                if not self._updateJson(index_path, file_table):
                    return False

        # 建立文件夹索引
        index_path = os.path.join(space_path, 'folders.json')
        for home, folders, files in os.walk(space_path):
            for folder in folders:
                folder_path = os.path.join(home, folder)
                logging.debug(f'Created index for {folder} folder.')
                table = {
                    folder: {
                        "type": "folder",
                        "system_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "file_date": datetime.fromtimestamp(os.path.getmtime(folder_path)).strftime(
                            "%Y-%m-%d %H:%M:%S"),
                        "state": ""
                    }
                }
                if not self._updateJson(index_path, table):
                    return False
        return True

    def analyseFiles(self, spacename: str, remote_data: list) -> dict:
        """
        分析双方文件索引是否需要同步
        remote_data [file_index_path, folder_index_path]
        0: 双方文件不同; 1: 本地文件不存在; 2: 远程文件不存在;
        :param spacename: 同步空间名称
        :param remote_data: 文件索引 & 文件夹索引 路径
        :return:
        """

        result = self._readIndex(spacename)
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

        return {
            'change_info': change_info,
            'local_file_index': local_file_index,
            'local_folder_index': local_folder_index,
            'remote_file_index': remote_file_index,
            'remote_folder_index': remote_folder_index
        }


class SyncData(Index, Control):
    """
    数据同步
    """

    def __init__(self):
        super().__init__()
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

    def updateLocalIndex(self, spacename: str, json_example: dict, isFile=True) -> bool:
        """
        更新本地指定同步空间的索引文件
        :param json_example: json更新内容
        :param isFile: 是否为文件索引
        :param spacename: 同步空间
        :return: 写入成功返回True，否则False
        """
        userdata_list = self.config['userdata']
        for userdata in userdata_list:
            if spacename == userdata['spacename']:
                index_json = os.path.join(userdata['path'], '\\.sync\\info\\files.json') if isFile else os.path.join(
                    userdata['path'], '\\.sync\\info\\folders.json')

                with open(index_json, mode='r+', encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                    except Exception as error:
                        print(error)
                        logging.error(f'Failed to load index file: {index_json}')
                        return False
                    try:
                        data['data'].update(json_example)
                    except Exception as e:
                        print(e)
                        logging.error(f'When updating index file {index_json}, no data object was found')
                    f.truncate(0)
                    json.dump(data, f, indent=4)
                return True

        logging.warning(f'No synchronization space was found in the configuration file: {spacename}')
        return False

    def syncFiles(self, device_id: str, spacename: str):
        """
        单线程同步指定的同步空间
        :param device_id: 同步的设备id
        :param spacename:
        :return:
        """
        ls = []
        for i in ['files.json', 'folders.json']:
            index_path = Control.getIndex(device_id, spacename)
            ls.append(os.path.join(index_path, i))
        result = self.analyseFiles(spacename, ls)

        # change_info, local_file_index, local_folder_index, remote_file_index, remote_folder_index = result[0], result[
        #     1], result[2], result[3], result[4]
        change_info: dict = result.get('change_info')
        local_file_index: dict = result.get('local_file_index')
        local_folder_index: dict = result.get('local_folder_index')
        remote_file_index: dict = result.get('remote_file_index')
        remote_folder_index: dict = result.get('remote_folder_index')

        logging.info(f'syncFiles: {device_id} Synchronize files between both parties.')
        for key, value in change_info.items():
            if value == 0:
                # 0: 文件时间不同, 开始进行判断
                tic: int = 5  # 文件修改时间在 tic 秒以内的文件，不进行同步
                try:
                    file_edit_date = local_file_index['data'][key]['file_edit_date']
                except Exception as e:
                    print(e)
                    return False

                local_file_start_time, local_file_end_time = float(file_edit_date) - tic, float(file_edit_date) + tic
                remote_file_start_time, remote_file_end_time = float(file_edit_date) - tic, float(file_edit_date) + tic
                # 如果文件修改的时间差在5s以内则进行同步
                if abs(remote_file_end_time - local_file_end_time) < tic and abs(
                        remote_file_start_time - local_file_start_time) < tic:

                    local_file_hash: str = local_file_index['data'][key]['hash']

                    if file_edit_date < remote_file_index['data'][key][
                        'file_edit_date']:
                        if local_file_hash != remote_file_index['data'][key][
                            'hash'] and Control.getFile(device_id, key):
                            # 更新文件至本地
                            value = remote_file_index['data'].get(key)
                            self.updateLocalIndex(spacename, {key: value})


                    elif file_edit_date > remote_file_index['data'][key][
                        'file_edit_date']:
                        if local_file_hash != remote_file_index['data'][key]['hash']:
                            # 更新文件至远程
                            Control.postFile(device_id, key, mode=2)
                            value = local_file_index['data'].get(key)
                            index = {
                                "data": {
                                    key: value
                                }
                            }
                            Control.postIndex(device_id, spacename, index)


                    else:
                        # 无操作
                        pass
                else:
                    pass

            elif value == 1:
                # 1: 本地文件不存在;
                value = remote_file_index['data'].get(key)
                Control.getFile(device_id, key)
                self.updateLocalIndex(spacename, f"{{'{key}': {value}}}")

            elif value == 2:
                # 2: 远程文件不存在;
                value = local_file_index['data'].get(key)
                Control.postFile(device_id, key, mode=2)
                Control.postIndex(device_id, spacename, {key: {value}})

    def syncFilesToAllDevices(self, spacename: str, method: int = 0):
        """
        同步所有设备的文件

        method = 0; 实现逻辑：本机依次同步所有设备的文件
        （拟）method = 1; 实现逻辑：本机首先发送给第一个需要同步设备IP名单，如果名单中的IP也在对方的同步列表中，
        那么对方设备会为IP名单中的设备进行文件同步，以此类推。（过程中本机也会继续同步其它设备文件）

        :param spacename:
        :param method:
        :return:
        """
        if method:
            pass
        else:
            for device in self.devices:
                thread = threading.Thread(target=self.syncFiles, args=(device, spacename))
                thread.start()
                thread.join()

    def syncShell(self, device, Command):
        """
        发送
        :param device:
        :param Command:
        :return:
        """


if __name__ == '__main__':
    # p = '.\\test\\space'
    # s = Index(p)
    # # s.updateIndex(p)
    # s.initIndex()
    # table = {
    #     'a': 1,
    #     'b': 6,
    #     'aa': 5
    # }
    # Index._updateJson('test\\index.json', table)
    pass
