import json
import logging
import os
import threading
import time

import ntplib

from core.addition import Record
from core.control import RunServer
from core.option import readConfig, Commands
from core.tools import relToAbs, HashTools


def createFile(file_path: str, content: str) -> bool:
    """
    快速创建文件
    :param file_path: 文件路径
    :param content: 文件内容
    :return:
    """
    if not os.path.exists(file_path):
        with open(file_path, mode='w', encoding='utf-8') as f:
            f.write(content)
        return True
    else:
        return False


class IndexBase(readConfig):
    def __init__(self):
        super().__init__()
        self.config = self.readJson()
        self.userdata = {}
        for space in self.config.get('userdata'):
            self.userdata[space['username']] = space

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
        return self.userdata.get(spacename)

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

        with open(os.path.join(index_path, 'files.json'), mode='r', encoding='utf-8') as f:
            files_json = json.load(f)
        with open(os.path.join(index_path, 'folders.json'), mode='r', encoding='utf-8') as f:
            folders_json = json.load(f)
        return files_json, folders_json


class Index(IndexBase):
    """
    建立索引，并且扫描文件是否需要同步
    首先传入：同步目录的路径
    """

    def __init__(self):
        super().__init__()
        Commands.setLogLevel(self.config['log']['loglevel'])

    @staticmethod
    def updateSystemTime():
        """
        EXSync依赖系统时间进行文件同步
        同步系统时间
        :return:
        """
        ntp_client = ntplib.NTPClient()
        response = ntp_client.request("pool.ntp.org")
        time_str = response.tx_time
        ntp_date = time.strftime('%Y-%m-%d', time.localtime(time_str))
        ntp_time = time.strftime('%X', time.localtime(time_str))
        os.system('date {} && time {}'.format(ntp_date, ntp_time))
        logging.debug('Synchronized system time')

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
        files_path = os.path.join(space_path, '.sync\\info\\files.json')
        folder_path = os.path.join(space_path, '.sync\\info\\folders.json')

        if not createFile(files_path, '{\n"data":{\n}\n}') and not createFile(folder_path, '{\n"data":{\n}\n}'):
            return False

        return self.updateIndex(spacename)

    def updateIndex(self, spacename: str, strict: bool = True) -> bool:
        """
        更新指定路径的同步空间索引
        :param strict: 严格模式会忽略日期和大小相同的因素，强行更新文件的hash值
        :param spacename:
        :return:
        """

        space = self.getSyncSpace(spacename)
        space_path = space.get('path')

        # 文件索引更新
        file_index_path = os.path.join(space_path, '.sync\\info\\files.json')
        with open(file_index_path, mode='r+', encoding='utf-8') as f:
            try:
                index_data: dict = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(
                    f'JSON parsing error at position {e.doc}, the incorrect content is {e.doc[e.pos:e.pos + 10]}')
                return False
            except Exception as e:
                logging.error(f'JSON parsing error: {e}')
                return False

            data: dict = index_data.get('data')

            for home, folders, files in os.walk(space_path):
                for file in files:
                    file_abspath = os.path.join(home, file)
                    file_relpath = os.path.relpath(file_abspath, space_path)

                    system_time = time.time()
                    file_edit_date = os.path.getmtime(file_abspath)
                    file_create_date = os.path.getctime(file_abspath)
                    file_read_date = os.path.getatime(file_abspath)
                    file_size = os.path.getsize(file_abspath)

                    if not strict:
                        # 如果严格模式关闭，如果修改日期和文件大小相同，就判定为同一文件
                        file_data = data.get(file_relpath)
                        if file_edit_date == file_data.get('file_edit_date') and file_size == file_data.get(
                                'file_size'):
                            continue

                    with Record(self.config, file_size, 'r'):  # 获取hash值时的硬盘读写情况
                        file_hash = HashTools.getFileHash(file_abspath)

                    file_table = {
                        "data": {
                            file_relpath: {
                                "type": "file",
                                "system_date": system_time,
                                "file_edit_date": file_edit_date,
                                "file_create_date": file_create_date,
                                "file_read_date": file_read_date,
                                "hash": file_hash,
                                "size": file_size,
                                "state": ""
                            }
                        }
                    }
                    index_data['data'].update(file_table)
                    f.seek(0)
                    f.truncate(0)
                    json.dump(index_data, f, indent=4)

        # 文件夹索引更新
        folder_index_path = os.path.join(space_path, '.sync\\info\\folders.json')
        with open(folder_index_path, mode='r+', encoding='utf-8') as f:
            try:
                index_data: dict = json.load(f)
            except json.JSONDecodeError as e:
                logging.error(
                    f'JSON parsing error at position {e.doc}, the incorrect content is {e.doc[e.pos:e.pos + 10]}')
                return False
            except Exception as e:
                logging.error(f'JSON parsing error: {e}')
                return False
            index_path = os.path.join(space_path, '.sync\\info\\folders.json')
            for home, folders, files in os.walk(space_path):
                for folder in folders:
                    folder_abspath = os.path.join(home, folder)
                    folder_relpath = os.path.relpath(folder_abspath, space_path)
                    logging.debug(f'Created index for {folder} folder.')
                    folder_table = {
                        folder_relpath: {
                            "type": "folder",
                            "system_date": time.time(),
                            "folder_date": os.path.getmtime(folder_abspath),
                            "state": ""
                        }
                    }
                    index_data['data'].update(folder_table)
                    f.seek(0)
                    f.truncate(0)
                    json.dump(index_data, f, indent=4)
        return True

    def analyseFiles(self, spacename: str, remote_data: list) -> dict:
        """
        分析双方文件索引判断是否需要同步
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

    # def pushIndex(self, index_content, cache_length=10):
    #     """
    #     把将要发送的索引内容加入队列，当达到cache_length则向服务端发送
    #     相当于多路复用减少延迟的效果
    #     """


class EXSync(RunServer, Index):
    def __init__(self):
        super().__init__()
        Commands.checkPython()
        Commands.printVersion(0.01)
        self.devices = self.getAllDevice()
        self.index_cache = []

    def init_app(self, app):
        """
        初始化EXSync至Flask
        :return:
        """
        if not hasattr(app, 'extensions'):
            raise RuntimeError('Flask instance does not have extensions object!')
        app.extensions['exsync'] = self

    def syncFiles(self, device_id: str, spacename: str):
        """
        单线程同步指定的同步空间
        :param device_id: 同步的设备id
        :param spacename: 同步空间名称
        :return:
        """

        def updateLocalIndex(spacename_: str, json_example_: dict) -> bool:
            """
            打开本地指定同步空间的索引文件并写入更新
            :param spacename_: 同步空间名称
            :param json_example_: json更新内容
            :return: 写入成功返回True，否则False
            """
            space = self.getSpace(spacename_)
            space_path = space.get('path')
            file_index_path = os.path.join(space_path, '.sync\\info\\files.json')
            if not os.path.exists(file_index_path):
                if not self.initIndex(spacename_):
                    logging.error(f'InitIndex: Failed to initialize {spacename_} index file!')
            with open(space_path, mode='r+', encoding='utf-8') as f:
                try:
                    data: dict = json.load(f)
                except json.JSONDecodeError as e_:
                    logging.error(
                        f'JSON parsing error at position {e_.doc}, the incorrect content is {e_.doc[e_.pos:e_.pos + 10]}')
                    return False
                except Exception as e_:
                    logging.error(f'JSON parsing error: {e_}')
                    return False
                data['data'].update(json_example_)
                f.truncate(0)
                f.seek(0)
                json.dump(data, f, indent=4)
            return True

        ls = []
        for i in ['files.json', 'folders.json']:
            index_path = self.getIndex(device_id, spacename)
            ls.append(os.path.join(index_path, i))
        result = self.analyseFiles(spacename, ls)  # 读完关闭

        change_info: dict = result.get('change_info')
        local_file_index: dict = result.get('local_file_index')
        local_folder_index: dict = result.get('local_folder_index')
        remote_file_index: dict = result.get('remote_file_index')
        remote_folder_index: dict = result.get('remote_folder_index')

        logging.info(f'syncFiles: {device_id} Synchronize files between both parties.')

        for filePath, fileInfo in change_info.items():
            if fileInfo == 0:
                # 0: 文件时间不同, 开始进行判断
                tic: int = 5  # 文件修改时间在 tic 秒以内的文件，不进行同步
                file_edit_date: float = local_file_index['data'][filePath].get('file_edit_date')
                try:
                    file_edit_date = float(file_edit_date)
                except Exception as e:
                    print(e)
                    logging.warning(f'file : {filePath}, Date format error!')
                    continue

                local_file_start_time, local_file_end_time = file_edit_date - tic, file_edit_date + tic
                remote_file_start_time, remote_file_end_time = file_edit_date - tic, file_edit_date + tic
                # 如果文件修改的时间差在5s以内则进行同步
                if abs(remote_file_end_time - local_file_end_time) < tic and abs(
                        remote_file_start_time - local_file_start_time) < tic:
                    local_file_hash: str = local_file_index['data'][filePath]['hash']

                    if file_edit_date < remote_file_index['data'][filePath][
                        'file_edit_date']:
                        if local_file_hash != remote_file_index['data'][filePath][
                            'hash'] and self.getFile(device_id, filePath):
                            # 更新文件至本地
                            fileInfo = remote_file_index['data'].get(filePath)
                            index_json_update = {
                                filePath: fileInfo
                            }
                            updateLocalIndex(spacename, index_json_update)

                    elif file_edit_date > remote_file_index['data'][filePath][
                        'file_edit_date']:
                        if local_file_hash != remote_file_index['data'][filePath]['hash']:
                            # 更新文件至远程
                            self.postFile(device_id, spacename, filePath, remote_file_index['data'][filePath], mode=2)
                            fileInfo = local_file_index['data'].get(filePath)
                            index = {
                                filePath: fileInfo
                            }
                            self.postIndex(device_id, spacename, index)

                    else:
                        # 无操作
                        pass
                else:
                    pass

            elif fileInfo == 1:
                # 1: 本地文件不存在;
                fileInfo = remote_file_index['data'].get(filePath)
                self.getFile(device_id, filePath)
                index_json_update: dict = {
                    filePath: fileInfo
                }
                updateLocalIndex(spacename, index_json_update)

            elif fileInfo == 2:
                # 2: 远程文件不存在;
                fileInfo = local_file_index['data'].get(filePath)
                self.postFile(device_id, spacename, filePath, remote_file_index['data'][filePath], mode=2)
                index = {
                    filePath: {fileInfo}
                }
                self.postIndex(device_id, spacename, index)

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


if __name__ == '__main__':
    pass
