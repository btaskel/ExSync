import json
import logging
import os
import time
from socket import socket

from xxhash import xxh3_128

from core.addition import readDiskInfo
from core.option import Config
from core.server.cache import indexReadCache
from core.tools import HashTools, Session, SocketSession, TimeDictInit, Status, CommandSet


# class Config(readConfig):
#     def __init__(self):
#         super().__init__()
#         self.config = readConfig.readJson()
#         self.local_ip: str = self.config['server']['addr'].get('ip')
#         self.encode_type: str = self.config['server']['setting'].get('encode')
#         self.password: str = self.config['server']['addr'].get('password')


class BaseCommandSet(Config, Session):
    """
    客户端指令发送类
    """

    def __init__(self, data_socket: socket, command_socket: socket, key: str):
        super().__init__()
        self.data_socket = data_socket
        self.command_socket = command_socket
        self.timedict = TimeDictInit(data_socket, command_socket, key)
        self.indexReadCache = indexReadCache
        self.readDiskInfo = readDiskInfo

        self.block: int = 4096 # 数据包发送分块大小(含filemark, AES_nonce and AES_gcm_tag)

        self.session = Session(self.timedict, key)
        self.key = key

        self.flags = []

    # def _addFlag(self, second: int):
    #     self.flags.remove()

    def checkConnect(self):
        while True:
            time.sleep(2)
            if not self.timedict.close_flag:
                continue


    def postFile(self, relative_path: str, file_status: dict, space: dict, mode: int = 1):
        """
        输入文件路径，发送文件至服务端
        mode = 0;
        如果不存在文件，则创建文件，返回True。否则不执行操作，返回False。

        mode = 1;
        如果不存在文件，则创建文件，返回True。否则重写文件。

        mode = 2;
        如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件，返回True。否则停止发送返回False。
        :param file_status:
        :param relative_path: 文件相对路径
        :param space: 同步空间
        :param mode: 发送文件模式
        :return:
        """
        start_time = time.time()

        # 获取8位数长度的文件头标识,用于保证文件的数据唯一性
        filemark = HashTools.getRandomStr(8)
        reply_mark = HashTools.getRandomStr(8)

        space_path: str = space.get('path')
        file_abspath = os.path.join(space_path, relative_path)

        space_name: str = space.get('spacename')

        # 本地文件大小
        local_size: int = file_status.get('size')

        sleep_time = local_size / self.readDiskInfo.getDiskCongestionInfo('r') + 10

        # 本地文件hash值
        local_filehash = file_status.get('hash')

        data_block = self.block - len(filemark) - 32 # 32 = nonce + tag

        command = {
            "command": "data",
            "type": "file",
            "method": "post",
            "data": {
                "file_path": relative_path,
                "file_size": local_size,
                "file_hash": local_filehash,
                "filemark": filemark,
                "mode": mode,
                "spacename": space_name
            }
        }
        # 1.发送获取文件指令
        # with SocketSession(self.timedict, command_socket=self.command_socket, data_socket=self.data_socket,mark=reply_mark, encrypt_password=self.key)
        result = self.session.sendCommand(self.command_socket, command=command, mark=reply_mark)

        if time.time() - start_time > sleep_time:
            return

        try:
            data = json.loads(result)
        except ValueError as e:
            print(e)
            return Status.PARAMETER_ERROR

        remote_size: int = data.get('file_size')
        remote_filehash: str = data.get('file_hash')
        remote_filedate: float = data.get('file_date')
        remote_status: str = data.get('status')

        match remote_status:
            case 'ok':
                pass
            case 'createRecvError':
                raise 'createRecvError'
            case 'WrongSpace':
                raise 'WrongSpace'
            case 'FileIsNotInSpace':
                raise 'FileIsNotInSpace'
            case 'ParameterError':
                raise 'ParameterError'
            case 'IndexError':
                raise 'IndexError'

        if not isinstance(remote_size, int) or not isinstance(remote_filehash, str) or not isinstance(remote_filedate,
                                                                                                      float):
            return Status.PARAMETER_ERROR

        with SocketSession(self.timedict, data_socket=self.data_socket, encrypt_password=self.key,
                           mark=filemark) as session:
            if mode == 0:
                if remote_size:
                    return False
                with open(file_abspath, mode='rb') as f:
                    data = f.read(data_block)
                    while True:
                        local_size -= data_block
                        if time.time() - start_time > sleep_time:
                            return
                        if local_size <= 0:
                            break
                        session.send(data)
                        data = f.read(data_block)
            elif mode == 1:
                with open(file_abspath, mode='rb') as f:
                    # 如果服务端已经存在文件，那么重写该文件
                    data = f.read(data_block)
                    while True:
                        local_size -= data_block
                        if time.time() - start_time > sleep_time:
                            return
                        if local_size <= 0:
                            break
                        session.send(data)
                        data = f.read(data_block)

            elif mode == 2:
                # 远程服务端准备完成
                xxh = xxh3_128()
                block_times, little_block = divmod(remote_size, 8192)
                read_data = 0
                with open(file_abspath, mode='rb') as f:
                    while True:
                        if read_data < block_times:
                            data = f.read(8192)
                            if time.time() - start_time > sleep_time:
                                return
                            xxh.update(data)
                            read_data += 1
                        else:
                            data = f.read(little_block)
                            if time.time() - start_time > sleep_time:
                                return
                            xxh.update(data)
                            break
                with SocketSession(self.timedict, self.data_socket, mark=reply_mark,
                                   encrypt_password=self.key) as command_session:
                    if remote_filehash == xxh.hexdigest():
                        # 文件前段xxhash_128相同，证明为未传输完成文件
                        command = {
                            "data": {
                                "status": True
                            }
                        }
                        command_session.send(command, output=False)

                        with open(file_abspath, mode='rb') as f:
                            f.seek(remote_size)
                            data = f.read(data_block)
                            while True:
                                if not data:
                                    break
                                if time.time() - start_time > sleep_time:
                                    return
                                session.send(data)
                        return True
                    else:
                        # ？这是肾么文件，这个文件不是中断传输的产物
                        command = {
                            "data": {
                                "status": False
                            }
                        }
                        self.session.sendCommand(self.data_socket, command=command, output=False, mark=reply_mark)
                        return False

    def getFile(self, path: str, space: dict, file_status: dict, output_path: str = None) -> bool:
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        如果远程文件不存在则返回False

        :param file_status:
        :param space: 同步空间对象
        :param path: 文件相对路径
        :param output_path: 写入路径（如果未填写则按path参数写入）
        :return:
        """
        start_time = time.time()
        filemark = HashTools.getRandomStr(8)
        reply_mark = HashTools.getRandomStr(8)

        space_path: str = space.get('path')
        spacename: str = space.get('spacename')
        file_abspath = os.path.join(space_path, path)

        self.timedict.createRecv(filemark)
        data_block = self.block - len(filemark) - 32  # 16 nonce + 16 tag

        if os.path.exists(file_abspath):
            file_hash = file_status.get('hash')
            file_size = file_status.get('size')
        else:
            file_hash = 0
            file_size = 0

        # 发送指令，远程服务端准备
        command = {
            "command": "data",
            "type": "file",
            "method": "get",
            "data": {
                "local_file_hash": file_hash,
                "local_file_size": file_size,
                "filemark": filemark,
                'spacename': spacename
            }
        }
        result = self.session.sendCommand(self.command_socket, command=command, mark=reply_mark)
        try:
            values = json.loads(result).get('data')
        except Exception as e:
            print(e)
            return False

        remote_file_size = values.get('file_size')
        remote_file_hash = values.get('file_hash')

        sleep_time = remote_file_size / self.readDiskInfo.getDiskCongestionInfo('w') + 10

        # 服务端文件缺失
        if not remote_file_size:
            return False

        # 如果没有设置输出路径，则默认覆盖原路径
        if not output_path:
            output_path = file_abspath

        if file_size > remote_file_size:
            # 重写本地文件
            write_data = 0
            with open(output_path, mode='wb') as f:
                while write_data < remote_file_size:
                    data = self.timedict.getRecvData(filemark)
                    if time.time() - start_time > sleep_time:
                        return False
                    f.write(data)
                    write_data += data_block
                return True

        elif file_size < remote_file_size:
            # 检查是否需要续写文件
            result = self.timedict.getRecvData(reply_mark, timeout=int(remote_file_size / 1048576))
            try:
                data = json.loads(result).get('data')
                status = data.get('status')
            except Exception as e:
                print(e)
                return False

            if not status:
                return False
            with open(output_path, mode='ab') as f:
                while True:
                    if file_size >= remote_file_size:
                        break
                    if time.time() - start_time > sleep_time:
                        return False
                    data = self.timedict.getRecvData(filemark)
                    f.write(data)
                    file_size += data_block
                    return True

        else:
            # 检查哈希值是否相同
            if file_hash != remote_file_hash:
                write_data = 0
                with open(output_path, mode='wb') as f:
                    while write_data < remote_file_size:
                        if time.time() - start_time > sleep_time:
                            return False
                        data = self.timedict.getRecvData(filemark)
                        f.write(data)
                    return True
        return True

    def postFolder(self, path: str, spacename: str) -> bool:
        """
        发送文件夹创建指令至服务端
        :param spacename: 同步空间名称
        :param path: 文件相对路径
        :return:
        """
        command = {
            "command": "data",
            "type": "folder",
            "method": "post",
            "data": {
                "path": path,
                "spacename": spacename
            }
        }
        with SocketSession(self.timedict, command_socket=self.command_socket,
                           encrypt_password=self.key) as command_session:
            command_session.send(command, output=False)
        return True

    def getFolder(self, path: str, space: dict) -> list:
        """
        遍历获取远程文件夹下的所有文件夹
        :param space: 同步空间对象
        :param path: 相对文件夹路径
        :return folder_paths:
        """
        # reply_mark = HashTools.getRandomStr(8)
        mark = HashTools.getRandomStr(8)
        command = {
            "command": "data",
            "type": "folder",
            "method": "get",
            "data": {
                "path": path,
                "spacename": space.get('spacename')
            }
        }
        with SocketSession(self.timedict, data_socket=self.data_socket, command_socket=self.command_socket,
                           encrypt_password=self.key, mark=mark) as command_session:
            result = command_session.send(command)

        try:
            data = json.loads(result).get('data')
        except Exception as e:
            print(e)
            return []
        status = data.get('status')
        paths = data.get('paths')
        if status == 'success':
            return paths
        elif status == 'pathError':
            # 路径不存在
            return []

    def postIndex(self, spacename: str, file_status: dict) -> str:
        """
        更新远程设备指定同步空间 文件/文件夹 索引
        发送成功返回 True 否则 False
        :param spacename: 同步空间名称
        :param file_status: 所要同步的json字符串
        :return: 状态码
        """

        json_data = json.dumps(file_status)
        if not 0 < len(json_data) <= 879:
            # 发送字节应该在(0,879]个字节之间
            logging.warning(f'postIndex {spacename}:The bytes sent should be between 0 and 879 bytes')
            return 'dataOverload'
        command = {
            "command": "data",
            "type": "index",
            "method": "post",
            "data": {
                "spacename": spacename,
                "json": json_data  # 应该在879个字节以内
            }
        }
        result = self.session.sendCommand(self.command_socket, command, output=False)
        try:
            data = json.loads(result).get('data')
        except Exception as e:
            print(e)
            return 'formatError'

        status = data.get('status')
        match status:
            case 'IndexNoExist':
                # 远程索引文件不存在
                logging.warning(f'postIndex {spacename}: No index files were found during state synchronization.')
                return 'remoteIndexNoExist'
            case 'remoteIndexError':
                # 远程索引文件内容并非是json
                logging.warning(f'postIndex {spacename}: Failed to parse JSON string during state synchronization.')
                return 'remoteIndexError'
            case 'jsonExampleError':
                # 远程无法解析本机发送的json内容
                logging.warning(f'postIndex {spacename}: Remote inability to parse JSON content sent locally')
            case 'remoteSpaceNameNoExist':
                # 远程同步空间不存在此索引文件
                logging.warning(
                    f'postIndex {spacename}: During state synchronization, it was found that the index file does not exist.')
                return 'remoteSpaceNameNoExist'
            case Status.UNKNOWN_ERROR:
                # 未知错误
                logging.warning(f'postIndex {spacename}: Unknown error.')
                return 'unknown'
            case Status.DATA_RECEIVE_TIMEOUT:
                # 超时错误
                logging.warning(f'postIndex {spacename}: A timeout error occurred during state synchronization.')
                return 'timeout'
            case 'remoteIndexUpdated':
                # 远程同步空间同步完毕
                logging.debug(f'postIndex {spacename}: Successfully synchronized status.')
                return 'remoteIndexUpdated'
            case _:
                logging.warning(f'postIndex {spacename}: Unknown error.')
                return 'unknown'

    def getIndex(self, space: dict):
        """
        获取对方指定同步空间的索引文件
        :param space:
        :return Boolean:
        """
        reply_mark = HashTools.getRandomStr(8)
        spacename = space.get('spacename')
        # command = {
        #     "command": "data",
        #     "type": "index",
        #     "method": "get",
        #     "data": {
        #         "spacename": spacename
        #     }
        # }
        # data = self.session.sendCommand(self.command_socket, command, mark=reply_mark)
        # if data == Status.DATA_RECEIVE_TIMEOUT:
        #     return False
        # try:
        #     data = json.loads(data).get('data')
        # except Exception as e:
        #     print(e)
        #     return
        # path = data.get('path')
        # if not path:
        #     # 路径不存在
        #     return False
        file_index_path = os.path.join(space.get('path'), '.sync\\info\\files.json')
        file_index_hash = HashTools.getFileHash(file_index_path)
        save_folder_path = os.path.join(os.getcwd(), f'data\\space\\cache\\{file_index_hash}')
        save_path = os.path.join(save_folder_path, 'files.jsons')
        if not os.path.exists(save_folder_path):
            os.makedirs(save_folder_path)
        file_status = {
            "hash": file_index_hash,
            "size": os.path.getsize(file_index_path)
        }
        result = self.getFile(file_index_path, space, file_status, output_path=save_path)

        if not result:
            return False
        if os.path.exists(save_path):
            logging.debug(f'{spacename} getIndex finish.')
            return save_folder_path
        else:
            return

    def send_Command(self, command: str, timeout: int = 2):
        """
        发送指令：以/sync开头的指令为EXSync指令
        :param timeout:
        :param command:
        :return:
        """
        with SocketSession(self.timedict, self.data_socket, self.command_socket, mark=HashTools.getRandomStr(8),
                           encrypt_password=self.key, timeout=timeout) as session:
            send_command = {
                "command": "comm",
                "type": "command",
                "method": "post",
                "data": {
                    "command": command
                }
            }

            result = session.send(send_command)

            try:
                result = json.loads(result).get('data')
            except Exception as e:
                print(e)
                logging.debug(f'Format result error: {result}')
                return CommandSet.FORMAT_ERROR
            status = result.get('status')
            return_code = result.get('return_code')
            output = result.get('output')
            error = result.get('error')

            try:
                if status == Status.DATA_RECEIVE_TIMEOUT:
                    return Status.DATA_RECEIVE_TIMEOUT
                elif status == CommandSet.EXSYNC_INSUFFICIENT_PERMISSION.value:
                    return CommandSet.EXSYNC_INSUFFICIENT_PERMISSION
            except Exception as e:
                print(e)
                logging.warning(f"Command execution failed: {command}")
                return CommandSet.FORMAT_ERROR

            return return_code, output, error


class CommandSend(BaseCommandSet):
    """
    指令拓展
    """

    def syncFile(self, spacename, path) -> bool:
        """
        在服务端收到文件后，并将文件索引进行更新
        自动判断文件操作模式：
            1.当远程文件存在时判断是否为需断点继传文件，是则继续写入。
            2.当远程文件存在并判断为并非需要断点继传文件，则重写该文件。
            3.当远程文件不存在时则创建文件。
            4.当远程文件存在时重写该文件。
        :param spacename: 同步空间名称
        :param path: 文件路径
        :return: 文件状态
        """
        file_size: int = os.path.getsize(path)
        file_hash: str = HashTools.getFileHash(path)
        file_date: float = os.path.getmtime(path)

        with SocketSession(self.timedict, self.data_socket, encrypt_password=self.key) as session:
            command = {
                'command': 'data',
                'type': 'syncfile',
                'method': 'post',
                'data': {
                    'spacename': spacename,
                    'file_path': path,
                    'file_size': file_size,
                    'file_hash': file_hash,
                    'file_date': file_date
                }
            }
            result = session.send(command)

            try:
                data = json.loads(result).get('data')
                status = data.get('status')
                remote_file_size = data.get('file_size')
                remote_file_hash = data.get('file_hash')
                remote_file_date = data.get('file_date')
            except Exception as e:
                print(e)
                return False

            sync_space: dict = {}
            for space in self.config.get('userdata'):
                if space.get('spacename') == spacename:
                    sync_space = space
                    break

            if not sync_space:
                logging.error(f'syncFile {spacename}: This sync space name does not exist!')
                return False

            # 获取spacename的索引文件目录
            index_path = sync_space.get('path')

            if status == 'sameFile':
                # 不予传输，并比较更新本地文件修改日期
                return True

            elif status == 'localFileTooLarge':
                return True

            elif status == 'remoteFileTooLarge':
                return True
