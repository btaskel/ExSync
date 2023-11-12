import json
import logging
import os
import shutil
from ast import literal_eval

import xxhash

from core.config import readConfig
from core.tools.status import Status, CommandSet
from core.tools.timedict import TimeDictInit
from core.tools.tools import HashTools, Session, SocketSession


class Config(readConfig):
    def __init__(self):
        super().__init__()
        self.config = readConfig.readJson()
        self.local_ip: str = self.config['server']['addr'].get('ip')
        self.encode_type: str = self.config['server']['setting'].get('encode')
        self.password: str = self.config['server']['addr'].get('password')


class CommandSend(Config, Session):
    """客户端指令发送类"""

    def __init__(self, data_socket, command_socket, key: str):
        super().__init__()
        self.data_socket = data_socket
        self.command_socket = command_socket
        # 数据包发送分块大小(含filemark, AES_)
        self.block = 1024

        self.timedict = TimeDictInit(data_socket, command_socket)
        self.session = Session(self.timedict, key)
        self.key = key

    def post_File(self, path: str, key: str, mode: int = 1):
        """
        输入文件路径，发送文件至服务端
        data_socket: 与服务端连接的socket
        path: 文件的绝对路径

        mode = 0;
        如果不存在文件，则创建文件，返回True。否则不执行操作，返回False。

        mode = 1;
        如果不存在文件，则创建文件，返回True。否则重写文件。

        mode = 2;
        如果存在文件，并且准备发送的文件字节是对方文件字节的超集(xxh3_128相同)，则续写文件，返回True。否则停止发送返回False。
        """

        # 获取8位数长度的文件头标识,用于保证文件的数据唯一性
        filemark = HashTools.getRandomStr(8)
        reply_mark = HashTools.getRandomStr(8)

        local_size = os.path.getsize(path)
        hash_value = HashTools.getFileHash(path)
        data_block = self.block - len(filemark)
        # 远程服务端初始化接收文件
        # 服务端返回信息格式：exist | filesize | filehash | filedate

        command = {
            "command": "data",
            "type": "file",
            "method": "post",
            "data": {
                "file_path": path,
                "file_size": local_size,
                "file_hash": hash_value,
                "mode": mode,
                "filemark": filemark
            }
        }
        result = self.session.sendCommand(self.command_socket, command=command, mark=reply_mark)
        try:
            data = literal_eval(result)
        except ValueError as e:
            print(e)
            return Status.PARAMETER_ERROR

        exist = data.get('exists')
        # 远程文件大小, 远程文件hash值，远程文件日期
        remote_size = data.get('file_size')
        remote_filehash = data.get('file_hash')
        remote_filedate = data.get('file_date')

        if not isinstance(exist, bool) or not isinstance(remote_size, int) or not isinstance(remote_filehash,
                                                                                             str) or not isinstance(
            remote_filedate, str):
            return Status.PARAMETER_ERROR

        # # 服务端准备完毕，开始传输文件
        # if result == Status.DATA_RECEIVE_TIMEOUT:
        #     return Status.DATA_RECEIVE_TIMEOUT
        # try:
        #     values = result.split('|')
        # except Exception as e:
        #     print(e)
        #     return Status.PARAMETER_ERROR

        # 本地文件大小，本地文件hash值，本地文件日期
        local_size, local_filehash, local_filedate = local_size, hash_value, os.path.getmtime(path)
        with SocketSession(self.timedict, data_socket=self.data_socket, encrypt_password=self.key,
                           mark=filemark) as session:
            match mode:
                case 0:
                    if exist:
                        return False
                    with open(path, mode='rb') as f:
                        data = f.read(data_block)
                        while True:
                            local_size -= data_block
                            if local_size <= 0:
                                break
                            session.send(data)
                            data = f.read(data_block)
                case 1:
                    with open(path, mode='rb') as f:
                        # 如果服务端已经存在文件，那么重写该文件
                        data = f.read(data_block)
                        while True:
                            local_size -= data_block
                            if local_size <= 0:
                                break
                            session.send(data)
                            data = f.read(data_block)

                case 2:
                    # 远程服务端准备完成
                    xxh = xxhash.xxh3_128()
                    block_times, little_block = divmod(remote_size, 8192)
                    read_data = 0
                    with open(path, mode='rb') as f:
                        while True:
                            if read_data < block_times:
                                data = f.read(8192)
                                xxh.update(data)
                                read_data += 1
                            else:
                                data = f.read(little_block)
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
                            self.session.sendCommand(self.data_socket, command=command, output=False, mark=reply_mark)

                            with open(path, mode='rb') as f:
                                f.seek(remote_size)
                                data = f.read(data_block)
                                while True:
                                    if not data:
                                        break
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

    def get_File(self, path: str, key: str, output_path: str = None) -> bool:
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        如果远程文件不存在则返回False

        output_path: 写入路径（如果未填写则按path参数写入）
        :param path:
        :param key:
        :param output_path:
        :return:
        """
        filemark = HashTools.getRandomStr(8)
        reply_mark = HashTools.getRandomStr(8)

        self.timedict.createRecv(filemark, self.password)  # 接下来的文件数据将会加密
        data_block = self.block - len(filemark) - 8  # 加密nonce 损耗8

        if os.path.exists(path):
            file_hash = HashTools.getFileHash(path)
            file_size = os.path.getsize(path)
        else:
            file_hash = 0
            file_size = 0

        # 发送指令，远程服务端准备
        # 服务端return: /_com:data:reply:filemark:{remote_size}|{hash_value}
        # result = self.session.sendCommand(self.timedict, self.command_socket,
        #                                  f'/_com:data:file:get:{path}|{file_hash}|{file_size}|{filemark}:_',
        #                                  mark=reply_mark, encrypt_password=self.password)
        command = {
            "command": "data",
            "type": "file",
            "method": "get",
            "data": {
                "local_file_hash": file_hash,
                "local_file_size": file_size,
                "filemark": filemark
            }
        }
        result = self.session.sendCommand(self.command_socket, command=command, mark=reply_mark)
        try:
            values = json.loads(result).get('data')
            remote_file_size = values.get('file_size')
            remote_file_hash = values.get('file_hash')
            remote_file_date = values.get('file_date')
        except Exception as e:
            print(e)
            return False

        # 服务端文件缺失
        if not remote_file_size:
            return False

        # 如果没有设置输出路径，则默认覆盖原路径
        if not output_path:
            output_path = path

        if file_size > remote_file_size:
            # 重写本地文件
            write_data = 0
            with open(output_path, mode='ab') as f:
                f.truncate(0)
                while write_data < remote_file_size:
                    data = self.timedict.getRecvData(filemark, decrypt_password=key)
                    f.write(data)
                    write_data += data_block
                return True

        elif file_size < remote_file_size:
            # 检查是否需要续写文件
            result = self.timedict.getRecvData(reply_mark, decrypt_password=key,
                                               timeout=int(remote_file_size / 1048576))
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
                    data = self.timedict.getRecvData(filemark, decrypt_password=key)
                    f.write(data)
                    file_size += data_block
                    return True

        else:
            # 检查哈希值是否相同
            if file_hash != remote_file_hash:
                write_data = 0
                with open(output_path, mode='ab') as f:
                    f.truncate(0)
                    while write_data < remote_file_size:
                        data = self.timedict.getRecvData(filemark, decrypt_password=key)
                        f.write(data)
                    return True
        return False

    def post_Folder(self, path: str) -> bool:
        """
        发送文件夹创建指令至服务端
        :param path:
        :return:
        """
        command = {
            "command": "data",
            "type": "folder",
            "method": "post",
            "data": {
                "path": path
            }
        }
        self.session.sendCommand(self.command_socket, command, output=False)
        return True

    def get_Folder(self, path: str) -> list:
        """
        遍历获取远程文件夹下的所有文件夹
        :param path:
        :return folder_paths:
        """
        reply_mark = HashTools.getRandomStr(8)
        command = {
            "command": "data",
            "type": "folder",
            "method": "get",
            "data": {
                "path": path
            }
        }
        result = self.session.sendCommand(self.command_socket, command, mark=reply_mark)
        try:
            data = json.loads(result).get('data')
            status = data.get('status')
            paths = data.get('paths')
        except Exception as e:
            print(e)
            return []
        if status == 'success':
            return paths
        elif status == 'pathError':
            # 路径不存在
            return []

    def get_Index(self, spacename: str):
        """
        传入spacename，获取对方指定同步空间的索引文件
        :param spacename:
        :return Boolean:
        """
        reply_mark = HashTools.getRandomStr(8)
        command = {
            "command": "data",
            "type": "index",
            "method": "get",
            "data": {
                "spacename": spacename
            }
        }
        data = self.session.sendCommand(self.command_socket, command, mark=reply_mark)
        if data == Status.DATA_RECEIVE_TIMEOUT:
            return False
        try:
            data = json.loads(data).get('data')
        except Exception as e:
            print(e)
            return
        path = data.get('path')
        if not path:
            # 路径不存在
            return

        index_save_path = os.path.join(os.getcwd(), f'\\userdata\\space')
        cache_path = os.path.join(index_save_path, 'cache')
        save_path = os.path.join(cache_path, HashTools.getRandomStr())

        if not os.path.exists(cache_path):
            os.makedirs(cache_path)
        result = self.get_File(os.path.join(path, '\\.sync\\info\\files.json'),
                               os.path.join(save_path, 'files.jsons')), self.get_File(
            os.path.join(path, '\\.sync\\info\\folders.json'), os.path.join(save_path, 'folders.json'))

        if all(result):
            folder_name = HashTools.getFileHash_32(
                os.path.join(save_path, 'files.jsons')) + HashTools.getFileHash_32(
                os.path.join(save_path, 'folders.jsons'))
            save_folder_path = os.path.join(index_save_path, spacename, folder_name)
            if os.path.exists(save_folder_path):
                if os.path.exists(os.path.join(save_folder_path, 'files.jsons')) and os.path.exists(
                        os.path.join(save_folder_path, 'folders.jsons')):
                    logging.debug(f'{spacename} getIndex finish.')
                    return save_folder_path
            else:
                os.makedirs(save_folder_path)
                for file in [os.path.join(save_path, 'files.jsons'), os.path.join(save_path, 'folders.json')]:
                    shutil.move(file, os.path.join(save_folder_path, file))
                logging.debug(f'{spacename} getIndex finish.')
                return save_folder_path
        else:
            return False

    def post_Index(self, spacename, json_example, is_file):
        """
        更新远程设备指定同步空间 文件/文件夹 索引
        发送成功返回 True 否则 False
        """
        if is_file:
            is_file = 'True'
        else:
            is_file = 'False'
        command = {
            "command": "data",
            "type": "index",
            "method": "post",
            "data": {
                "spacename": spacename,
                "json": json_example,
                "isfile": is_file
            }
        }
        result = self.session.sendCommand(self.command_socket, command, output=False)

        try:
            data = json.loads(result).get('data')
        except Exception as e:
            print(e)
            return
        status = data.get('status')

        match status:
            case 'remoteIndexNoExist':
                # 远程索引文件不存在
                return
            case 'remoteIndexError':
                # 远程索引文件内容并非是json
                return
            case 'remoteSpaceNameNoExist':
                # 远程同步空间不存在此索引文件
                return
            case Status.UNKNOWN_ERROR:
                # 未知错误
                return
            case Status.DATA_RECEIVE_TIMEOUT:
                # 超时错误
                return
            case 'remoteIndexUpdated':
                # 远程同步空间同步完毕
                return True
            case _:
                return

    def send_Command(self, command: str, timeout: int = 2):
        """
        发送指令：以/sync开头的指令为EXSync指令
        :param timeout:
        :param command:
        :return:
        """
        reply_mark = HashTools.getRandomStr(8)
        with SocketSession(self.timedict, self.data_socket, self.command_socket, mark=reply_mark,
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

    @staticmethod
    def status(result):
        """状态值返回，用于集中判断服务端的接收状态"""
        # /_com:data:reply:filemark:Value:_
        if result == Status.DATA_RECEIVE_TIMEOUT:
            return False, Status.DATA_RECEIVE_TIMEOUT
        else:
            result = result.split('|')
            return True, result

    # def replyFinish(self, filemark, expect=True, *args):
    #     """
    #     发送请求结束传输，并让服务端删除答复记录
    #     此方法不接收服务端返回状态
    #     :param filemark: 文件传输标识
    #     :param expect: 是否达到客户端的预期目标
    #     :param args: 返回至服务端的参数
    #     :return: 超时/正常状态
    #     """
    #     return self.session.sendCommand(self.timedict, self.command_socket,
    #                                    f'/_com:data:reply_end:{filemark}:{expect}:{args}',
    #                                    output=False)
