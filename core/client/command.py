import logging
import os
import shutil
from ast import literal_eval

import xxhash

from core.config import readConfig
from core.tools.status import Status, CommandSet
from core.tools.timedict import TimeDictInit
from core.tools.tools import HashTools, SocketTools

class Config(readConfig):
    def __init__(self):
        super().__init__()
        self.config = readConfig.readJson()
        self.local_ip: str = self.config['server']['addr'].get('ip')
        self.encode_type: str = self.config['server']['setting'].get('encode')
        self.password: str = self.config['server']['addr'].get('password')

class CommandSend(Config):
    """客户端指令发送类"""

    def __init__(self, data_socket, command_socket):
        super().__init__()
        self.data_socket = data_socket
        self.command_socket = command_socket
        # 数据包发送分块大小(含filemark, AES_)
        self.block = 1024

        self.timedict = TimeDictInit(data_socket, command_socket)

    def post_File(self, path: str, mode: int = 1, output_path: str = None):
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
        if not output_path:
            output_path = path

        # 获取8位数长度的文件头标识,用于保证文件的数据唯一性
        filemark = HashTools.getRandomStr(8)
        reply_mark = HashTools.getRandomStr(8)

        local_size = os.path.getsize(path)
        hash_value = HashTools.getFileHash(path)
        data_block = self.block - len(filemark)
        # 远程服务端初始化接收文件
        # 服务端返回信息格式：exist | filesize | filehash | filedate

        command = '''{
            "command": "data",
            "type": "file",
            "method": "post",
            "data": {
                "file_path": "%s",
                "file_size": %s,
                "file_hash": "%s",
                "mode": %s,
                "filemark": "%s"
            }
        }''' % (path, local_size, hash_value, mode, filemark)
        result = SocketTools.sendCommand(self.timedict, self.command_socket, command, mark=reply_mark)
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

        # 本地文件大小，本地文件hash值，远程文件日期
        local_size, local_filehash, local_filedate = local_size, hash_value, os.path.getmtime(path)

        if mode == 0 or mode == 1:
            if mode == 0 and exist:
                return False
            else:
                with open(output_path, mode='rb') as f:
                    if mode == 1 and exist:
                        # 如果服务端已经存在文件，那么重写该文件
                        local_size -= remote_size
                        f.seek(remote_size)
                    data = f.read(data_block)
                    while True:
                        local_size -= data_block
                        if local_size <= 0:
                            break
                        self.data_socket.send(bytes(filemark, 'utf-8') + data)
                        data = f.read(data_block)

        elif mode == 2:
            # 远程服务端准备完成
            xxh = xxhash.xxh3_128()

            if result == 'True':
                block_times, little_block = divmod(remote_size, 8192)
                read_data = 0
                with open(output_path, mode='rb') as f:
                    while True:
                        if read_data < block_times:
                            data = f.read(8192)
                            xxh.update(data)
                            read_data += 1
                        else:
                            data = f.read(little_block)
                            xxh.update(data)
                            break
                file_block_hash = xxh.hexdigest()

                if remote_filehash == file_block_hash:
                    # 文件前段xxhash_128相同，证明为未传输完成文件
                    SocketTools.sendCommand(self.timedict, self.command_socket, f'True', output=False,
                                            mark=reply_mark)

                    with open(output_path, mode='rb') as f:
                        f.seek(remote_size)
                        data = f.read(data_block)
                        while True:
                            if not data:
                                break
                            data = bytes(filemark, 'utf-8') + data
                            self.data_socket.send(data)
                    return True
                else:
                    # ？这是肾么文件，这个文件不是中断传输的产物
                    return False
            return

    def get_File(self, path, output_path=None):
        """
        获取远程文件
        传入获取文件的路径，如果本地文件已经存在则会检查是否为意外中断文件，如果是则继续传输；
        如果本地文件不存在则接收远程文件传输
        如果远程文件不存在则返回False

        output_path: 写入路径（如果未填写则按path参数写入）
        """
        filemark = HashTools.getRandomStr(8)
        reply_mark = HashTools.getRandomStr(8)

        self.timedict.createRecv(filemark, self.password)  # 接下来的文件数据将会加密
        data_block = self.block - len(filemark)

        if os.path.exists(path):
            file_hash = HashTools.getFileHash(path)
            file_size = os.path.getsize(path)
        else:
            file_hash = 0
            file_size = 0

        # 发送指令，远程服务端准备
        # 服务端return: /_com:data:reply:filemark:{remote_size}|{hash_value}
        # result = SocketTools.sendCommand(self.timedict, self.command_socket,
        #                                  f'/_com:data:file:get:{path}|{file_hash}|{file_size}|{filemark}:_',
        #                                  mark=reply_mark, encrypt_password=self.password)
        result = SocketTools.sendCommand(self.timedict, self.command_socket,
                                         '''
                                         {
                                            "command": "data",
                                            "type": "file",
                                            "method": "get",
                                            "data": {
                                                "remote_file_hash": %s,
                                                "remote_size": %s,
                                                "filemark": %s
                                            }
                                         }
                                         ''' % (file_hash, file_size, filemark),
                                         mark=reply_mark, encrypt_password=self.password)
        try:
            values = result.split('|')
        except Exception as e:
            print(e)
            return Status.PARAMETER_ERROR

        remote_file_size, remote_file_hash = values[0], values[1]
        if not remote_file_size:
            # 服务端文件缺失
            return

        if not output_path:
            output_path = path

        if file_size:
            if self.timedict.getRecvData(reply_mark) == "True":
                read_data = 0
                with open(output_path, mode='ab') as f:
                    f.seek(file_size)
                    while True:
                        if read_data < remote_file_size:
                            data = self.timedict.getRecvData(filemark, decrypt_password=self.password)
                        else:
                            return True
                        f.write(data)
                        read_data += data_block
            else:
                return Status.DIFF_FILE
        else:
            read_data = 0
            with open(output_path, mode='ab') as f:
                while True:
                    if read_data < remote_file_size:
                        data = self.timedict.getRecvData(filemark, decrypt_password=self.password)
                    else:
                        return True
                    if data:
                        f.write(data)
                        read_data += data_block
                    else:
                        break

    def post_Folder(self, path):
        """发送文件夹创建指令至服务端"""
        SocketTools.sendCommandNoTimeDict(self.command_socket,
                                          f'/_com:data:folder:post:{path}:_', output=False)
        return True

    def get_Folder(self, path):
        """
        遍历获取远程文件夹下的所有文件夹
        :param path:
        :return folder_paths:
        """
        reply_mark = HashTools.getRandomStr(8)
        result = SocketTools.sendCommand(self.timedict, self.command_socket, f'/_com:data:folder:get:{path}',
                                         output=False, mark=reply_mark)
        if result == Status.DATA_RECEIVE_TIMEOUT:
            return Status.DATA_RECEIVE_TIMEOUT
        elif result == 'pathError':
            return Status.PATH_ERROR
        else:
            return result

    def get_Index(self, spacename):
        """
        传入spacename，获取对方指定同步空间的索引文件
        :param spacename:
        :return Boolean:
        """
        reply_mark = HashTools.getRandomStr(8)
        path = SocketTools.sendCommand(self.timedict, self.command_socket, f'/_com:comm:sync:get:index:{spacename}_',
                                       mark=reply_mark)
        if path == Status.DATA_RECEIVE_TIMEOUT:
            return False
        else:
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
        result = SocketTools.sendCommand(self.timedict, self.command_socket,
                                         f'/_com:comm:sync:post:index:{spacename}|{json_example}|{is_file}:_',
                                         output=False)
        match result:
            case 'remoteIndexNoExist':
                # 远程索引文件不存在
                return
            case 'remoteIndexError':
                # 远程索引文件内容并非是json
                return
            case 'remoteSpaceNameNoExist':
                # 远程同步空间不存在此索引文件
                return
            case 'remoteIndexUpdated':
                # 远程同步空间同步完毕
                return True

    def send_Command(self, command, timeout=2):
        """
        发送指令：以/sync开头的指令为EXSync指令
        :param timeout:
        :param command:
        :return:
        """
        reply_mark = HashTools.getRandomStr(8)
        result = SocketTools.sendCommand(self.timedict, self.command_socket, f'/_com:comm:sync:post:comm:{command}_',
                                         timeout=timeout, mark=reply_mark)

        try:
            result = list(result)
        except Exception as e:
            print(e)
            logging.debug(f'Format result error: {result}')
            return CommandSet.FORMAT_ERROR

        try:
            if result[0] == Status.DATA_RECEIVE_TIMEOUT:
                return Status.DATA_RECEIVE_TIMEOUT
            elif result[0] == CommandSet.EXSYNC_INSUFFICIENT_PERMISSION:
                return CommandSet.EXSYNC_INSUFFICIENT_PERMISSION
            else:
                return result
        except Exception as e:
            print(e)
            logging.warning(f"Command execution failed: {command}")
            return CommandSet.FORMAT_ERROR

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
    #     return SocketTools.sendCommand(self.timedict, self.command_socket,
    #                                    f'/_com:data:reply_end:{filemark}:{expect}:{args}',
    #                                    output=False)
