import enum


class Status(enum.Enum):
    """客户端的状态信息枚举"""
    CONNECTED = '客户端已经连接'
    CONNECT_TIMEOUT = '客户端连接超时'

    DATA_SENDING_TIMEOUT = '数据发送超时'
    DATA_RECEIVE_TIMEOUT = '数据接收超时'

    KEY_ERROR = '密匙验证失败'

    CONFIRMATION_FAILED = '客户端连接确认失败'

    SESSION_TRUE = '会话验证成功'
    SESSION_FALSE = '会话验证失败'

    PARAMETER_ERROR = '参数错误'

    REPLY_ERROR = '回复错误'

    SOCKET_OBJECT_ERROR = '套接字对象错误'


class SyncStatus(enum.Enum):
    """同步状态"""
    DIFF_FILE = '双方文件不同'
    LOCAL_FILE = '本地文件缺失'
    REMOTE_FILE = '远程文件缺失'

class CommandSet(enum.Enum):
    EXSYNC_INSUFFICIENT_PERMISSION = 'EXSync权限不足'
    FAILED = '执行失败'
    SUCCESSFUL = '执行成功'