import enum


class Status(enum):
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
