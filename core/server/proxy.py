import logging
import socket

import socks


class Proxy:
    @staticmethod
    def setProxyServer(config: dict, proxy_type: str = 'socks5'):
        """
        并且初始化代理设置
        :return:
        """
        proxy = config['server']['proxy']
        proxy_host = proxy.get('hostname')
        proxy_port = proxy.get('port')
        username = proxy.get('username')
        password = proxy.get('password')
        match proxy_type.lower():
            case 'socks5':
                logging.info(f'proxy type: {proxy_type}')
                proxy_type = socks.SOCKS5
            case 'socks4':
                logging.info(f'proxy type: {proxy_type}')
                proxy_type = socks.SOCKS4
            case 'http':
                logging.info(f'proxy type: {proxy_type}')
                proxy_type = socks.HTTP
            case _:
                logging.warning(f'Unknown proxy type: {proxy_type}')
                return socket.socket

        socks.set_default_proxy(proxy_type=proxy_type, addr=proxy_host, port=proxy_port, username=username,
                                password=password)
        return socks.socksocket
