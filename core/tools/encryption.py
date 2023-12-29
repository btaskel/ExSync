import base64
import logging
from hashlib import sha256

from Crypto.Cipher import AES


class CryptoTools:
    """加解密套件"""

    def __init__(self, key: str, method: str = 'aes-ctr', textLength: int = 1024):
        """
        :param key: 密码
        :param method: 加密方式(默认AES-CTR)
        :param textLength: 文本长度
        """
        if method.lower() == 'aes-ctr':
            self.key = sha256(key.encode('utf-8')).hexdigest()[:16]
        else:
            raise ValueError(f'Unsupported password suite: {method}')
        self.textLength = textLength

    def aes_ctr_encrypt(self, message: str or bytes, offset: int = 0) -> bytes:
        """
        aes-128-ctr 加密
        数据内容占用1008个字节
        :param message: 数据内容
        :param offset: 偏移值：默认按nonce + Mark加密后1024个字节; offset会补偿诺干字节
        :return:
        """
        if len(message) > (self.textLength - 8 + offset):  # nonce 和 mark 共需要16个字节
            raise ValueError('aes_ctr_encrypt加密时遇到超过1008个字节的信息流')
        elif isinstance(message, bytes):
            cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
            ciphertext = cipher.encrypt(message)
        else:
            cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
            ciphertext = cipher.encrypt(message.encode('utf-8'))
        return cipher.nonce + ciphertext

    def aes_ctr_decrypt(self, ciphertext: bytes) -> bytes:
        """aes-128-ctr 解密"""
        if len(ciphertext) > 8:
            content, nonce = ciphertext[8:], ciphertext[:8]

            cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)
            plaintext = cipher.decrypt(content)
            # logging.debug('Core : AES_Ctr_Decrypt decryption failed!')
            return plaintext
        else:
            logging.debug('Core : AES_Ctr_Decrypt execution failed!')
            raise ValueError('Core : AES_Ctr_Decrypt execution failed!')

    def b64_ctr_encrypt(self, message: bytes) -> str:
        """
        使用aes-ctr加密并转换为base64
        :param message: 最初数据
        :return:
        """
        encry_message = self.aes_ctr_encrypt(message)
        return base64.b64encode(encry_message).decode('utf-8')

    def b64_ctr_decrypt(self, message: str) -> bytes:
        """
        解密一个使用aes-ctr base64转码的字符串
        :param message: b64_ctr_encrypt加密后的数据
        :return:
        """
        b64 = base64.b64decode(message)
        return self.aes_ctr_decrypt(b64)


if __name__ == '__main__':
    cry = CryptoTools('123')
    encry = cry.aes_ctr_encrypt('awdhawdihawdoiw')
    # print(encry)
    # print(base64.b64encode(encry).decode())
    # decry = cry.aes_ctr_decrypt(encry)
    print(cry.aes_ctr_decrypt(encry))
    # print(decry)

    # string = b'\x939\xca|\xc1\x19J\x7fE\x19_\xde\xde_\xbc\xed\xc6zj\x11\x95\xf1;'
    # string = base64.b64encode(string).decode()
    # print(string)
    # awdhawdihawdoiw
