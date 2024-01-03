import base64
import logging
from hashlib import sha256

from Crypto.Cipher import AES


class CryptoTools:
    """加解密套件"""

    def __init__(self, key: str, textLength: int = 4096):
        """
        :param key: 密码
        :param textLength: 文本长度
        """
        self.key = sha256(key.encode('utf-8')).hexdigest()[:16]
        self.textLength = textLength

    # def aes_ctr_encrypt(self, data: str or bytes, offset: int = 0) -> bytes:
    #     """
    #     aes-128-ctr 加密
    #     数据内容占用4080个字节
    #     :param data: 数据内容
    #     :param offset: 偏移值：默认按nonce + Mark加密后1024个字节; offset会补偿诺干字节
    #     :return:
    #     """
    #     if len(data) > (self.textLength - 8 + offset):  # nonce 和 mark 共需要16个字节
    #         raise ValueError('aes_ctr_encrypt加密时遇到超过1008个字节的信息流')
    #     elif isinstance(data, bytes):
    #         cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
    #         ciphertext = cipher.encrypt(data)
    #     else:
    #         cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
    #         ciphertext = cipher.encrypt(data.encode('utf-8'))
    #     return cipher.nonce + ciphertext
    #
    # def aes_ctr_decrypt(self, ciphertext: bytes) -> bytes:
    #     """aes-128-ctr 解密"""
    #     if len(ciphertext) > 8:
    #         content, nonce = ciphertext[8:], ciphertext[:8]
    #
    #         cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)
    #         plaintext = cipher.decrypt(content)
    #         # logging.debug('Core : AES_Ctr_Decrypt decryption failed!')
    #         return plaintext
    #     else:
    #         logging.debug('Core : AES_Ctr_Decrypt execution failed!')
    #         raise ValueError('Core : AES_Ctr_Decrypt execution failed!')
    #
    # def b64_ctr_encrypt(self, data: bytes) -> str:
    #     """
    #     使用aes-ctr加密并转换为base64
    #     :param data: 最初数据
    #     :return:
    #     """
    #     encry_message = self.aes_ctr_encrypt(data)
    #     return base64.b64encode(encry_message).decode('utf-8')
    #
    # def b64_ctr_decrypt(self, data: str) -> bytes:
    #     """
    #     解密一个使用aes-ctr base64转码的字符串
    #     :param data: b64_ctr_encrypt加密后的数据
    #     :return:
    #     """
    #     b64 = base64.b64decode(data)
    #     return self.aes_ctr_decrypt(b64)

    def b64_gcm_encrypt(self, data: bytes) -> str:
        """
        使用aes-ctr加密并转换为base64
        :param data: 最初数据
        :return:
        """
        encry_message = self.aes_gcm_encrypt(data)
        return base64.b64encode(encry_message).decode('utf-8')

    def b64_gcm_decrypt(self, data: str) -> bytes:
        """
        解密一个使用aes-ctr base64转码的字符串
        :param data: b64_ctr_encrypt加密后的数据
        :return:
        """
        b64 = base64.b64decode(data)
        return self.aes_gcm_decrypt(b64)

    def aes_gcm_encrypt(self, data: str or bytes) -> bytes:
        if len(data) - 40 > self.textLength:
            raise ValueError('DataLengthError')
        elif isinstance(data, str):
            data = data.encode('utf-8')
        elif isinstance(data, bytes):
            pass
        else:
            raise ValueError('DataTypeError')
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        return cipher.nonce + tag + ciphertext

    def aes_gcm_decrypt(self, data: bytes) -> bytes:
        nonce = data[:16]
        tag = data[16:32]
        data_ = data[32:]
        if not nonce or not tag or not data_:
            raise ValueError('aes_gcm_decrypt:DataError')
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(data_, tag)


if __name__ == '__main__':
    cry = CryptoTools('123')
    result = cry.aes_gcm_encrypt('aawdawdabc'.encode())
    de_result = cry.aes_gcm_decrypt(b'dawwadawdawdwadawdawdawdawdawdawdwdawdwwad')
    print(de_result)
    # encry = cry.aes_ctr_encrypt('awdhawdihawdoiw')
    # print(cry.aes_ctr_decrypt(b'ajwdawodjwad').decode('utf-8'))
    # print(encry)
    # print(base64.b64encode(encry).decode())
    # decry = cry.aes_ctr_decrypt(encry)

    # print(decry)

    # string = b'\x939\xca|\xc1\x19J\x7fE\x19_\xde\xde_\xbc\xed\xc6zj\x11\x95\xf1;'
    # string = base64.b64encode(string).decode()
    # print(string)
    # awdhawdihawdoiw
