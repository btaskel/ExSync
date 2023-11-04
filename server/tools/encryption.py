import logging
from hashlib import sha256

from Crypto.Cipher import AES


class CryptoTools:
    """加解密套件"""

    def __init__(self, key: str, method: str = 'aes-ctr', textLength: int = 1024):
        if method.lower() == 'aes-ctr':
            self.key = sha256(key.encode('utf-8')).hexdigest()[:16]
        else:
            raise ValueError(f'Unsupported password suite: {method}')
        self.textLength = textLength

    def aes_ctr_encrypt(self, message: str or bytes) -> bytes:
        """
        aes-128-ctr 加密
        数据内容占用1008个字节
        """
        block = self.textLength - 16  # nonce 和 mark 共需要16个字节
        if len(message) > block:
            raise ValueError('aes_ctr_encrypt加密时遇到超过1008个字节的信息流')
        elif type(message) is bytes:
            cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
            ciphertext = cipher.encrypt(message)
        else:
            cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
            ciphertext = cipher.encrypt(message.encode('utf-8'))
        return cipher.nonce + ciphertext

    def aes_ctr_decrypt(self, ciphertext: bytes):
        """aes-128-ctr 解密"""
        if len(ciphertext) > 8:
            content, nonce = ciphertext[8:], ciphertext[:8]

            cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)
            try:
                plaintext = cipher.decrypt(content)
            except Exception as e:
                print(e)
                logging.debug('Core : AES_Ctr_Decrypt decryption failed!')
                return

            return plaintext.decode('utf-8')
        else:
            logging.debug('Core : AES_Ctr_Decrypt execution failed!')
            return


class AESSession(CryptoTools):
    """加密套件会话"""

    def __init__(self, key: str, method: str = 'aes-ctr'):
        super().__init__(key, method)

    def encry(self, message: str or bytes) -> bytes:
        return self.aes_ctr_encrypt(message)

    def decry(self, ciphertext: bytes) -> str:
        return self.aes_ctr_decrypt(ciphertext)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


if __name__ == '__main__':
    cry = CryptoTools('123')
    encry = cry.aes_ctr_encrypt('awdhawdihawdoiw')
    print(len(encry))
    decry = cry.aes_ctr_decrypt(encry)
    print(len(decry))
