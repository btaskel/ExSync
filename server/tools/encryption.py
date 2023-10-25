from hashlib import sha256

from Crypto.Cipher import AES


class CryptoTools:
    """加解密套件"""

    def __init__(self, key: str, method: str = 'aes-ctr'):
        if method.lower() == 'aes-ctr':
            self.key = sha256(key.encode('utf-8')).hexdigest()[:16]
        else:
            raise ValueError(f'Unsupported password suite: {method}')
        self.cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
        self.nonce = self.cipher.nonce

    def aes_ctr_encrypt(self, message: str or bytes) -> bytes:
        """aes-128-ctr 加密"""
        if type(message) is bytes:
            ciphertext = self.cipher.encrypt(message)
        else:
            ciphertext = self.cipher.encrypt(message.encode('utf-8'))
        return ciphertext

    def aes_ctr_decrypt(self, ciphertext: bytes) -> str:
        """aes-128-ctr 解密"""
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR, nonce=self.nonce)
        plaintext = cipher.decrypt(ciphertext[8:])
        return plaintext.decode('utf-8')


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
    print(encry)
    decry = cry.aes_ctr_decrypt(encry)
    print(decry)
