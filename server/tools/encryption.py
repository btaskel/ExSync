from hashlib import sha256

from Crypto.Cipher import AES


class CryptoTools:
    """加解密套件"""

    def __init__(self, key: str, method: str = 'aes-ctr'):
        if method == 'aes-ctr':
            self.key = sha256(key.encode('utf-8')).hexdigest()[:16]
        else:
            raise ValueError(f'Unsupported password suite: {method}')

    def aes_ctr_encrypt(self, message: str) -> bytes:
        """aes-128-ctr 加密"""
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR)
        ciphertext = cipher.encrypt(message.encode('utf-8'))
        return cipher.nonce + ciphertext

    def aes_ctr_decrypt(self, ciphertext: bytes) -> str:
        """aes-128-ctr 解密"""
        nonce = ciphertext[:8]
        cipher = AES.new(self.key.encode('utf-8'), AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext[8:])
        return plaintext.decode('utf-8')


if __name__ == '__main__':
    cry = CryptoTools('123')
    encry = cry.aes_ctr_encrypt('message test')
    decry = cry.aes_ctr_decrypt(encry)
    print(decry)
