package encryption

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

const dataLength = 4096 // 加密后允许的最大长度

func NewGCM(key string) (*Gcm, error) {
	block, err_ := aes.NewCipher([]byte(key))
	if err_ != nil {
		return nil, err_
	}
	aesGCM, err_ := cipher.NewGCM(block)
	if err_ != nil {
		return nil, err_
	}
	return &Gcm{Key: []byte(key), aesGCM: aesGCM}, nil
}

type Gcm struct {
	Key    []byte
	aesGCM cipher.AEAD
}

// AesGcmEncrypt 使用aes-ctr加密并转换为base64
func (g *Gcm) AesGcmEncrypt(data []byte) (res []byte, err error) {
	if len(data)-40 > dataLength {
		return nil, errors.New("lengthError")
	} else {
		nonce := make([]byte, g.aesGCM.NonceSize())
		if _, err_ := io.ReadFull(rand.Reader, nonce); err_ != nil {
			return nil, err_
		}
		ciphertext := g.aesGCM.Seal(nil, nonce, data, nil)
		return ciphertext, nil
	}
}

// AesGcmDecrypt 解密一个使用aes-ctr base64转码的字符串
func (g *Gcm) AesGcmDecrypt(data []byte) ([]byte, error) {
	nonceSize := g.aesGCM.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertextTooShort")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := g.aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

// B64GCMEncrypt 使用aes-ctr加密并转换为base64
func (g *Gcm) B64GCMEncrypt(data []byte) (string, error) {
	ciphertext, err := g.AesGcmEncrypt(data)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// B64GCMDecrypt 解密一个使用aes-ctr base64转码的字符串
func (g *Gcm) B64GCMDecrypt(data string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, err
	}

	return g.AesGcmDecrypt(ciphertext)
}
