package encryption

import (
	"testing"
)

func TestGcm_AesGcmEncrypt(t *testing.T) {
	gcm := gcm{key: []byte("123456")}
	encrypt, err := gcm.AesGcmEncrypt([]byte("测试文本内容"))
	if err != nil {
		return
	}
	t.Logf("______")

	t.Logf("加密内容: %v", encrypt)
}
