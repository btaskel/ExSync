package hashext

import (
	"bufio"
	"fmt"
	"github.com/cespare/xxhash/v2"
	"io"
	"math/rand"
	"os"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func GetRandomStr(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// getXXHash 获取一个文件的64位的xx哈希值
func getXXHash(path string) (fileHash string, err error) {
	file, err := os.Open(path)
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			return
		}
	}(file)

	render := bufio.NewReader(file)
	buffer := make([]byte, 8192)

	hasher := xxhash.New()

	for {
		n, err := render.Read(buffer) // 从渲染器中读取到buffer切片
		if err != nil && err != io.EOF {
			return "", err
		}
		if n == 0 {
			break
		}
		_, err = hasher.Write(buffer)
		if err != nil {
			return "", err
		}
	}
	//return string(hasher.Sum(nil)), nil
	return fmt.Sprintf("%x", hasher.Sum(nil)), nil
}
