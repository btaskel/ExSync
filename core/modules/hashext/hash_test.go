package hashext

import (
	"fmt"
	"testing"
)

//go test .\hash_test.go .\hash.go

func TestGetRandomStr(t *testing.T) {
	t.Logf("TestGetRandomStr passed:%v", GetRandomStr(8))
}

func TestGetXXHash(t *testing.T) {
	hash, err := getXXHash("test.txt")
	if err != nil {
		return
	}
	fmt.Println(hash)
	t.Logf("hash: %v", hash)
}
