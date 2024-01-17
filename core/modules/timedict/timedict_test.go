package timedict

import (
	"fmt"
	"testing"
)

//func TestSocketTimeDict_RecvData(t *testing.T) {
//	timedict := SocketTimeDict{}
//	timedict.set("abc", []byte{5})
//	fmt.Println(timedict.get("abc"))
//}

func TestNewTimeDict(t *testing.T) {
	timedict := NewTimeDict()
	timedict.Set("abc", []byte{5})
	get, err := timedict.Get("abc")
	if err != nil {
		return
	}
	fmt.Println(get)
}
