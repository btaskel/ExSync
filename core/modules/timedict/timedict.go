package timedict

import (
	"errors"
	"time"
)

type TimeDict struct {
	dict      map[string][]byte // TimeDict存储
	closeFlag bool
}

func (t *TimeDict) set(key string, value byte) {
	if _, ok := t.dict[key]; ok && len(t.dict[key]) < 65535 {
		t.dict[key] = append(t.dict[key], value)
	} else {
		t.dict[key] = []byte{byte(time.Now().Unix())}
	}
	//markLs := t.dict[key]

}

func (t *TimeDict) get(key string) (data []byte, err error) {
	tic1 := time.Now().Unix()
	for {
		data := t.dict[key]
		if data == nil {
			if time.Now().Unix()-tic1 > 4 {
				err = errors.New("timeout")
				break
			}
		} else {
			return
		}
	}
	return
}

func (t *TimeDict) delKey(key string) {
	delete(t.dict, key)
}

func (t *TimeDict) hasKey(key string) bool {
	if _, ok := t.dict[key]; ok {
		return true
	} else {
		return false
	}
}

func (t *TimeDict) closeTimeDict() {

}

func (t *TimeDict) release() {

}
