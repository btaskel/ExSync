package timedict

import (
	"encoding/binary"
	"errors"
	"time"
)

type TimeDict struct {
	dict      map[string][][]byte // TimeDict存储
	closeFlag bool
}

func (t *TimeDict) set(key string, value []byte) {
	if _, ok := t.dict[key]; ok && len(t.dict[key]) < 65535 {
		t.dict[key] = append(t.dict[key], value)
	} else {
		now := time.Now().Unix()
		var data []byte
		binary.BigEndian.PutUint64(data, uint64(now))
		t.dict[key] = [][]byte{data}
	}
	//markLs := t.dict[key]

}

func (t *TimeDict) get(key string) (data []byte, err error) {
	tic1 := time.Now().Unix()
	for {
		result := t.dict[key]
		if result == nil {
			if tic1-int64(binary.BigEndian.Uint64(result[0])) > 4 {
				err = errors.New("timeout")
				break
			}
		} else {
			return result[1], err
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
	for {
		if !t.closeFlag {
			t.dict = make(map[string][][]byte)
			return
		}

		for key, value := range t.dict {
			timeStamp := value[0]
			if time.Now().Unix()-int64(binary.BigEndian.Uint64(timeStamp)) > 8 {
				delete(t.dict, key)
			}
		}

	}
}
