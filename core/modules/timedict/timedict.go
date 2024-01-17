package timedict

import (
	"EXSync/core/modules/encryption"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"
)

func NewTimeDict() *TimeDict {
	timedict := &TimeDict{
		dict: sync.Map{},
	}
	go func() {
		timedict.release()
	}()

	return timedict
}

type TimeDict struct {
	//dict map[string][][]byte // TimeDict存储
	dict      sync.Map
	closeFlag bool
}

// CreateRecv 创建一个数据流接收队列
func (t *TimeDict) CreateRecv(mark string) {
	if len(mark) != 8 && t.HasKey(mark) {
		return
	}
	now := time.Now().Unix()
	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(now))
	//t.dict[mark] = [][]byte{data}
	t.dict.Store(mark, [][]byte{data})
}

func (t *TimeDict) Set(key string, value []byte) bool {
	v, ok := t.dict.Load(key)
	values := v.([][]byte)
	if len(values) >= 65535 {
		return false
	}
	if ok {
		timeStamp := make([]byte, 8)
		binary.BigEndian.PutUint64(timeStamp, uint64(time.Now().Unix()))
		values[0] = timeStamp
		t.dict.Store(key, append(values, value))
		return true
	} else {
		return false
	}
}

func (t *TimeDict) Get(key string) (data []byte, ok bool) {
	tic1 := time.Now().Unix()
	for {
		v, ok := t.dict.Load(key)
		if ok {
			result := v.([][]byte)
			if len(result) > 2 {
				date := make([]byte, 8)
				binary.BigEndian.PutUint64(date, uint64(time.Now().Unix()))
				dataSlice := make([][]byte, 0)
				dataSlice = append(dataSlice, date)
				dataSlice = append(dataSlice, result[2:]...)
				t.dict.Store(key, dataSlice)
				return result[1], true
			} else {
				if tic1-int64(binary.BigEndian.Uint64(result[0])) > 4 {
					return nil, false
				} else {
					continue
				}
			}
		} else {
			return nil, false
		}
	}
}

func (t *TimeDict) DelKey(key string) {
	t.dict.Delete(key)
}

func (t *TimeDict) HasKey(key string) bool {
	if _, ok := t.dict.Load(key); ok {
		return true
	} else {
		return false
	}
}

// CloseTimeDict 关闭timedict
func (t *TimeDict) CloseTimeDict() {
	t.closeFlag = true
}

func (t *TimeDict) release() {
	for {
		if !t.closeFlag {
			t.dict = sync.Map{}
			return
		}
		t.dict.Range(func(key, value any) bool {
			timeStamp := value.([][]byte)[0]
			if time.Now().Unix()-int64(binary.BigEndian.Uint64(timeStamp)) > 8 {
				t.dict.Delete(key)
			}
			return true
		})
		//for key, value := range t.dict {
		//	timeStamp := value[0]
		//	if time.Now().Unix()-int64(binary.BigEndian.Uint64(timeStamp)) > 8 {
		//		t.dict.Delete(key)
		//	}
		//}
	}
}

// NewSocketTimeDict 创建SocketTimeDict实例
func NewSocketTimeDict(key string) *SocketTimeDict {
	return &SocketTimeDict{TimeDict{dict: sync.Map{}}, key}
}

type SocketTimeDict struct {
	TimeDict
	Key string
}

func (s *SocketTimeDict) RecvData(conn net.Conn) {
	go func() {
		gcm, err := encryption.NewGCM(s.Key)
		if err != nil {
			panic("SocketTimeDict解密失败")
		}
		for {
			if s.closeFlag {
				err := conn.Close()
				if err != nil {
					return
				}
				return
			}
			//render := bufio.NewReader(conn)
			//var buf [4096]byte
			//n, err := render.Read(buf[:])
			//if err != nil {
			//	break
			//}
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err == io.EOF {
				s.CloseTimeDict()
				break
			}

			data, err := gcm.AesGcmDecrypt(buf[:n])
			if err != nil {
				return
			}
			if len(data) <= 8 {
				continue
			}
			key := string(data[:8])
			if !s.HasKey(key) {
				continue
			}
			s.Set(key, data[8:])
		}
	}()
}
