package socket

import (
	"EXSync/core/modules/encryption"
	"EXSync/core/modules/timedict"
	"encoding/json"
	"errors"
	"net"
)

//// SendCommand 发送指令并准确接收返回数据
////
////	例： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。
////
////	1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
////	2. 在发送指令的前方追加[答复ID]，编码发送。
////	3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。
//func (s *Session) SendCommand() (err error) {
//
//}

// NewSession 使用with快速创建一个会话, 可以省去每次填写sendCommand()部分形参的时间
//
//	data_socket & command_socket:
//	SocketSession会根据传入了哪些形参而确定会话方法
//	1: 当data, command都未传入, 将抛出异常;
//	2: 当data传入, command为空, 将会只按data_socket进行收发，不会经过对方的指令处理;
//	3: 当command传入, data为空，将会按照sendCommandNoTimedict()进行对话(特殊用途);
//	4: 当data, command都传入, 第一条会通过command_socket发送至对方的指令处理,
//	    接下来的会话将会使用data_socket进行处理(适用于指令环境下);
func NewSession(timedict *timedict.SocketTimeDict, dataSocket net.Conn, commandSocket net.Conn, mark string, key string) (*Session, error) {

	if len(mark) != 8 {
		return nil, errors.New("SocketSession: Mark标识缺少")
	}

	if dataSocket == nil && commandSocket == nil {
		return nil, errors.New("SocketSession: data_socket和command_socket未传入")
	}

	method := 0
	if dataSocket != nil && commandSocket != nil {
		method = 0
	} else if dataSocket != nil && commandSocket == nil {
		method = 1
	} else {
		method = 2
	}

	aesGcm, err := encryption.NewGCM(key)
	if err != nil {
		return nil, err
	}

	return &Session{
		timeDict:      timedict,
		dataSocket:    dataSocket,
		commandSocket: commandSocket,
		mark:          mark,
		method:        method,
		aesGCM:        aesGcm,
	}, nil
}

type Session struct {
	timeDict      *timedict.SocketTimeDict
	dataSocket    net.Conn
	commandSocket net.Conn
	mark          string
	count         int
	method        int
	aesGCM        *encryption.Gcm
}

// Recv 从指定mark队列接收数据
func (s *Session) Recv() (data []byte, ok bool) {
	data, ok = s.timeDict.Get(s.mark)
	return
}

// GetSessionCount 当前会话次数
func (s *Session) GetSessionCount() int {
	return s.count
}

// Send 如果发送为[]byte类型，则立即发送
// 如果发送为map[string]interface{}类型，则立即发送
func (s *Session) Send(data interface{}, output bool) (result map[string]interface{}, err error) {
	switch data.(type) {
	case map[string]interface{}:
		v := data.(map[string]interface{})
		switch s.method {
		case 0:
			var conn net.Conn
			if s.count == 0 {
				conn = s.commandSocket
			} else {
				conn = s.dataSocket
			}
			return s.sendTimeDict(conn, v, output)
		case 1:
			return s.sendTimeDict(s.dataSocket, v, output)
		case 2:
			return s.sendNoTimeDict(s.commandSocket, v, output)
		}
		panic("错误的Session发送方法")
	case []byte:
		v := data.([]byte)
		if s.aesGCM != nil {
			if len(v) > 4056 {
				panic("sendNoTimeDict: 指令发送时大于1008个字节")
			} else if len(v) < 40 {
				panic("sendNoTimeDict: 指令发送时无字节")
			}
			byteData, err := s.aesGCM.AesGcmEncrypt(append([]byte(s.mark), v...))
			if err != nil {
				return nil, err
			}
			_, err = s.dataSocket.Write(byteData)
			if err != nil {
				return nil, err
			}
			return nil, nil
		} else {
			if len(v) > 4088 {
				panic("sendNoTimeDict: 指令发送时大于1016个字节")
			} else if len(v) < 40 {
				panic("sendNoTimeDict: 指令发送时无字节")
			}
			byteData := append(append([]byte(s.mark), v...))
			_, err := s.dataSocket.Write(byteData)
			if err != nil {
				return nil, err
			}
			return nil, nil
		}

	default:
		panic("错误的Session发送类型")
	}
}

//func process(conn net.Conn) {
//	defer conn.Close()
//	reader := bufio.NewReader(conn)
//	var buf [4096]byte
//	for {
//		n, err := reader.Read(buf[:])
//		if err != nil {
//			fmt.Printf("read from conn failed, err:%v\n", err)
//			break
//		}
//		fmt.Printf("收到的数据：%v\n", string(buf[:n]))
//	}
//}

func (s *Session) sendNoTimeDict(conn net.Conn, data interface{}, output bool) (map[string]interface{}, error) {

	switch v := data.(type) {
	case []byte:
		if s.aesGCM != nil {
			if len(v) > 4056 {
				panic("sendNoTimeDict: 指令发送时大于1008个字节")
			} else if len(v) < 40 {
				panic("sendNoTimeDict: 指令发送时无字节")
			}
			v, err := s.aesGCM.AesGcmEncrypt(append([]byte(s.mark), v...))
			if err != nil {
				return nil, err
			}
			// 发送数据
			_, err = conn.Write(v)
			if err != nil {
				//netErr.Timeout()
				return nil, err
			}
		} else {
			if len(v) > 4088 {
				panic("sendNoTimeDict: 指令发送时大于1016个字节")
			} else if len(v) < 40 {
				panic("sendNoTimeDict: 指令发送时无字节")
			}
			// 发送数据
			_, err := conn.Write(v)
			if err != nil {
				//netErr.Timeout()
				return nil, err
			}
		}

		// 接收数据
		if output {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			var result []byte
			if s.aesGCM != nil {
				result, err = s.aesGCM.AesGcmDecrypt(buf[:n])
			} else {
				result = buf[:n]
			}
			var decodeData map[string]interface{}
			err = json.Unmarshal(result, &decodeData)
			return decodeData, nil
		} else {
			return nil, nil
		}

	case map[string]interface{}:
		if s.aesGCM != nil {
			if len(v) > 4056 {
				panic("sendNoTimeDict: 指令发送时大于1008个字节")
			} else if len(v) < 40 {
				panic("sendNoTimeDict: 指令发送时无字节")
			}
		} else {
			if len(v) > 4088 {
				panic("sendNoTimeDict: 指令发送时大于1016个字节")
			} else if len(v) < 40 {
				panic("sendNoTimeDict: 指令发送时无字节")
			}
		}

		commandJson, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		_, err = conn.Write(commandJson)
		if err != nil {
			//netErr.Timeout()
			return nil, err
		}

		if output {
			buf := make([]byte, 4096)
			n, err := conn.Read(buf)
			if err != nil {
				return nil, err
			}
			var decodeData map[string]interface{}
			err = json.Unmarshal(buf[:n], &decodeData)
			return decodeData, nil
		} else {
			return nil, nil
		}
	default:
		panic("sendNoTimeDict：未知类型数据发送")
	}
}

// sendTimeDict 发送指令并准确接收返回数据
//
//	例： 本地客户端发送至对方服务端 获取文件 的指令（对方会返回数据）。
//
//	1. 生成 8 长度的字符串作为[答复ID]，并以此在timedict中创建一个接收接下来服务端回复的键值。
//	2. 在发送指令的前方追加[答复ID]，编码发送。
//	3. 从timedict中等待返回值，如果超时，返回DATA_RECEIVE_TIMEOUT。
//
//	output: 设置是否等待接下来的返回值。
//	socket_: 客户端选择使用（Command Socket/Data Socket）作为发送套接字（在此例下是主动发起请求方，为Command_socket）。
//	command: 设置发送的指令, 如果为字典类型则转换为json发送。
//	return: 如果Output=True在发送数据后等待对方返回一条数据; 否则仅发送
func (s *Session) sendTimeDict(conn net.Conn, command map[string]interface{}, output bool) (map[string]interface{}, error) {
	s.timeDict.CreateRecv(s.mark)
	commandJson, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}

	if s.aesGCM != nil {
		if len(commandJson) > 4056 {
			panic("sendNoTimeDict: 指令发送时大于1008个字节")
		} else if len(commandJson) < 40 {
			panic("sendNoTimeDict: 指令发送时无字节")
		}
		commandJson, err = s.aesGCM.AesGcmEncrypt(append([]byte(s.mark), commandJson...))
		if err != nil {
			return nil, err
		}

	} else {
		if len(commandJson) > 4088 {
			panic("sendNoTimeDict: 指令发送时大于1016个字节")
		} else if len(commandJson) < 40 {
			panic("sendNoTimeDict: 指令发送时无字节")
		}
	}
	_, err = conn.Write(append([]byte(s.mark), commandJson...))
	if err != nil {
		return nil, err
	}

	var decodeData map[string]interface{}
	if output {
		data, ok := s.timeDict.Get(s.mark)
		if ok {
			err := json.Unmarshal(data, &decodeData)
			if err != nil {
				return nil, err
			}
			return decodeData, nil
		}
	}
	return nil, nil
}
