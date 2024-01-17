package socket

import (
	"net"
)

//
//func send() {
//
//}

// recv 从一个套接字中读取数据
func recv(conn net.Conn) ([]byte, error) {
	//render := bufio.NewReader(conn)
	//buf := make([]byte, 4096)
	//for {
	//	n, err := Conn.Read(buf[:])
	//	if err != nil {
	//
	//	}
	//}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
