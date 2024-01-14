package client

import (
	"encoding/json"
	"errors"
	"github.com/sirupsen/logrus"
	"net"
	"strconv"
	"time"
)

type Client struct {
	CommandSocket     net.Conn
	DataSocket        net.Conn
	CommandSocketPort int
	DataSocketPort    int
	HostInfo          map[string]string
	IP                string
}

func (c *Client) setProxy() {
	return
}

func (c *Client) initSocket() (error error) {

	return
}

func (c *Client) connectRemoteCommandSocket() (error error) {
	connectVerify := func(debugStatus bool) bool {

	}
	connectVerifyNoPassword := func(publicKey string, output bool) bool {

	}

	direct := func() bool {
		address := c.IP + ":" + strconv.Itoa(c.CommandSocketPort)
		conn, err := net.DialTimeout("tcp", address, time.Duration(4)*time.Second)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				error = errors.New("timeout")
				return false
			} else {
				error = errors.New("unknownError")
			}
		}
		c.CommandSocket = conn
	}
	check := func() bool {
		for i := 0; i < 3; i++ {
			logrus.Debugf("Connecting to server %v for the %vth time", c.IP, i)
			address := c.IP + ":" + strconv.Itoa(c.CommandSocketPort)
			conn, err := net.DialTimeout("tcp", address, time.Duration(4)*time.Second)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					error = errors.New("timeout")
					return false
				} else {
					error = errors.New("unknownError")
				}
			}
			// 1.本地发送验证指令:发送指令开始进行验证
			command := map[string]interface{}{
				"command": "comm",
				"type":    "verifyconnect",
				"method":  "post",
				"data": map[string]string{
					"version": "0.01",
				},
			}
			jsonData, err := json.Marshal(command)
			if err != nil {
				return false
			}

		}

	}

}
