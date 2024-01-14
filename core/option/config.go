package option

import (
	"EXSync/core/modules/hashext"
	"encoding/json"
	"github.com/sirupsen/logrus"
	"os"
	"path/filepath"
)

const configPath = ".\\data\\config"

type Config struct {
	Log struct {
		LogLevel string `json:"loglevel"`
	} `json:"log"`
	Server struct {
		Addr struct {
			ID       string `json:"id"`
			IP       string `json:"ip"`
			Port     int    `json:"port"`
			Password string `json:"password"`
		} `json:"addr"`
		Setting struct {
			Encode     string `json:"encode"`
			IOBalance  bool   `json:"iobalance"`
			Encryption string `json:"encryption"`
		} `json:"setting"`
		Scan struct {
			Enabled bool     `json:"enabled"`
			Type    string   `json:"type"`
			Max     int      `json:"max"`
			Devices []string `json:"devices"`
		} `json:"scan"`
		Plugin struct {
			Enabled   bool     `json:"enabled"`
			Blacklist []string `json:"blacklist"`
		} `json:"plugin"`
		Proxy struct {
			Enabled  bool   `json:"enabled"`
			Hostname string `json:"hostname"`
			Port     int    `json:"port"`
			Username string `json:"username"`
			Password string `json:"password"`
		} `json:"proxy"`
	} `json:"server"`
	Userdata []struct {
		Spacename string   `json:"spacename"`
		Path      string   `json:"path"`
		Interval  int      `json:"interval"`
		Autostart bool     `json:"autostart"`
		Active    bool     `json:"active"`
		Devices   []string `json:"devices"`
	} `json:"userdata"`
	Version float64 `json:"version"`
}

// LoadConfig 加载Config文件
func (c *Config) LoadConfig() (config map[string]interface{}, err error) {
	file, err := os.ReadFile(filepath.Join(configPath, "config.json"))
	if err != nil {
		return
	}
	err = json.Unmarshal(file, &config)
	if err != nil {
		return
	}
	return
}

// CreateConfig 创建配置文件
func (c *Config) CreateConfig() (err error) {
	config := Config{
		Log: struct {
			LogLevel string `json:"loglevel"`
		}{
			LogLevel: "info",
		},
		Server: struct {
			Addr struct {
				ID       string `json:"id"`
				IP       string `json:"ip"`
				Port     int    `json:"port"`
				Password string `json:"password"`
			} `json:"addr"`
			Setting struct {
				Encode     string `json:"encode"`
				IOBalance  bool   `json:"iobalance"`
				Encryption string `json:"encryption"`
			} `json:"setting"`
			Scan struct {
				Enabled bool     `json:"enabled"`
				Type    string   `json:"type"`
				Max     int      `json:"max"`
				Devices []string `json:"devices"`
			} `json:"scan"`
			Plugin struct {
				Enabled   bool     `json:"enabled"`
				Blacklist []string `json:"blacklist"`
			} `json:"plugin"`
			Proxy struct {
				Enabled  bool   `json:"enabled"`
				Hostname string `json:"hostname"`
				Port     int    `json:"port"`
				Username string `json:"username"`
				Password string `json:"password"`
			} `json:"proxy"`
		}{
			Addr: struct {
				ID       string `json:"id"`
				IP       string `json:"ip"`
				Port     int    `json:"port"`
				Password string `json:"password"`
			}{
				ID:       hashext.GetRandomStr(8),
				IP:       "127.0.0.1",
				Port:     5002,
				Password: hashext.GetRandomStr(10),
			},
			Setting: struct {
				Encode     string `json:"encode"`
				IOBalance  bool   `json:"iobalance"`
				Encryption string `json:"encryption"`
			}{
				Encode:     "utf-8",
				IOBalance:  false,
				Encryption: "AES_ECB",
			},
			Scan: struct {
				Enabled bool     `json:"enabled"`
				Type    string   `json:"type"`
				Max     int      `json:"max"`
				Devices []string `json:"devices"`
			}{
				Enabled: true,
				Type:    "lan",
				Max:     5,
				Devices: []string{"127.0.0.1:5001"},
			},
			Plugin: struct {
				Enabled   bool     `json:"enabled"`
				Blacklist []string `json:"blacklist"`
			}{
				Enabled:   true,
				Blacklist: []string{},
			},
			Proxy: struct {
				Enabled  bool   `json:"enabled"`
				Hostname string `json:"hostname"`
				Port     int    `json:"port"`
				Username string `json:"username"`
				Password string `json:"password"`
			}{
				Enabled:  false,
				Hostname: "localhost",
				Port:     0,
				Username: "",
				Password: "",
			},
		},
		Userdata: []struct {
			Spacename string   `json:"spacename"`
			Path      string   `json:"path"`
			Interval  int      `json:"interval"`
			Autostart bool     `json:"autostart"`
			Active    bool     `json:"active"`
			Devices   []string `json:"devices"`
		}{
			{
				Spacename: "",
				Path:      "",
				Interval:  30,
				Autostart: true,
				Active:    true,
				Devices:   []string{""},
			},
		},
		Version: 0.01,
	}

	// 创建一个文件
	configJsonPath := filepath.Join(configPath, "config.json")
	_, err = os.Stat(configJsonPath)
	if !os.IsNotExist(err) {
		return
	}

	file, err := os.Create(configJsonPath)
	if err != nil {
		logrus.Debugf("Error creating config file:%s", err)
		return
	}
	defer file.Close()

	// 创建一个json编码器并将Config实例编码到文件中
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "    ")
	err = encoder.Encode(config)
	if err != nil {
		logrus.Debugf("Error encoding config to JSON:%s", err)
	}
	return
}
