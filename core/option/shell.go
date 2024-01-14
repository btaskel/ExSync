package option

import (
	"github.com/sirupsen/logrus"
	"os"
)

type Shell struct {
}

func (s *Shell) setLogLevel(level string) {
	log := logrus.New()
	file, err := os.OpenFile("debug.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err == nil {
		log.Out = file
	} else {
		log.Errorf("Failed to log to file, using default stderr")
	}
	// 设置日志格式
	log.Formatter = &logrus.TextFormatter{
		FullTimestamp: true,
	}

	// 设置日志级别
	switch level {
	case "debug":
		log.Level = logrus.DebugLevel
	case "info":
		log.Level = logrus.InfoLevel
	case "warning":
		log.Level = logrus.WarnLevel
	case "error":
		log.Level = logrus.ErrorLevel
	case "fatal":
		log.Level = logrus.FatalLevel
	default:
		log.Level = logrus.InfoLevel
	}
}
