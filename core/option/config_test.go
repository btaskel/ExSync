package option

import (
	"log"
	"testing"
)

func TestCreateConfig(t *testing.T) {
	config := Config{}
	err := config.CreateConfig()
	if err != nil {
		log.Fatalf("TestCreateConfig: %v", err)
		return
	}
}
