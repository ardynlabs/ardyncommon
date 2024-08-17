package ardynconfig

import (
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

//-------------------------------------------------------

// LoadConfiguration loads configuration from a YAML file
func LoadConfiguration(path string, config interface{}) (err error) {

	log.Println("Loading configuration file: ", path)

	bytes, err := os.ReadFile(path)

	if err != nil {

		return

	}

	err = yaml.Unmarshal(bytes, config)

	if err != nil {

		return

	}

	return

}

//-------------------------------------------------------
