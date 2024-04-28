package utils

import (
	"log"
	"os"
)

func CreateFolderIfNotExists(path string) error {
	// Create folder if not exists
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			log.Printf("Creating folder %s", path)
			err = os.Mkdir(path, 0755)
			if err != nil {
				return err
			}
		}
	} else {
		log.Printf("Folder %s already exists", path)
	}
	return nil
}
