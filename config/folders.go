package config

import "os"

const DataStorePath = "data/"

const ScriptPath = "scripts/"
const UserPath = "users/"

func GetDataStorePath() string {
	paramDataStorePath := os.Getenv("DATA_PATH")
	if paramDataStorePath != "" {
		return paramDataStorePath
	}
	return DataStorePath
}
