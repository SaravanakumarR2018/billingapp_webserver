/*
  loggerUtil.go
  This package is used for creating a logging mechanism for the whole
  callHome Process
*/
package loggerUtil

import (
	"fmt"
	"log"
	"os"
	"runtime"
)

var (
	Log   *log.Logger
	debug bool = false
)

func SetDebug(d bool) {
	debug = d
	Log.Println("DEBUG LOGGING: ", d)
}

func InitLog(filename string) {
	var path string
	var ok bool
	if runtime.GOOS == "windows" {
		path, ok = os.LookupEnv("HOMEPATH")
		if !ok {
			path = os.Getenv("TEMP")
		}
	} else {
		path, ok = os.LookupEnv("HOME")
		if !ok {
			path = "/tmp"
		}
	}
	logfilepath := path + "/" + filename
	fmt.Println("BillingApp INITIATED: Logs at ", logfilepath)
	file, err := os.OpenFile(logfilepath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0755)
	if err != nil {
		panic(err)
	}
	Log = log.New(file, "", log.LstdFlags|log.Lshortfile)
}

func Debugln(args ...interface{}) {
	if debug == true {
		Log.Println(args...)
	}
}
