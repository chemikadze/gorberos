package logging

import (
	"log"
)

func Debugf(format string, v ...interface{}) {
	log.Printf("DEBUG: "+format, v...)
}

func Infof(format string, v ...interface{}) {
	log.Printf("INFO: "+format, v...)
}

func Errorf(format string, v ...interface{}) {
	log.Print("ERROR: ")
	log.Printf("ERROR: "+format, v...)
}
