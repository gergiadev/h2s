package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
)

var (
	Warning *log.Logger
	Info    *log.Logger
	Error   *log.Logger
	Http    *log.Logger
)

func file_line() string {
	_, fileName, fileLine, ok := runtime.Caller(1)
	var s string
	if ok {
		s = fmt.Sprintf("%s:%d", fileName, fileLine)
	} else {
		s = ""
	}
	return s
}

func initLog(file *os.File) {

	Info = log.New(file, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warning = log.New(file, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(file, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func initHttpLog(file *os.File) {

	Http = log.New(file, "HTTP Request: ", log.Ldate|log.Ltime|log.Lshortfile)

}

// Joins the message parts by hand: passing the slice straight to Println would
// print it as "[part one part two]", brackets included.
func logLine(message []string) string {
	return strings.Join(message, " ")
}

func HttpLogger(message ...string) {
	Http.Println(logLine(message))
}

func InfoLogger(message ...string) {
	Info.Println(logLine(message))
}

func WarningLogger(message ...string) {
	Warning.Println(logLine(message))
}

func ErrorLogger(message ...string) {
	Error.Println(logLine(message))
}
