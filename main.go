package main

import (
	"flag"
	"fmt"
	"log"

	_ "net/http/pprof"
	"os"
)

var (
// targetList = sync.Map{}
// OIDList    = sync.Map{}

)

// type h2sConf_Struct dataMap.H2sConf_Struct

// Initialize logs
func init() {
	// Applicative log
	if file, err := os.OpenFile("h2s.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666); err == nil {
		initLog(file)
	} else {

		log.Fatal(err)
	}

	// Web server log
	if fileHttp, errHttp := os.OpenFile("h2s_access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666); errHttp == nil {
		initHttpLog(fileHttp)
	} else {

		log.Fatal(errHttp)
	}

}

func main() {

	h2sTitle = "H2S (HTTP to SNMP) Proxy"
	h2sVersion = "1.0 Beta"

	var (
		encryptPar string
		decryptPar string
		startH2S   bool
	)
	const usage = `Usage of using_flag:
	-s, --start start h2s
	-e, --encrypt encrypt a password/passphrase string
	-d, --decrypt decrypt a password/passphrase string
	-h, --help prints help information 
  `
	/*
	   go get -u github.com/google/pprof
	   go tool pprof -alloc_objects http://:6060/debug/pprof/allocs
	   pprof> top
	*/

	/*	go func() {
			fmt.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	*/

	flag.BoolVar(&startH2S, "start", false, "--start start h2s")
	flag.BoolVar(&startH2S, "s", false, "--start start h2s")

	flag.StringVar(&encryptPar, "encrypt", "", "encrypt a password/passphrase string")
	flag.StringVar(&encryptPar, "e", "", "encrypt a password/passphrase string")

	flag.StringVar(&decryptPar, "decrypt", "", "decrypt a password/passphrase string")
	flag.StringVar(&decryptPar, "d", "", "decrypt a password/passphrase string")

	flag.Usage = func() { fmt.Print(usage) }
	flag.Parse()

	// Every branch below ends up using the AES key, so it is checked once here:
	// a build made without -ldflags used to panic on the first encrypt/decrypt
	if err := validateKey(); err != nil {
		ErrorLogger(err.Error() + "(" + file_line() + ")")
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}

	if len(encryptPar) > 0 {
		encryptedPar, err := encrypt(encryptPar)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("%s\n", encryptedPar)
		os.Exit(0)
	} else if len(decryptPar) > 0 {
		decryptedPar, err := decrypt(decryptPar)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
		fmt.Printf("%s\n", decryptedPar)
		os.Exit(0)
	} else if startH2S {
		httpQueryAllowed.Store(true)
		InfoLogger("Starting H2S daemon...")
		h2sConf := loadConf()

		intDB()
		go runSQLPrompt(h2sConf)

		loadOIDList()

		//loadMibDir()
		loadOIDConf()

		InfoLogger("Loading Target Devices...")
		loadTargets(h2sConf)

		//	testSnmp()
		//h2sConf.printConf()
		InfoLogger("Starting HTTP Daemon...")
		fmt.Printf("Ready\n")
		startHTTP(h2sConf)
	}
}
