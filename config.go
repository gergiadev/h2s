package main

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Loads the configuration and tries to unmarshall YAML
func loadConf() H2sConf_Struct {
	var (
		h2sConf H2sConf_Struct
	)

	yfile, errReadYAML := os.ReadFile("h2s.conf")

	if errReadYAML != nil {
		// Only a missing file is a normal condition: anything else (permissions,
		// unreadable device) would silently leave us with an empty configuration
		if os.IsNotExist(errReadYAML) {
			WarningLogger("h2s.conf does not exist. Creating a new one (" + file_line() + ")")
			createFirstConf()
		}

		ErrorLogger("Can't read h2s.conf: " + errReadYAML.Error() + " (" + file_line() + ")")
		fmt.Fprintf(os.Stderr, "Can't read h2s.conf: %s\n", errReadYAML.Error())

		os.Exit(1)
	}

	errLoadYAML := yaml.Unmarshal(yfile, &h2sConf)

	if errLoadYAML != nil {
		WarningLogger("Error parsing h2s.conf (" + file_line() + ")")

		os.Exit(1)
	}

	if len(h2sConf.ListenAddress) == 0 {
		h2sConf.ListenAddress = "127.0.0.1"
	}

	if h2sConf.ListenPort <= 0 {
		h2sConf.ListenPort = 23432
	}

	// Kept out of the file by default: an existing h2s.conf has no console-port key
	if h2sConf.ConsolePort <= 0 {
		h2sConf.ConsolePort = 3333
	}

	if len(h2sConf.NodesPath) == 0 {
		h2sConf.NodesPath = "./nodes"
	}

	return h2sConf

}

// If the conf file h2s.conf does not exists create the default and exit
func createFirstConf() {
	var (
		b       bytes.Buffer
		h2sConf H2sConf_Struct
		err     error
	)

	yamlEncoder := yaml.NewEncoder(&b)
	yamlEncoder.SetIndent(2)
	h2sConf.ListenAddress = "127.0.0.1"
	h2sConf.ListenPort = 23432
	h2sConf.ConsolePort = 3333
	h2sConf.NodesPath = "./nodes"

	if h2sConf.AdminPwd, err = encrypt("password"); err != nil {
		ErrorLogger("Can't encrypt the default admin password (" + file_line() + ")")
		fmt.Fprintf(os.Stderr, "Can't encrypt the default admin password: %s\n", err.Error())
		os.Exit(1)
	}

	yamlEncoder.Encode(&h2sConf)
	yamlEncoder.Close()

	if err := os.WriteFile("h2s.conf", b.Bytes(), 0600); err != nil {
		ErrorLogger("Issues while creating h2s.conf file (" + file_line() + ")")
		os.Exit(1)
	} else {
		InfoLogger("Default h2s.conf file created (" + file_line() + ")")
		fmt.Fprintf(os.Stderr, "Default h2s.conf file created\n")
		fmt.Fprintf(os.Stderr, "Review the configuration file and restart h2s\n")
		os.Exit(0)

	}

}
