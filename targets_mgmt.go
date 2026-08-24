package main

import (
	"bufio"
	b64 "encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Set defaults value for the node and store it in memory
func insertTargets(tmp NodeConf_struct_YAML) {

	// Secrets stay encrypted in memory exactly as they are written in the node file:
	// they are decrypted only when an SNMP query is actually built
	if tmp.NodeSNMPVer != "2" && tmp.NodeSNMPVer != "2c" {
		tmp.NodeComm = ""
	}

	if tmp.NodeSNMPVer != "3" {
		tmp.NodePasswd = ""
		tmp.NodePassPhrase = ""
	}

	nodeActive := 0
	if tmp.NodeStatus {
		nodeActive = 1
	}

	// Defaults live here only, so a node loaded from disk and one created over HTTP
	// end up with the very same values
	if strings.ToLower(tmp.NodeProtocol) != "udp" && strings.ToLower(tmp.NodeProtocol) != "tcp" {
		tmp.NodeProtocol = "udp"
	}

	if tmp.NodePort <= 0 {
		tmp.NodePort = 161
	}

	if tmp.NodeTimeout <= 0 {
		tmp.NodeTimeout = 10
	}

	if tmp.NodeRetries <= 0 {
		tmp.NodeRetries = 3
	}

	jsonNodeIncludeResp, _ := json.Marshal(tmp.NodeInclude)

	insertQuery := "INSERT INTO hosts (group, name, active, snmpver, ip, protocol, port,  timeout, retries, user, community, password, passphrase, encalgo, authalgo, seclevel, querylist) values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"

	_, err := db.Exec(insertQuery, tmp.NodeGroup, tmp.NodeName, nodeActive, tmp.NodeSNMPVer, tmp.NodeIP, tmp.NodeProtocol, tmp.NodePort, tmp.NodeTimeout, tmp.NodeRetries, tmp.NodeUser, tmp.NodeComm, tmp.NodePasswd, tmp.NodePassPhrase, tmp.NodeEncAlgo, tmp.NodeAuthAlgo, tmp.NodeSecLevel, string(jsonNodeIncludeResp))
	if err != nil {
		ErrorLogger("sql.Exec: Error:", err.Error(), "while loading hosts")
	} else {
		InfoLogger("Node '" + tmp.NodeName + "' added correctly")
	}

	tmp = NodeConf_struct_YAML{}
}

// Walks the ./targets folder and search for node configurations.
// If any, loads it in the YAML structure, saving the proper data
// (different from 2c and 3)
func loadTargets(conf H2sConf_Struct) error {

	var (
		tmp      NodeConf_struct_YAML
		totNodes int
	)

	totNodes = 0

	// To avoid problems I delete the content of table "hosts" before loading from disk
	deleteQuery := "DELETE FROM hosts;"

	_, deleteQueryErr := db.Exec(deleteQuery)
	if deleteQueryErr != nil {
		ErrorLogger("Can't empty host list in memory:", deleteQueryErr.Error(), file_line())
	}

	err := filepath.Walk(conf.NodesPath,
		func(path string, info os.FileInfo, err error) error {
			// The error has to be checked first: when Walk reports one, info is nil
			// and touching it would panic
			if err != nil {
				ErrorLogger("Error walking " + path + ". (" + err.Error() + ")")
				return err
			}

			if !info.IsDir() {

				yfile, errReadYAML := os.ReadFile(path)
				if errReadYAML != nil {
					ErrorLogger("Error reading " + path + ". (" + errReadYAML.Error() + ")")
					return errReadYAML
				}

				errLoadYAML := yaml.Unmarshal(yfile, &tmp)

				if errLoadYAML != nil {
					WarningLogger("Error parsing " + path + ". (" + errLoadYAML.Error() + ")")

					return errLoadYAML

				}

				totNodes++

				insertTargets(tmp)

				// Empty tmp var, in order to avoid data mixing
				tmp = NodeConf_struct_YAML{}

			}

			return nil
		})

	InfoLogger(fmt.Sprintf("Loaded %d nodes", totNodes))

	if err != nil {
		ErrorLogger(err.Error())

		return err
	}
	return nil

}

// Walks the ./snmpconfs folder and search for OID  configurations.
// If any, loads it in the structure, saving the proper data
func loadOIDConf() error {

	var (
		tmp      OIDS_struct_YAML
		listName int
	)

	err := filepath.Walk("./queryconfs",
		func(path string, info os.FileInfo, err error) error {
			// The error has to be checked first: when Walk reports one, info is nil
			// and touching it would panic
			if err != nil {
				ErrorLogger("Error walking " + path + ". (" + err.Error() + ")")
				os.Exit(1)
			}

			if !info.IsDir() {

				yfile, errReadYAML := os.ReadFile(path)
				if errReadYAML != nil {
					ErrorLogger("Error reading " + path + ". (" + errReadYAML.Error() + ") ")
					os.Exit(1)
				}

				errLoadYAML := yaml.Unmarshal(yfile, &tmp)

				if errLoadYAML != nil {
					WarningLogger("Error parsing " + path + ". (" + errLoadYAML.Error() + ")")

					os.Exit(1)
				}

				// For every OID collection I insert its name in the table and after that I retrieve its id number
				searchQuery := "SELECT id FROM lists WHERE name=?;"

				query := "INSERT INTO lists(name) VALUES(?);"
				_, err := db.Exec(query, tmp.Name)
				if err != nil {
					ErrorLogger("Can't add list in memory:", err.Error())
					tmp = OIDS_struct_YAML{}
					return nil
				}

				rows, err := db.Query(searchQuery, tmp.Name)
				if err != nil {
					ErrorLogger("Can't retrieve list id:", err.Error(), file_line())
					tmp = OIDS_struct_YAML{}
					return nil
				}

				// I retrieve its id number
				for rows.Next() {
					rows.Scan(&listName)
				}
				rows.Close()

				/* Type:
				   1 = GET
				   2 = BULK
				   3 = TABLE
				   4 = CMD
				*/

				// For every collection type (GET, BULK, TABLE), I load its OID list putting them in the specific table
				// Here I associate OIDs and acollection name by the id number previously getted
				for v, k := range tmp.Get {
					insertOIDAction(listName, v, k, 1, "GET")
				}

				for v, k := range tmp.Bulk {
					insertOIDAction(listName, v, k, 2, "BULK")
				}

				for v, k := range tmp.Table {
					insertOIDAction(listName, v, k, 3, "Table")
				}

				// A command may contain quotes and pipes, so it is stored base64 encoded.
				// snmpQuery decodes it with the very same encoding before running it.
				for v, k := range tmp.Cmd {
					insertOIDAction(listName, v, b64.StdEncoding.EncodeToString([]byte(k)), 4, "Cmd")
				}

				InfoLogger("List '" + tmp.Name + "' added correctly")
			}
			tmp = OIDS_struct_YAML{}
			return nil
		})

	if err != nil {
		ErrorLogger(err.Error())
		return err

	}
	return nil

}

// Stores a single OID (or command) of a collection, keeping the four action loops
// in loadOIDConf down to one line each
func insertOIDAction(listName int, name string, oid string, oidType int, action string) {
	query := "INSERT INTO oids(idList, name, oid, type) VALUES(?, ?, ?, ?);"

	_, err := db.Exec(query, listName, name, oid, oidType)
	if err != nil {
		ErrorLogger("Can't add "+action+" action in memory:", err.Error())
	}
}

// Simply load the oid_maps file, splitting each row in 2 element;
// the first element will be the map value
// the second element will be the map key
// map[key] = value

func loadOIDList() error {

	InfoLogger("Start loading OID map in memory...")
	readFile, err := os.Open("oids_map")

	if err != nil {
		ErrorLogger(err.Error(), file_line())
		return err
	}

	defer readFile.Close()

	// The map is filled aside and published only at the end, so the HTTP handlers
	// reading it during a "reload oid" never see a half built map
	newOidMap := make(map[string]string)

	fileScanner := bufio.NewScanner(readFile)

	fileScanner.Split(bufio.ScanLines)

	for fileScanner.Scan() {
		dataToload := strings.Split(fileScanner.Text(), " ")
		if len(dataToload) == 2 {
			newOidMap[dataToload[1]] = dataToload[0]
		} else {
			ErrorLogger("Invalid OID mapping: ", dataToload[0])
		}
	}

	oidMapLock.Lock()
	oidMap = newOidMap
	oidMapLock.Unlock()

	InfoLogger("End loading OID map in memory...")

	return nil
}
