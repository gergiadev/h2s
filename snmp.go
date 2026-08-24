package main

import (
	b64 "encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/k-sone/snmpgo"
)

// Returned when the requested node is not in memory, so the daemon can answer
// 404 instead of a silent empty 200
var errNodeNotFound = errors.New("node not found")

func snmpQuery(node *sqlNode, version int) map[string]interface{} {

	var (
		//		snmpErrorResults map[string]interface{}
		snmpResults map[string]interface{}
		oidList     []string
		idList      int
		err         error
		query       string
		oidTmp      string
		oidName     string
		snmp        *snmpgo.SNMP
		args        *snmpgo.SNMPArguments
	)

	snmpResults = make(map[string]interface{})

	// Secrets are kept encrypted in memory and decrypted only here. A failure is
	// logged and left empty: snmpgo will refuse the query with its own message.
	community, errComm := decrypt(node.community)
	if errComm != nil && len(node.community) > 0 {
		ErrorLogger("Can't decrypt the community of node '"+node.name+"': "+errComm.Error(), file_line())
	}

	authPassword, errPwd := decrypt(node.password)
	if errPwd != nil && len(node.password) > 0 {
		ErrorLogger("Can't decrypt the password of node '"+node.name+"': "+errPwd.Error(), file_line())
	}

	privPassword, errPhrase := decrypt(node.passphrase)
	if errPhrase != nil && len(node.passphrase) > 0 {
		ErrorLogger("Can't decrypt the passphrase of node '"+node.name+"': "+errPhrase.Error(), file_line())
	}

	args = &snmpgo.SNMPArguments{
		//Network:          *protocol,
		Network: node.protocol,
		Address: fmt.Sprintf("%s:%d", node.ip, node.port),
		Timeout: time.Duration(node.timeout) * time.Second,
		//	Retries:          *retries,
		Retries:      uint(node.retries),
		Community:    community,
		UserName:     node.user,
		AuthPassword: authPassword,
		AuthProtocol: snmpgo.AuthProtocol(strings.ToUpper(node.authalgo)),
		PrivPassword: privPassword,
		PrivProtocol: snmpgo.PrivProtocol(strings.ToUpper(node.encalgo)),
		//	SecurityEngineId: *secengine,
		//	ContextEngineId:  *contextengine,
		//	ContextName:      *contextname,
		SecurityEngineId: "",
		ContextEngineId:  "",
		ContextName:      "",
	}

	if version == 3 {
		args.Version = snmpgo.V3

		// Only v3 carries a security level: checking it for a v2c node logged an
		// "Illegal SecurityLevel" error on every single query
		switch strings.ToLower(node.seclevel) {
		case "noauthnopriv":
			args.SecurityLevel = snmpgo.NoAuthNoPriv
		case "authnopriv":
			args.SecurityLevel = snmpgo.AuthNoPriv
		case "authpriv":
			args.SecurityLevel = snmpgo.AuthPriv
		default:
			ErrorLogger(fmt.Sprintf("Illegal SecurityLevel, value `%s`", node.seclevel))
		}
	} else if version == 2 {
		args.Version = snmpgo.V2c
	}

	snmp, err = snmpgo.NewSNMP(*args)

	if err != nil {
		errStr := fmt.Sprintf("Error creating SNMP object: %s", err.Error())
		ErrorLogger(errStr, file_line())
		snmpResults["Error"] = errStr
		return snmpResults
	}

	// snmpgo opens the socket on the first request: without this the daemon leaked
	// one udp descriptor per HTTP call
	defer snmp.Close()

	// Read once: the console can swap the map while this query is running
	currentMap := currentOIDMap()

	errOIDListJson := json.Unmarshal([]byte(node.querylist), &oidList)

	if errOIDListJson == nil {
		for _, v := range oidList {
			// Extract the list's ID
			query = "SELECT id FROM lists WHERE name =?;"

			rows, err := db.Query(query, v)
			if err != nil {
				ErrorLogger("Error retrieving OID list: "+err.Error(), file_line())
				continue
			}

			for rows.Next() {
				if err := rows.Scan(&idList); err != nil {
					ErrorLogger("Error scanning target's host: "+err.Error(), file_line())
				}
			}
			rows.Close()

			// With ID, extract all OIDs by action
			// Action GET
			query = "SELECT oid, name FROM oids WHERE idList=? AND type=1;"

			rows, err = db.Query(query, idList)
			if err != nil {
				ErrorLogger("Error retrieving OID list: "+err.Error(), file_line())
				continue
			}

			for rows.Next() {
				if err := rows.Scan(&oidTmp, &oidName); err != nil {
					ErrorLogger("Error scanning target's host: "+err.Error(), file_line())
					continue
				}

				oid, _ := snmpgo.NewOids([]string{oidTmp})
				pdu, err := snmp.GetRequest(oid)
				if err != nil {
					errStr := fmt.Sprintf("Error in get SNMP object: %s", err.Error())
					ErrorLogger(errStr, file_line())
					snmpResults["Error"] = errStr
					rows.Close()
					return snmpResults
				}
				for _, val := range pdu.VarBinds() {
					// fmt.Printf(" %s = %s: %s\n", val.Oid, val.Variable.Type(), val.Variable)
					snmpResults[oidName] = val.Variable.String()

				}
			}
			rows.Close()

			// Action BULK
			query = "SELECT oid, name FROM oids WHERE idList=? AND type=2;"

			rows, err = db.Query(query, idList)
			if err != nil {
				ErrorLogger("Error retrieving OID list: "+err.Error(), file_line())
				continue
			}

			for rows.Next() {
				if err := rows.Scan(&oidTmp, &oidName); err != nil {
					ErrorLogger("Error scanning target's host: "+err.Error(), file_line())
					continue
				}

				oid, _ := snmpgo.NewOids([]string{oidTmp})
				pdu, err := snmp.GetBulkWalk(oid, 0, 10)

				if err != nil {
					errStr := fmt.Sprintf("Error in get SNMP object: %s", err.Error())
					ErrorLogger(errStr, file_line())
					snmpResults["Error"] = errStr
					rows.Close()
					return snmpResults
				}

				bulkOID := make(map[string]string)

				for _, val := range pdu.VarBinds() {

					// val.Oid.String()            -> oidStringSlice
					// "1.3.6.1.4.1.2021.10.1.3.1" -> ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"."1"]
					oidStringSlice := strings.Split(val.Oid.String(), ".")

					// oidStringSlice                                    -> lastOidString
					// ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"."1"] -> ["1"]
					lastOidString := strings.Join(oidStringSlice[len(oidStringSlice)-1:], "")

					// oidStringSlice[:len(oidStringSlice)-1]            -> oidStringSlice
					// ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"."1"] -> ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"]
					oidStringSlice = oidStringSlice[:len(oidStringSlice)-1]

					// strings.Join(oidStringSlice, ".")                -> oidString
					// ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"] -> "1.3.6.1.4.1.2021.10.1.3."
					oidString := strings.Join(oidStringSlice, ".")

					// A name of its own, so it does not shadow the collection name
					// that labels the whole bulk result below
					mappedName, oidExists := currentMap[oidString]

					// Is the OID already mapped?
					if oidExists {
						mappedName = fmt.Sprintf("%s.%s", mappedName, lastOidString)
						bulkOID[mappedName] = val.Variable.String()
					} else {
						oidString = fmt.Sprintf("%s.%s", oidString, lastOidString)
						bulkOID[oidString] = val.Variable.String()

					}
				}

				snmpResults[oidName] = bulkOID
			}
			rows.Close()

			// Action TABLE
			query = "SELECT oid, name FROM oids WHERE idList=? AND type=3;"

			rows, err = db.Query(query, idList)
			if err != nil {
				ErrorLogger("Error retrieving OID list: "+err.Error(), file_line())
				continue
			}

			for rows.Next() {
				if err := rows.Scan(&oidTmp, &oidName); err != nil {
					ErrorLogger("Error scanning target's host: "+err.Error(), file_line())
					continue
				}

				oid, _ := snmpgo.NewOids([]string{oidTmp})
				pdu, err := snmp.GetBulkWalk(oid, 0, 10)

				if err != nil {
					errStr := fmt.Sprintf("Error in get SNMP object: %s", err.Error())
					ErrorLogger(errStr, file_line())
					snmpResults["Error"] = errStr
					rows.Close()
					return snmpResults
				}

				tableOID := make(map[string][]string)

				for _, val := range pdu.VarBinds() {

					// val.Oid.String()            -> oidStringSlice
					// "1.3.6.1.4.1.2021.10.1.3.1" -> ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"."1"]
					oidStringSlice := strings.Split(val.Oid.String(), ".")

					// oidStringSlice[:len(oidStringSlice)-1]            -> oidStringSlice
					// ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"."1"] -> ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"]
					oidStringSlice = oidStringSlice[:len(oidStringSlice)-1]

					// strings.Join(oidStringSlice, ".")                -> oidString
					// ["1"."3"."6"."1"."4"."1"."2021"."10"."1"."3"] -> "1.3.6.1.4.1.2021.10.1.3."
					oidString := strings.Join(oidStringSlice, ".")

					// Get OID name from map
					mappedName, oidExists := currentMap[oidString]

					// Is the OID already mapped? If not the numeric OID is the label:
					// it used to fall back to an empty key, piling up every unmapped
					// column under the same entry
					if oidExists {
						tableOID[mappedName] = append(tableOID[mappedName], val.Variable.String())
					} else {
						tableOID[oidString] = append(tableOID[oidString], val.Variable.String())

					}

				}

				snmpResults[oidName] = tableOID
			}
			rows.Close()

			// Action CMD
			query = "SELECT oid, name FROM oids WHERE idList=? AND type=4;"

			rows, err = db.Query(query, idList)
			if err != nil {
				ErrorLogger("Error retrieving OID list: "+err.Error(), file_line())
				continue
			}

			for rows.Next() {
				if err := rows.Scan(&oidTmp, &oidName); err != nil {
					ErrorLogger("Error scanning target's host: "+err.Error(), file_line())
					continue
				}

				// Same encoding used by loadOIDConf when the command was stored
				uDec, errDecode := b64.StdEncoding.DecodeString(oidTmp)
				if errDecode != nil {
					ErrorLogger("Can't decode command: "+errDecode.Error(), file_line())
					continue
				}

				// The command can hold pipes and quotes (see queryconfs/iftable.yml),
				// so it goes to the shell instead of being split on spaces by hand
				cmd := exec.Command("/bin/sh", "-c", string(uDec))

				out, err := cmd.CombinedOutput()
				if err != nil {
					ErrorLogger("cmd.Run() failed with ", err.Error(), file_line())
				}

				snmpResults[oidName] = strings.Split(strings.TrimRight(string(out), "\n"), "\n")
			}
			rows.Close()

		}
	} else {
		errStr := fmt.Sprintf("Error parsing SNMP object: %s", errOIDListJson.Error())
		ErrorLogger(errStr, file_line())
		snmpResults["Error"] = errStr
	}
	return snmpResults

}

func snmpQueryAssetBuilder(itemName string) (map[string]interface{}, error) {
	var (
		queryResponse map[string]interface{}
		node          *sqlNode
		query         string
		nodeFound     bool
	)

	node = new(sqlNode)

	queryResponse = make(map[string]interface{})

	query = "SELECT * FROM hosts WHERE name =?;"

	rows, err := db.Query(query, itemName)
	if err != nil {
		ErrorLogger("Error retrieving target's host: "+err.Error(), file_line())
		return queryResponse, err
	}

	defer rows.Close()

	for rows.Next() {
		if err := rows.Scan(&node.id, &node.group, &node.name, &node.active, &node.snmpver, &node.ip, &node.protocol, &node.port, &node.timeout, &node.retries, &node.user, &node.community, &node.password, &node.passphrase, &node.encalgo, &node.authalgo, &node.seclevel, &node.querylist); err != nil {
			ErrorLogger("Error scanning target's host: "+err.Error(), file_line())
			return queryResponse, err
		}
		nodeFound = true
	}

	// Used to end up as an empty 200: the caller can now tell the two cases apart
	if !nodeFound {
		return queryResponse, errNodeNotFound
	}

	//Verify the struct type before populating map
	if node.snmpver == "2" || node.snmpver == "2c" {
		queryResponse = snmpQuery(node, 2)
	} else if node.snmpver == "3" {
		queryResponse = snmpQuery(node, 3)

	} else {
		return queryResponse, fmt.Errorf("unsupported snmp-ver '%s' for node '%s'", node.snmpver, itemName)
	}

	return queryResponse, nil
}
