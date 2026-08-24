package main

import (
	"bufio"
	"crypto/subtle"
	"database/sql"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	_ "github.com/proullon/ramsql/driver"
)

// Initialize RamSQL, creating the in-memory db/tables I need:
// hosts:	to store all node's data
// lists:	to store OID collention's names
// oid:		to store OID from collections
// oidList:	to store the list of mapped OIDs (from oid_map)

func intDB() {

	var err error

	InfoLogger("Starting RAMSQL DB")

	batch := []string{
		`CREATE TABLE hosts (id BIGSERIAL PRIMARY KEY, group TEXT, name TEXT, active INT, snmpver TEXT, ip TEXT, protocol TEXT, port INT, timeout INT, retries INT, user TEXT, community TEXT, password TEXT, passphrase TEXT, encalgo TEXT, authalgo TEXT, seclevel TEXT, querylist TEXT);`,
		`CREATE TABLE lists (id BIGSERIAL PRIMARY KEY, name TEXT);`,
		`CREATE TABLE oids (id BIGSERIAL PRIMARY KEY, idList INT, name TEXT, oid TEXT, type INT);`,
		`CREATE TABLE oidList (id BIGSERIAL PRIMARY KEY, oid TEXT, name TEXT);`,
		//		`INSERT INTO hosts (group, name, active, snmpver, ip, port, timeout, user, community, password, passphrase, encalgo, authalgo, seclevel, querylist) VALUES ('<group>', '<name>', 1, '3', '<ip>', 161, 10, '<user>', '', '<encrypted password>', '<encrypted passphrase>', 'AES', 'SHA', 'authPriv', 'default,ifTable');`,
	}

	// Create h2s db
	InfoLogger("Initializing in-ram database 'h2s'")
	db, err = sql.Open("ramsql", "h2s")
	if err != nil {
		fmt.Printf("sql.Open : Error : %s\n", err)
	}

	// Create tables
	InfoLogger("Initializing tables")
	for _, b := range batch {
		_, err := db.Exec(b)
		if err != nil {
			ErrorLogger("sql.Exec: Error:", err.Error())
		}

	}

}

// Run h2s tcp console on localhost:<console-port>
func runSQLPrompt(conf H2sConf_Struct) {

	l, err := net.Listen("tcp", "localhost:"+strconv.Itoa(conf.ConsolePort))
	if err != nil {
		ErrorLogger("Error listening:", err.Error())
		os.Exit(1)
	}

	defer l.Close()
	InfoLogger("Listening on " + "localhost:" + strconv.Itoa(conf.ConsolePort))
	for {

		conn, err := l.Accept()
		if err != nil {
			// A failed accept concerns that connection only: it used to bring the
			// whole daemon down
			ErrorLogger("Error accepting: ", err.Error())
			continue
		}

		go handleRequest(conn, conf)
	}
}

// Asks for the admin password before handing over the console. It is always on:
// the console shows credentials in clear text and runs raw queries.
func consoleLogin(conn net.Conn, reader *bufio.Reader, conf H2sConf_Struct) bool {

	adminPwd, err := decrypt(conf.AdminPwd)
	if err != nil || len(adminPwd) == 0 {
		conn.Write([]byte(string("Console unavailable: admin-password is missing or cannot be decrypted\n")))
		ErrorLogger("Console login refused: invalid admin-password in h2s.conf", file_line())
		return false
	}

	conn.Write([]byte(string("Password: ")))

	pwdRaw, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(pwdRaw)), []byte(adminPwd)) != 1 {
		conn.Write([]byte(string("Access denied\n")))
		WarningLogger("Console login failed from", conn.RemoteAddr().String())
		return false
	}

	InfoLogger("Console login from", conn.RemoteAddr().String())

	return true
}

// Manage all request to h2s console: parse statements and execute all commands
func handleRequest(conn net.Conn, conf H2sConf_Struct) {

	defer conn.Close()

	// One reader for the whole connection: building it inside the loop threw away
	// whatever the client had already sent after the current line
	reader := bufio.NewReader(conn)

	if !consoleLogin(conn, reader, conf) {
		return
	}

	conn.Write([]byte(string("h2s> ")))

	for {
		netDataRaw, err := reader.ReadString('\n')
		if err != nil {
			return
		}

		netData := strings.ToLower(strings.TrimSpace(string(netDataRaw)))

		if len(netData) > 0 {

			splittedString := strings.Fields(netData)
			if netData == "quit" {
				conn.Write([]byte(string("Bye \n")))
				break
			} else if strings.HasPrefix(netData, "help") {
				if len(splittedString) == 1 {
					conn.Write([]byte(fmt.Sprintf("%-20s%s\n", "show <sub cmd>", "Shows target list/details")))
					conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "query <stmt>", "Exec a raw query")))
					conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "reload [hosts/oid]", "Reload hosts/oid from disk")))
					conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "version", "Show current h2s version")))
				} else {
					promptHelp(conn, netData)
				}
				// To validate composite command I parse its first word; if the first one matches, I continue parsing the rest
			} else if strings.HasPrefix(netData, "show") {
				if len(splittedString) == 1 {
					conn.Write([]byte(string("Missing command\n")))
				} else {
					var (
						id         int
						group      string
						name       string
						active     int
						snmpver    string
						ip         string
						port       int
						protocol   string
						timeout    int
						retries    int
						user       string
						community  string
						password   string
						passphrase string
						encalgo    string
						authalgo   string
						seclevel   string
						querylist  string
					)

					splittedString = splittedString[1:]
					if splittedString[0] == "all" {
						if strings.HasPrefix(netData, "show all") {
							query := `SELECT id, name FROM hosts;`
							rows, err := db.Query(query)
							if err != nil {
								conn.Write([]byte(string("Error showing data: " + err.Error() + "\n")))
							} else {

								for rows.Next() {
									if err := rows.Scan(&id, &name); err != nil {
										conn.Write([]byte(string("Error showing data: " + err.Error() + "\n")))
										continue
									}
									conn.Write([]byte(fmt.Sprintf("%d) %s\n", id, name)))

								}
								rows.Close()
							}
						}
					} else if splittedString[0] == "target" {
						// Load data for a single target host
						var (
							query      string
							targetName string
							isFull     bool
						)

						splittedString = splittedString[1:]

						// "full" is optional and is stripped before reading the name:
						// asking for it without a name used to panic on splittedString[1]
						if len(splittedString) > 0 && splittedString[0] == "full" {
							isFull = true
							splittedString = splittedString[1:]
						}

						if len(splittedString) > 0 {
							targetName = splittedString[0]
							query = "SELECT * FROM hosts WHERE name =?;"

							rows, err := db.Query(query, targetName)
							if err != nil {
								conn.Write([]byte(string("Error showing data: " + err.Error() + "\n")))
							} else {

								for rows.Next() {
									if err := rows.Scan(&id, &group, &name, &active, &snmpver, &ip, &protocol, &port, &timeout, &retries, &user, &community, &password, &passphrase, &encalgo, &authalgo, &seclevel, &querylist); err != nil {
										conn.Write([]byte(string("Error selecting data\n")))
										ErrorLogger("Error showing data: ", err.Error(), file_line())
										continue
									}

									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Group:", group)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Name:", name)))
									activeString := "False"
									if active == 1 {
										activeString = "True"
									}
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Active:", activeString)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "SNMP Ver:", snmpver)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "IP:", ip)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Protocol:", protocol)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30d\n", "Port:", port)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30d\n", "Timeout:", timeout)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30d\n", "Retries:", retries)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "User:", user)))

									// The community is a secret like the other two, so
									// it is only spelled out with "show target full"
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Community:", showSecret(community, isFull))))
									if isFull {
										conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Password:", showSecret(password, isFull))))
										conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Passphrase:", showSecret(passphrase, isFull))))
									}
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Auth. Algo:", authalgo)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Priv. Algo:", encalgo)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Security Lvl.:", seclevel)))
									conn.Write([]byte(fmt.Sprintf("%-15s%30s\n", "Query Type:", querylist)))

								}
								rows.Close()
							}
						} else {

							conn.Write([]byte(string("Invalid target\n")))

						}

					}
				}
				// To validate composite command I parse its first word; if the first one matches, I continue parsing the rest
			} else if strings.HasPrefix(netData, "query") {
				splittedStmt := strings.Split(netData, " ")
				newStmt := strings.Join(splittedStmt[1:], " ")
				query(conn, newStmt)
				// To validate composite command I parse its first word; if the first one matches, I continue parsing the rest
			} else if strings.HasPrefix(netData, "reload") {
				var errReload error
				if strings.HasPrefix(netData, "reload hosts") {
					httpQueryAllowed.Store(false)
					if errReload = loadTargets(conf); errReload != nil {
						conn.Write([]byte(fmt.Sprintf("Can't reload devices: %s\n", errReload.Error())))
					} else {
						conn.Write([]byte("Devices correctly reloaded\n"))

					}
					httpQueryAllowed.Store(true)
				} else if strings.HasPrefix(netData, "reload oid") {
					httpQueryAllowed.Store(false)
					if errReload = loadOIDList(); errReload != nil {
						conn.Write([]byte(fmt.Sprintf("Can't reload OIDs: %s\n", errReload.Error())))
					} else {
						conn.Write([]byte("OIDs correctly reloaded\n"))

					}
					httpQueryAllowed.Store(true)
				}

			} else if strings.HasPrefix(netData, "version") {
				conn.Write([]byte(fmt.Sprintf("%s ver. %s\n", h2sTitle, h2sVersion)))
			}
		}
		conn.Write([]byte(string("h2s> ")))
	}
}

// Decrypts a stored secret for display, or masks it when "full" was not asked for
func showSecret(secret string, isFull bool) string {
	if len(secret) == 0 {
		return "N/A"
	}

	if !isFull {
		return "********"
	}

	plainSecret, err := decrypt(secret)
	if err != nil {
		return "<cannot decrypt>"
	}

	return plainSecret
}

func promptHelp(conn net.Conn, netData string) {
	if strings.HasPrefix(netData, "help show") {
		conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "show all", "Shows target list")))
		conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "show target <hostname>", "Shows target details without passwords")))
		conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "show target full <hostname>", "Shows target details with passwords")))
	} else if strings.HasPrefix(netData, "help query") {
		conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "query <query>", "Exec a raw query (allowed stmt: SELECT, DELETE, UPDATE)")))

	} else if strings.HasPrefix(netData, "help reload") {
		conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "reload hosts", "Reload hosts from disk into memory")))
		conn.Write([]byte(fmt.Sprintf("%-30s%s\n", "reload oid", "Reload OID map from disk into memory")))

	}
}

func query(conn net.Conn, query string) {

	// The help has always advertised these three: nothing enforced it, so a DROP
	// from the console could wipe the in-ram schema
	allowed := false
	for _, stmt := range []string{"select", "delete", "update"} {
		if strings.HasPrefix(strings.TrimSpace(query), stmt) {
			allowed = true
			break
		}
	}

	if !allowed {
		conn.Write([]byte(string("Only SELECT, DELETE and UPDATE statements are allowed\n")))
		return
	}

	rows, err := db.Query(query)
	if err != nil {
		ErrorLogger("ERROR : Cannot query :", err.Error(), file_line())
		conn.Write([]byte(string("Cannot query: " + err.Error() + "\n")))
		return
	}

	defer rows.Close()

	columns, err := rows.Columns()
	if err != nil {
		ErrorLogger("ERROR : Cannot get columns name :", err.Error(), file_line())
		return
	}

	// print rows name
	prettyPrintHeader(conn, columns)

	for rows.Next() {
		holders := make([]interface{}, len(columns))
		for i := range holders {
			holders[i] = new(string)
		}
		err := rows.Scan(holders...)
		if err != nil {
			ErrorLogger("ERROR : cannot scan values :", err.Error(), file_line())
			return
		}
		prettyPrintRow(conn, holders)
	}
	conn.Write([]byte(string("\n")))

}

func prettyPrintHeader(conn net.Conn, row []string) {
	var line string

	conn.Write([]byte(string("\n")))
	for i, r := range row {
		if i != 0 {
			line += "  |  "
		}
		line += fmt.Sprintf("%-5s", r)
	}
	conn.Write([]byte(fmt.Sprintf("%s\n", line)))
	lineLen := len(line)
	for i := 0; i < lineLen; i++ {
		conn.Write([]byte(string("-")))
	}
	conn.Write([]byte(string("\n")))
}

func prettyPrintRow(conn net.Conn, row []interface{}) {
	conn.Write([]byte(string("\n")))

	for i, r := range row {
		if i != 0 {
			conn.Write([]byte(string("  |  ")))

		}
		s, ok := r.(*string)
		if !ok {
			// A column of another type is printed as it is, instead of taking the
			// whole daemon down with a panic
			conn.Write([]byte(fmt.Sprintf("%-5v", r)))
			continue
		}
		conn.Write([]byte(fmt.Sprintf("%-5s", *s)))

	}
}
