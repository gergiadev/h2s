package main

import (
	"bytes"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// A node name ends up both in a SQL statement and in a file name, so it is checked
// against a safe character set instead of looking for single bad characters
var validNodeName = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// Format the output in JSON format (default)
func outputJSON(queryResponse map[string]interface{}, isPretty bool, w http.ResponseWriter, r *http.Request) {
	var (
		jsonResp []byte
		err      error
	)

	if isPretty {
		if jsonResp, err = json.MarshalIndent(queryResponse, " ", "   "); err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
			return
		}
	} else {
		if jsonResp, err = json.Marshal(queryResponse); err != nil {
			w.WriteHeader(500)
			w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
			return
		}
	}
	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("%s\n\n", jsonResp)))
}

// Format the output in YAML format (default)
func outputYAML(queryResponse map[string]interface{}, w http.ResponseWriter, r *http.Request) {
	var (
		yamlResp []byte
		err      error
	)

	if yamlResp, err = yaml.Marshal(queryResponse); err != nil {
		w.WriteHeader(500)
		w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
		return
	}

	w.WriteHeader(200)
	w.Write([]byte(fmt.Sprintf("%s\n\n", yamlResp)))
}

func startHTTP(conf H2sConf_Struct) {

	mux := http.NewServeMux()

	mux.HandleFunc("/get", func(w http.ResponseWriter, r *http.Request) {
		// Declared per request: they used to be shared by every handler call, so two
		// concurrent /get overwrote each other's response
		var (
			queryResponse map[string]interface{}
			err           error
		)

		if httpQueryAllowed.Load() {

			if conf.SSL {
				w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}

			if r.Method == http.MethodPost {
				w.Header().Add("Content-Type", "application/json")
				w.WriteHeader(http.StatusMethodNotAllowed)
				w.Write([]byte("405 - Method not allowed\r\r"))

			} else {

				isPretty := r.URL.Query().Has("pretty")
				itemName := r.URL.Query().Get("name")
				outputFormat := r.URL.Query().Get("format")

				if len(outputFormat) == 0 {
					outputFormat = "json"
				}

				if outputFormat == "yaml" {
					w.Header().Add("Content-Type", "application/yaml")
				} else {
					w.Header().Add("Content-Type", "application/json")
				}

				if validNodeName.MatchString(itemName) {

					if queryResponse, err = snmpQueryAssetBuilder(itemName); err != nil {
						// An unknown node used to come back as an empty 200
						if errors.Is(err, errNodeNotFound) {
							w.WriteHeader(404)
							w.Write([]byte(fmt.Sprintf("{'Error':'Unknown node \\'%s\\''}\n\n", itemName)))
						} else {
							w.WriteHeader(500)
							w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
						}
					} else {

						if outputFormat == "json" {
							outputJSON(queryResponse, isPretty, w, r)
						} else if outputFormat == "yaml" {
							outputYAML(queryResponse, w, r)

						} else {
							w.WriteHeader(500)
							w.Write([]byte(fmt.Sprintf("{'Error':'Invalid format \\'%s\\''}\n\n", outputFormat)))

						}
					}
				} else {
					w.WriteHeader(400)
					w.Write([]byte("{'Error':'Invalid node name'}\n\n"))

				}

			}
		} else {
			w.WriteHeader(http.StatusNotAcceptable)
			w.Write([]byte("406 - Site in maintencer\r"))

		}
	})

	// Create function
	// From a HTTP POST create a file object with device configuration:
	// V2:
	// {
	// 	"group":"CPN",
	// 	"name":"nodotest",
	// 	"snmp-ver":"2",
	// 	"ip":"1.1.1.1",
	// 	"community":
	// 	"alcatel_l"
	// }
	// V3:
	// {
	// 	"group":"Siziano",
	// 	"name":"vb-si-vm-mail02",
	// 	"snmp-ver":"3",
	// 	"ip":"10.253.253.21",
	// 	"user":"<user>",
	// 	"password":"<password>",
	// 	"passphrase":"<passphrase>",
	// 	"encalgo":"aes128",
	// 	"authalgo":"sha",
	// 	"sec-level":"authPriv",
	// 	"include":
	// 	[
	// 		"default",
	// 		"ifTable"
	// 	]

	mux.HandleFunc("/create", func(w http.ResponseWriter, r *http.Request) {
		var (
			v2DataJSON NodeConf_struct_JSON
			v2DataYAML NodeConf_struct_YAML
			yamlBuffer bytes.Buffer
		)
		if httpQueryAllowed.Load() {

			if conf.SSL {
				w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}

			if r.Method == http.MethodPost {
				decoder := json.NewDecoder(r.Body)
				err := decoder.Decode(&v2DataJSON)
				if err != nil {
					// It used to carry on and write a node file full of empty fields
					ErrorLogger(err.Error(), file_line())
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte(fmt.Sprintf("400 - %s\n\n", err.Error())))
					return
				}

				if !validNodeName.MatchString(v2DataJSON.NodeName) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("400 - Invalid or missing node name\n\n"))
					return
				}

				if len(v2DataJSON.NodeIP) == 0 {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("400 - Missing node ip\n\n"))
					return
				}

				if v2DataJSON.NodeSNMPVer != "2" && v2DataJSON.NodeSNMPVer != "2c" && v2DataJSON.NodeSNMPVer != "3" {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("400 - Invalid snmp-ver: allowed values are 2, 2c and 3\n\n"))
					return
				}

				v2DataYAML.NodeGroup = v2DataJSON.NodeGroup
				v2DataYAML.NodeName = v2DataJSON.NodeName
				v2DataYAML.NodeStatus = v2DataJSON.NodeStatus
				v2DataYAML.NodeSNMPVer = v2DataJSON.NodeSNMPVer
				v2DataYAML.NodeIP = v2DataJSON.NodeIP
				v2DataYAML.NodeProtocol = v2DataJSON.NodeProtocol
				v2DataYAML.NodePort = v2DataJSON.NodePort
				v2DataYAML.NodeTimeout = v2DataJSON.NodeTimeout
				v2DataYAML.NodeRetries = v2DataJSON.NodeRetries
				v2DataYAML.NodeUser = v2DataJSON.NodeUser
				if len(v2DataJSON.NodeComm) > 0 {
					if v2DataYAML.NodeComm, err = encrypt(v2DataJSON.NodeComm); err != nil {
						w.WriteHeader(500)
						w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
						return
					}
				}
				if len(v2DataJSON.NodePasswd) > 0 {
					if v2DataYAML.NodePasswd, err = encrypt(v2DataJSON.NodePasswd); err != nil {
						w.WriteHeader(500)
						w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
						return
					}
				}
				if len(v2DataJSON.NodePassPhrase) > 0 {
					if v2DataYAML.NodePassPhrase, err = encrypt(v2DataJSON.NodePassPhrase); err != nil {
						w.WriteHeader(500)
						w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
						return
					}
				}
				v2DataYAML.NodeEncAlgo = v2DataJSON.NodeEncAlgo
				v2DataYAML.NodeAuthAlgo = v2DataJSON.NodeAuthAlgo
				v2DataYAML.NodeSecLevel = v2DataJSON.NodeSecLevel
				v2DataYAML.NodeInclude = v2DataJSON.NodeInclude

				insertTargets(v2DataYAML)

				yamlEncoder := yaml.NewEncoder(&yamlBuffer)
				yamlEncoder.SetIndent(2)
				yamlEncoder.Encode(&v2DataYAML)
				yamlEncoder.Close()

				// filepath.Base on top of the name check above: the path used to be
				// built by concatenation, so a name with ".." escaped the nodes folder
				destFileYAML := filepath.Join(conf.NodesPath, filepath.Base(v2DataJSON.NodeName))

				err = os.WriteFile(destFileYAML, yamlBuffer.Bytes(), 0600)

				if err != nil {
					ErrorLogger("Can't create resource file: ", v2DataJSON.NodeName, destFileYAML, file_line())

					retCode := 500
					w.WriteHeader(retCode)
					w.Write([]byte(fmt.Sprintf("%s\n\n", err.Error())))
				} else {
					retCode := 200
					w.WriteHeader(retCode)
					w.Write([]byte(fmt.Sprintf("%d - %s\n\n", retCode, "ok")))
				}
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
				w.Write([]byte("405 - Method not allowed\r\r"))
			}
		} else {
			w.WriteHeader(http.StatusNotAcceptable)
			w.Write([]byte("406 - Site in maintence\r"))

		}
	})

	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		// The ECDSA suites belong here too: certs/server.crt is an EC certificate,
		// and with the RSA only list a TLS 1.2 client found no suite in common
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}

	srv := &http.Server{
		Addr:         conf.ListenAddress + ":" + strconv.Itoa(conf.ListenPort),
		Handler:      httpLogger(Http)(httpAuth(conf)(mux)),
		ErrorLog:     Error,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	if conf.SSL {
		if err := srv.ListenAndServeTLS(conf.SSLCert, conf.SSLKey); err != nil {
			ErrorLogger(err.Error() + "(" + file_line() + ")")
		}
	} else {
		if err := srv.ListenAndServe(); err != nil {
			ErrorLogger(err.Error() + "(" + file_line() + ")")
		}
	}

}

// Checks the bearer token against the admin password of h2s.conf.
// It only kicks in when "require-auth" is true, so clients written against the
// previous behaviour keep working until the option is turned on.
func httpAuth(conf H2sConf_Struct) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !conf.RequireAuth {
				next.ServeHTTP(w, r)
				return
			}

			adminPwd, err := decrypt(conf.AdminPwd)
			if err != nil || len(adminPwd) == 0 {
				ErrorLogger("require-auth is on but admin-password is missing or cannot be decrypted", file_line())
				w.WriteHeader(http.StatusInternalServerError)
				w.Write([]byte("500 - Authentication is not configured\r\r"))
				return
			}

			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

			if subtle.ConstantTimeCompare([]byte(token), []byte(adminPwd)) != 1 {
				HttpLogger(fmt.Sprintf("Unauthorized %s %s %s", r.Method, r.URL.Path, r.RemoteAddr))
				w.Header().Add("WWW-Authenticate", "Bearer")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("401 - Unauthorized\r\r"))
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func httpLogger(logger *log.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {

				HttpLogger(fmt.Sprintf("%s %s %s %s %s", r.Method, r.URL.Path, r.URL.RequestURI(), r.RemoteAddr, r.UserAgent()))
			}()
			next.ServeHTTP(w, r)
		})
	}
}
