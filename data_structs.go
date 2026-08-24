package main

import (
	"database/sql"
	"sync"
	"sync/atomic"
)

// h2s configuration struct
type H2sConf_Struct struct {
	ListenAddress string `yaml:"listen-address"`
	ListenPort    int    `yaml:"listen-port"`
	SSL           bool   `yaml:"ssl"`
	SSLCert       string `yaml:"ssl-cert"`
	SSLKey        string `yaml:"ssl-key"`
	AdminPwd      string `yaml:"admin-password"`
	RequireAuth   bool   `yaml:"require-auth"`
	ConsolePort   int    `yaml:"console-port"`
	NodesPath     string `yaml:"nodes-path"`
}

type NodeConf_struct_JSON struct {
	NodeGroup      string   `json:"group"`
	NodeName       string   `json:"name"`
	NodeStatus     bool     `json:"active"`
	NodeSNMPVer    string   `json:"snmp-ver"`
	NodeSecLevel   string   `json:"sec-level,omitempty"`
	NodeIP         string   `json:"ip"`
	NodeProtocol   string   `json:"protocol,omitempty"`
	NodePort       int      `json:"port,omitempty"`
	NodeComm       string   `json:"community,omitempty"`
	NodeTimeout    int      `json:"timeout,omitempty"`
	NodeRetries    int      `json:"retries,omitempty"`
	NodeInclude    []string `json:"include,omitempty"`
	NodeUser       string   `json:"user,omitempty"`
	NodePasswd     string   `json:"password,omitempty"`
	NodePassPhrase string   `json:"passphrase,omitempty"`
	NodeEncAlgo    string   `json:"encalgo,omitempty"`
	NodeAuthAlgo   string   `json:"authalgo,omitempty"`
}

type NodeConf_struct_YAML struct {
	NodeGroup      string   `yaml:"group"`
	NodeName       string   `yaml:"name"`
	NodeStatus     bool     `yaml:"active"`
	NodeSNMPVer    string   `yaml:"snmp-ver"`
	NodeSecLevel   string   `yaml:"sec-level,omitempty"`
	NodeIP         string   `yaml:"ip"`
	NodeProtocol   string   `yaml:"protocol,omitempty"`
	NodePort       int      `yaml:"port,omitempty"`
	NodeComm       string   `yaml:"community,omitempty"`
	NodeTimeout    int      `yaml:"timeout,omitempty"`
	NodeRetries    int      `yaml:"retries,omitempty"`
	NodeInclude    []string `yaml:"include,omitempty"`
	NodeUser       string   `yaml:"user,omitempty"`
	NodePasswd     string   `yaml:"password,omitempty"`
	NodePassPhrase string   `yaml:"passphrase,omitempty"`
	NodeEncAlgo    string   `yaml:"encalgo,omitempty"`
	NodeAuthAlgo   string   `yaml:"authalgo,omitempty"`
}

type OIDS_struct_YAML struct {
	Name  string            `yaml:"name"`
	Get   map[string]string `yaml:"get,omitempty"`
	Bulk  map[string]string `yaml:"bulk,omitempty"`
	Table map[string]string `yaml:"table,omitempty"`
	Cmd   map[string]string `yaml:"cmd,omitempty"`
}

type OID_map_struct struct {
	OIDName   string
	OID       string
	QueryType int
	Type      string
}

type Response_struct struct {
	OIDName  string
	OIDValue interface{}
}

type sqlNode struct {
	id         int
	group      string
	name       string
	active     int
	snmpver    string
	ip         string
	protocol   string
	port       int
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
}

var db *sql.DB

// The OID map is read by the HTTP handlers while the console can reload it, so it
// is never written in place: loadOIDList builds a new map and swaps it under the lock.
var oidMap map[string]string
var oidMapLock sync.RWMutex

// Read by the HTTP handlers, written by the console goroutine during a reload
var httpQueryAllowed atomic.Bool

var (
	h2sVersion string
	h2sTitle   string
)

// Returns the OID map currently in use. loadOIDList never modifies a map it has
// already published, so the caller can keep reading the returned one without the lock.
func currentOIDMap() map[string]string {
	oidMapLock.RLock()
	defer oidMapLock.RUnlock()

	return oidMap
}
