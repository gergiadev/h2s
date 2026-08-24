# h2s — HTTP to SNMP Proxy

h2s asks SNMP questions to your devices and returns the answers as JSON or YAML over HTTP.

You describe each device in a small YAML file. You describe the OIDs you want to read in
another YAML file. h2s reads both at start, keeps them in memory, and serves them at
`GET /get?name=<device>`.

```
                  +-----------+  SNMP   +---------------+
  GET /get  --->  |    h2s    | ------> | your devices  |
  JSON/YAML <---  +-----------+         +---------------+
                    ^       ^
              nodes/   queryconfs/
```

## Table of contents

- [Install](#install)
- [Quick start](#quick-start)
- [Host files](#host-files)
- [OID list files](#oid-list-files)
- [The oids_map file](#the-oids_map-file)
- [Reading data](#reading-data)
- [The admin console](#the-admin-console)
- [Main configuration](#main-configuration)
- [Things to know](#things-to-know)

## Install

You need Go 1.22 or newer.

h2s encrypts the device passwords. The AES key is not stored in the code: you pass it at
build time. The key must be **exactly 32 bytes**.

```bash
export H2S_AES_KEY='<your 32 bytes key>'
make
```

If you build without the key, h2s stops at start and tells you what is missing.

> **Important:** always use the same key. If you change the key, you must encrypt all
> passwords again. See `ROTAZIONE-CREDENZIALI.md`.

## Quick start

```bash
export H2S_AES_KEY='<your 32 bytes key>'
make
./h2s -s
```

At the first run, if `h2s.conf` does not exist, h2s creates a default one and stops.
Open the file, check the values, and start h2s again.

When you see `Ready`, the server is listening. Try it:

```bash
curl 'http://localhost:23432/get?name=bb-web1-aec&pretty'
```

## Host files

One file per device, inside the `nodes/` folder (you can change the folder with
`nodes-path` in `h2s.conf`).

The file name is free, but it is a good idea to use the device name. What really counts
is the `name:` field inside the file: this is the value you pass to `/get?name=`.

### Fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `group` | string | no | — | A free label to group devices. Only shown in the console. |
| `name` | string | **yes** | — | The name used in `/get?name=`. |
| `active` | bool | no | `false` | Stored, but see [Things to know](#things-to-know). |
| `snmp-ver` | string | **yes** | — | `2`, `2c` or `3`. |
| `ip` | string | **yes** | — | Address of the device. |
| `protocol` | string | no | `udp` | `udp` or `tcp`. Any other value becomes `udp`. |
| `port` | int | no | `161` | SNMP port. |
| `timeout` | int | no | `10` | Seconds to wait for an answer. |
| `retries` | int | no | `3` | How many times to try again. |
| `include` | list | no | — | Names of the OID lists to read. See below. |
| `community` | string | v2c only | — | **Encrypted.** |
| `user` | string | v3 only | — | SNMPv3 user name. |
| `password` | string | v3 only | — | **Encrypted.** Authentication password. |
| `passphrase` | string | v3 only | — | **Encrypted.** Privacy password. |
| `authalgo` | string | v3 only | — | Authentication protocol: `MD5` or `SHA`. |
| `encalgo` | string | v3 only | — | Privacy protocol: `DES` or `AES`. |
| `sec-level` | string | v3 only | — | `noAuthNoPriv`, `authNoPriv` or `authPriv`. |

Values of `authalgo`, `encalgo` and `sec-level` are not case sensitive.

> **Careful with the two algorithm fields.** `authalgo` is how the device *signs* the
> message (MD5 / SHA). `encalgo` is how the device *encrypts* it (DES / AES). It is easy
> to swap them by mistake, and the error message from SNMP is not always clear.

### Encrypt the secrets first

You never write a password in clear text. Use the `-e` option to encrypt it, then copy
the result into the file:

```bash
$ ./h2s -e 'my-snmp-password'
Qf3NPW7Y1SBtXZ5hrGHsxtwYucaWN8I3Hf0rDEffOlXCf24aODllRnFdkQ==
```

Do the same for `passphrase` and for `community`. You can read a value back with `-d`:

```bash
./h2s -d 'Qf3NPW7Y1SBtXZ5hrGHsxtwYucaWN8I3Hf0rDEffOlXCf24aODllRnFdkQ=='
```

### Example: SNMPv2c

`nodes/router-01`

```yaml
group: branch-office
name: router-01
active: true
snmp-ver: "2c"
ip: 192.168.0.10
port: 161
protocol: udp
timeout: 10
retries: 3
community: c-543wBGUoF7QBBRnafUvFV-yKEaror2nMViVHFt_vOasKowmaIo
include:
  - default
```

The quotes around `"2c"` are not required: YAML also converts a plain `2` or `3` into
text here. The files in this repository use quotes anyway, because they make clear that
the value is a version label and not a number.

### Example: SNMPv3

`nodes/db-server-01`

```yaml
group: datacenter
name: db-server-01
active: true
snmp-ver: "3"
ip: 192.168.0.143
port: 161
timeout: 10
retries: 3
sec-level: authPriv
user: monitoring
password: tM80fii8aQzkCcqmBkD3HSbqZwS5Ue9RuMx0owpIP7rgTLDrP2TXICteoA==
passphrase: CRG5LVp7NwAwfZtvbtH8oFtgpVvKJE6Q24rI6VLu6JU6Z2jN1ky6rw==
authalgo: SHA
encalgo: AES
include:
  - default
  - iftable
```

### Create a host over HTTP

You can also send the device as JSON. h2s encrypts the secrets for you and writes the
YAML file:

```bash
curl -X POST http://localhost:23432/create \
  -H 'Content-Type: application/json' \
  -d '{
        "group":"datacenter",
        "name":"db-server-02",
        "snmp-ver":"3",
        "ip":"192.168.0.144",
        "user":"monitoring",
        "password":"<password>",
        "passphrase":"<passphrase>",
        "authalgo":"sha",
        "encalgo":"aes",
        "sec-level":"authPriv",
        "include":["default","iftable"]
      }'
```

Here you send the passwords in **clear text**, so use HTTPS (`ssl: true`) if the request
leaves your machine.

The name must contain only letters, numbers, dot, dash and underscore.

## OID list files

One file per list, inside the `queryconfs/` folder. A list is a group of OIDs that you
want to read together. A device asks for a list with `include`.

### How a host finds a list

The link is the `name:` field **inside** the list file, not the file name:

```yaml
# queryconfs/default.yml
name: default        # <-- this is what you write in "include"
```

```yaml
# nodes/router-01
include:
  - default          # <-- matches the "name" above
```

### The four action types

Each list can contain four blocks. Every entry is `label: OID`. The label becomes the key
in the JSON answer, so choose a name that means something to you.

| Block | SNMP operation | What you get back |
|---|---|---|
| `get` | GET on one OID | a single value |
| `bulk` | walk under an OID | an object: name → value |
| `table` | walk under an OID | an object: column → list of values |
| `cmd` | *no SNMP*, runs a shell command | a list of output lines |

#### `get`

Use it for one single value, like the system description.

```yaml
name: default
get:
  sysdescr: .1.3.6.1.2.1.1.1.0
```

Answer:

```json
{ "sysdescr": "Linux bb-web1-aec 4.19.0-8-amd64 x86_64" }
```

#### `bulk`

Use it to read everything under a branch. h2s adds the last number of the OID to the
name, so you can tell the entries apart.

```yaml
name: default
bulk:
  load: .1.3.6.1.4.1.2021.10.1.3
```

Answer:

```json
{
  "load": {
    "laLoad.1": "0.64",
    "laLoad.2": "0.76",
    "laLoad.3": "1.35"
  }
}
```

#### `table`

Same walk as `bulk`, but the values are grouped by column. Use it for real tables, like
the interface table.

```yaml
name: iftable
table:
  iftable1: 1.3.6.1.2.1.31.1.1
```

Answer:

```json
{
  "iftable1": {
    "ifName":        ["lo", "eth0", "eth1"],
    "ifHCInOctets":  ["1420", "88213", "0"],
    "ifHCOutOctets": ["1420", "45120", "0"]
  }
}
```

The values keep the same order in every column, so `ifName[1]` and `ifHCInOctets[1]`
describe the same interface.

#### `cmd`

This block does **not** talk SNMP. It runs a command on the machine where h2s runs, and
puts the output in the answer. It goes through the shell, so pipes and quotes work.

```yaml
name: iftable
cmd:
  custom: /usr/bin/ls -alrt | awk '{print $NF}'
```

Answer:

```json
{ "custom": ["..", ".", "file-one", "file-two"] }
```

> **Security note:** anything written here runs as the h2s user. Treat `queryconfs/` as
> trusted files and do not let untrusted people write in that folder.

### A complete list file

```yaml
name: system
get:
  sysdescr: .1.3.6.1.2.1.1.1.0
  sysuptime: .1.3.6.1.2.1.1.3.0
bulk:
  load: .1.3.6.1.4.1.2021.10.1.3
  memory: .1.3.6.1.4.1.2021.4
table:
  interfaces: 1.3.6.1.2.1.31.1.1
```

A device can include more than one list. The answers are merged in one object, so use
different labels in different lists to avoid a collision.

## The oids_map file

This file translates numeric OIDs into readable names. It is used by `bulk` and `table`.

The format is one line per OID: the **name**, one space, the **OID**.

```
sysGenInfoShelfName 1.3.6.1.4.1.43.1.12.3.1.1.1.1.1
laLoad 1.3.6.1.4.1.2021.10.1.3
ifName 1.3.6.1.2.1.31.1.1.1
```

If an OID is not in this file, h2s uses the numeric OID as the key. Nothing breaks, the
answer is only harder to read.

Lines that do not have exactly one space are skipped, and h2s writes an error in
`h2s.log`. If a name looks missing, check that line first.

## Reading data

```bash
# default output: JSON on one line
curl 'http://localhost:23432/get?name=router-01'

# easier to read
curl 'http://localhost:23432/get?name=router-01&pretty'

# YAML instead of JSON
curl 'http://localhost:23432/get?name=router-01&format=yaml'
```

| Status | Meaning |
|---|---|
| `200` | OK. |
| `400` | The name is empty or has characters that are not allowed. |
| `404` | No device with that name. |
| `406` | h2s is reloading. Try again in a moment. |
| `500` | Something went wrong. Look at `h2s.log`. |

If the device does not answer, you still get `200`, and the body contains an `Error` key:

```json
{ "Error": "Error in get SNMP object: read udp 127.0.0.1:45173->127.0.0.1:161: read: connection refused" }
```

So always check for an `Error` key before you read the values.

### Turn on authentication

Set `require-auth: true` in `h2s.conf`. Then every request needs the admin password as a
bearer token:

```bash
curl -H "Authorization: Bearer <admin password>" \
  'http://localhost:23432/get?name=router-01&pretty'
```

The default is `false`, so old clients keep working until you turn it on.

## The admin console

h2s opens a small text console on `localhost:3333` (change it with `console-port`).
It asks for the admin password.

```bash
nc localhost 3333
```

| Command | What it does |
|---|---|
| `show all` | List every device in memory. |
| `show target <name>` | Show one device, secrets hidden. |
| `show target full <name>` | Same, but shows the secrets in clear text. |
| `query <statement>` | Run a raw SELECT, DELETE or UPDATE. |
| `reload hosts` | Read the `nodes/` folder again. |
| `reload oid` | Read `oids_map` again. |
| `version` | Show the h2s version. |
| `help` | Show the list of commands. |
| `quit` | Close the connection. |

Use `reload hosts` after you add or edit a file in `nodes/`: you do not need to restart.

## Main configuration

`h2s.conf`, in the folder where you start h2s.

```yaml
listen-address: 127.0.0.1
listen-port: 23432
ssl: false
ssl-cert: "certs/server.crt"
ssl-key: "certs/server.key"
admin-password: <encrypted with ./h2s -e>
require-auth: false
console-port: 3333
nodes-path: ./nodes
```

`admin-password` is used by the console and, when `require-auth` is true, by the HTTP
API. Create it with `./h2s -e 'your-password'`.

## Things to know

These are current limits of h2s. They are not bugs you need to fix, but they surprise
people the first time.

- **The `queryconfs/` folder is read only at start.** `reload oid` reloads `oids_map`,
  not the list files. After you add or change a file in `queryconfs/`, restart h2s.
- **The `active` field does nothing yet.** h2s stores it and shows it in the console, but
  it does not skip a device when `active: false`. Every device in `nodes/` is loaded.
- **The path `./queryconfs` is fixed.** Only `nodes-path` can be changed.
- **Console commands are lower case.** The console puts the whole line in lower case, so
  `show target MyHost` does not find a device called `MyHost`. Use lower case names.
- **`timeout` and `retries` multiply.** A device that is down takes
  `timeout × retries` seconds. With the defaults that is about 30 seconds, which is more
  than the HTTP write timeout of 10 seconds. Lower `timeout` for devices that are often
  unreachable.
- **Do not commit your secrets.** `h2s.conf`, `nodes/` and `certs/*.key` are in
  `.gitignore` for a reason.
