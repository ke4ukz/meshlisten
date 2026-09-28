# meshlisten

An interactive command-line listener for a [Meshtastic](https://meshtastic.org) node connected over USB serial.
It prints packets as they arrive, keeps a searchable history of everything received in SQLite, and has
commands for sending messages, traceroutes and info requests.

## Requirements

- Python 3.12 or newer
- A Meshtastic node connected by USB serial, or reachable over Wi-Fi
- Standard Meshtastic firmware (only the `sniff` command needs a custom module)

```
pip install -r requirements.txt
```

## Usage

```
python3 meshlisten.py --port /dev/cu.usbserial-XXXX
python3 meshlisten.py --host 192.168.1.50
```

| Option | |
|-|-|
| `-p`, `--port` | Serial port of the node |
| `--host` | Hostname or IP address of a node on Wi-Fi (TCP port 4403); use this or `--port` |
| `--db` | SQLite file for the packet history (default: `meshlisten.db` next to the script) |
| `--hops` | Default hop limit for messages you send (default 3) |
| `--debug` | Print extra debugging output, including full packets |
| `--quiet` | Don't print received packets as they arrive (they are still stored) |
| `--log-admin` | Also store `ADMIN_APP` packets. See [Admin packets](#admin-packets) before using this |
| `--purge-admin` | Delete stored `ADMIN_APP` packets and compact the database. On its own it exits afterwards; with `--port` or `--host` it then starts normally |

On macOS, the first `--host` connection may fail with "No route to host" while macOS asks whether your
terminal app may access devices on the local network. Allow it and run the command again. The setting is in
System Settings → Privacy & Security → Local Network.

Running one instance per node is fine. They can share the same database, and each packet records which
node received it.

## Commands

| Command | |
|-|-|
| `h`, `help` | Show the command list |
| `n`, `nodes [node_id]` | List known nodes, or show one node's details |
| `s`, `send <node_id> <message>` | Send a text message |
| `t`, `traceroute <node_id>` | Send a traceroute |
| `r`, `request <node_id>` | Request node info |
| `c`, `config [unredacted]` | Fetch and print the connected node's config. Private key, Wi-Fi password, Bluetooth PIN and position are hidden unless `unredacted` is given |
| `status` | Show the node's firmware version, hardware model and role, and its Wi-Fi, Bluetooth and serial connection status (including its IP address) |
| `m`, `messages` | Browse the stored packet history (see below) |
| `hops [n]` | Show or set the hop limit for sent messages |
| `d`, `debug [on\|off]` | Show or toggle debug output |
| `quiet [on\|off]` | Show or toggle printing of received packets (they are still stored) |
| `sniff [on\|off]` | Show or toggle sniff mode (needs custom firmware, see below) |
| `reboot`, `shutdown` | Reboot or shut down the node, then quit |
| `q`, `quit` | Quit |

Node IDs are written `!xxxxxxxx`. `^all`, `all`, `any`, `broadcast` or `*` mean broadcast.

### Packet history

Every packet received is stored in the `packets` table: receive time, sender, recipient, packet type,
packet ID, the receiving node, the packet as JSON, and the original protobuf.

```
m                          the 20 most recent packets
m list 1 10                packets 1 to 10 (also: m list --from 1 --to 10)
m list 25                  20 packets starting at 25
m find hello               most recent packets whose text contains "hello"
m find --from !0012abcd --type TEXT_MESSAGE_APP --since 2026-01-01
m show 23 --packet --raw   one packet in detail, with its JSON and protobuf
```

`m -h`, `m list -h`, `m find -h` and `m show -h` list all options. CTRL+C stops a long listing.

### Admin packets

`ADMIN_APP` packets are the node's replies to admin requests, such as the config sections fetched by `c`.
They can contain the node's **private key**, **Wi-Fi password**, **Bluetooth PIN** and admin session
passkeys, so they are not stored unless you pass `--log-admin`.

If you do use `--log-admin`, treat the database file as sensitive: don't share it or commit it. To remove
them later, run `python3 meshlisten.py --purge-admin`. This deletes the rows and runs SQLite's `VACUUM`,
so the data is removed from the file itself, not just hidden.

### Sniff mode

Normally a node only passes packets to the client if they are broadcast or addressed to it. `sniff on`
asks the node to also pass along packets addressed to other nodes that it overhears or relays.

Sniff needs a custom firmware module that listens on private port 300. It isn't part of standard
Meshtastic firmware, and with standard firmware the command has no effect. `meshlisten` turns sniff mode
off again when it quits.

## License

[GNU Affero General Public License v3.0](LICENSE)
