# meshlisten

An interactive command-line listener for a [Meshtastic](https://meshtastic.org) node connected over USB serial.
It prints packets as they arrive, keeps a searchable history of everything received in SQLite, and has
commands for sending messages, traceroutes and info requests.

## Requirements

- Python 3.12 or newer
- A Meshtastic node connected by USB serial
- Standard Meshtastic firmware (only the `sniff` command needs a custom module)

```
pip install -r requirements.txt
```

## Usage

```
python3 meshlisten.py --port /dev/cu.usbserial-XXXX
```

| Option | |
|-|-|
| `-p`, `--port` | Serial port of the node (required) |
| `--db` | SQLite file for the packet history (default: `meshlisten.db` next to the script) |
| `--hops` | Default hop limit for messages you send (default 3) |
| `--debug` | Print extra debugging output, including full packets |

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
| `c`, `config` | Fetch and print the connected node's config |
| `m`, `messages` | Browse the stored packet history (see below) |
| `hops [n]` | Show or set the hop limit for sent messages |
| `d`, `debug [on\|off]` | Show or toggle debug output |
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

### Sniff mode

Normally a node only passes packets to the client if they are broadcast or addressed to it. `sniff on`
asks the node to also pass along packets addressed to other nodes that it overhears or relays.

Sniff needs a custom firmware module that listens on private port 300. It isn't part of standard
Meshtastic firmware, and with standard firmware the command has no effect. `meshlisten` turns sniff mode
off again when it quits.

## License

[GNU Affero General Public License v3.0](LICENSE)
