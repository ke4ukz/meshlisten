from meshtastic.serial_interface import SerialInterface
from meshtastic.tcp_interface import TCPInterface
import meshtastic
from meshtastic.protobuf import admin_pb2, mesh_pb2, portnums_pb2, localonly_pb2
from pubsub import pub
from datetime import datetime
from sys import exit, stderr
from time import sleep
from typing import Any, Tuple
import argparse
import base64
import contextlib
import json
import os
import shlex
import sqlite3
import threading
from prompt_toolkit import patch_stdout, PromptSession

debug_enabled:bool = False
quiet:bool = False  # stop printing received packets (they are still stored)
log_admin:bool = False  # store ADMIN_APP packets, which can contain keys, passwords and session passkeys
config_request:dict|None = None  # {"pending": set of config sections still to print, "unredacted": bool}
# fields hidden by the c command unless "c unredacted" is used
REDACTED_CONFIG_FIELDS = {"security": ["private_key"], "network": ["wifi_psk"], "bluetooth": ["fixed_pin"]}
REDACTED_NODE_FIELDS = ["position", "adminSessionPassKey"]
MESSAGE_RX_SUBSCRIPTION = "meshtastic.receive"
SNIFF_PORTNUM = portnums_pb2.PortNum.ValueType(300)  # private port handled by the custom firmware SniffModule
sniff_requested:bool = False
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "meshlisten.db")
db:sqlite3.Connection|None = None
db_lock = threading.Lock()  # packets are stored from the meshtastic reader thread

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY,     -- auto-incrementing row id
    rx_time REAL NOT NULL,      -- local receive time, unix epoch seconds
    from_node INTEGER,
    to_node INTEGER,
    portnum TEXT,               -- e.g. TEXT_MESSAGE_APP, or the number for private ports; NULL if still encrypted
    packet_id INTEGER,          -- MeshPacket.id, for matching replies and duplicates
    port TEXT,                  -- serial device or host the packet arrived through
    local_node INTEGER,         -- node number of the connected device
    packet_json TEXT NOT NULL,  -- packet dict as JSON (bytes base64-encoded, protobuf "raw" objects omitted)
    packet_raw BLOB             -- serialized MeshPacket protobuf, exactly as received
);
"""

class ANSIColor:
    """ ANSI color codes """
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    GREEN = "\033[0;32m"
    BROWN = "\033[0;33m"
    BLUE = "\033[0;34m"
    PURPLE = "\033[0;35m"
    CYAN = "\033[0;36m"
    LIGHT_GRAY = "\033[0;37m"
    DARK_GRAY = "\033[1;30m"
    LIGHT_RED = "\033[1;31m"
    LIGHT_GREEN = "\033[1;32m"
    YELLOW = "\033[1;33m"
    LIGHT_BLUE = "\033[1;34m"
    LIGHT_PURPLE = "\033[1;35m"
    LIGHT_CYAN = "\033[1;36m"
    LIGHT_WHITE = "\033[1;37m"
    BOLD = "\033[1m"
    FAINT = "\033[2m"
    ITALIC = "\033[3m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    NEGATIVE = "\033[7m"
    CROSSED = "\033[9m"
    END = "\033[0m"

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    connection = parser.add_mutually_exclusive_group()
    connection.add_argument("-p", "--port", action="store", type=str, help="Serial port to use for device communication")
    connection.add_argument("--host", action="store", type=str, help="Hostname or IP address of a node on Wi-Fi (TCP port 4403)")
    parser.add_argument("--debug", action="store_true", default=False, help="Enables printing additional debugging messages (such as full tx and rx packets)")
    parser.add_argument("--quiet", action="store_true", default=False, help="Don't print received packets as they arrive (they are still stored)")
    parser.add_argument("--hops", action="store", type=int, default=3, help="Specifies the default hop limit when sending messages")
    parser.add_argument("--db", action="store", type=str, default=DEFAULT_DB_PATH, help="SQLite database file for the received packet history")
    parser.add_argument("--log-admin", action="store_true", default=False,
                        help="Also store ADMIN_APP packets. These include config replies with the node's private key, Wi-Fi password and admin session passkeys")
    parser.add_argument("--purge-admin", action="store_true", default=False,
                        help="Delete stored ADMIN_APP packets and compact the database. Without --port or --host, exit afterwards")
    args = parser.parse_args()
    if not (args.port or args.host or args.purge_admin):
        parser.error("one of the arguments -p/--port --host is required")
    return args

def node_name(interface, num):
    """Turn a numeric node ID into !deadbeef + friendly name if known."""
    if num is None:
        return "unknown"
    node = interface.nodesByNum.get(num, {})
    user = node.get("user", {})

    node_id = f"!{num:08x}"
    name = user.get("longName") or user.get("shortName")

    return f"{name} ({node_id})" if name else node_id

def print_message(time:datetime, interface, packet:dict)->None:

    decoded = packet.get("decoded", {})

    sender = packet.get("from")
    destination = packet.get("to")

    portnum = decoded.get("portnum", "UNKNOWN")

    rx_snr = packet.get("rxSnr")
    rx_rssi = packet.get("rxRssi")

    hop_start = packet.get("hopStart")
    hop_limit = packet.get("hopLimit")

    # Approximate number of hops already consumed, when both are available.
    hops = None
    if hop_start is not None and hop_limit is not None:
        hops = hop_start - hop_limit

    print(
        f"{time:%H:%M:%S}  "
        f"{node_name(interface, sender)} -> "
        f"{node_name(interface, destination)}"
    )

    print(
        f"  {portnum}"
        f" | hops={hops}"
        f" | SNR={rx_snr}"
        f" | RSSI={rx_rssi}"
    )

    # A little useful information for packet types we're interested in.
    if portnum == "POSITION_APP":
        position = decoded.get("position", {})

        lat = position.get("latitude")
        lon = position.get("longitude")
        altitude = position.get("altitude")

        if lat is not None and lon is not None:
            print(f"  position: {lat:.5f}, {lon:.5f}  alt={altitude}")

    elif portnum == "TELEMETRY_APP":
        telemetry = decoded.get("telemetry", {})

        device = telemetry.get("deviceMetrics")
        environment = telemetry.get("environmentMetrics")

        if device:
            print(
                f"  battery={device.get('batteryLevel')}% "
                f"voltage={device.get('voltage')}V "
                f"channelUtil={device.get('channelUtilization')}%"
            )
        if environment:
            print(f"  environment: {environment}")

    elif portnum == "NODEINFO_APP":
        user = decoded.get("user", {})
        print(
            f"hardware={user.get("hwModel")} "
            f"psk={user.get("publicKey")}"
        )

    elif portnum == "ROUTING_APP":
        routing = decoded.get("routing", {})
        print(
            f"  request ID={routing.get("requestId")} "
            f"error reason={routing.get("errorReason")}"
        )

def open_db(path:str)->sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)  # autocommit
    conn.executescript(DB_SCHEMA)
    return conn

def purge_admin_packets(conn:sqlite3.Connection)->int:
    """Delete stored ADMIN_APP packets, then VACUUM so the deleted data is gone from the file too"""
    with db_lock:
        removed = conn.execute("DELETE FROM packets WHERE portnum = 'ADMIN_APP'").rowcount
        conn.execute("VACUUM")
    return removed

def json_safe(value):
    """Copy of a packet dict that json can serialize"""
    if isinstance(value, dict):
        return {k: json_safe(v) for k, v in value.items() if k != "raw"}
    if isinstance(value, (list, tuple)):
        return [json_safe(v) for v in value]
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)

def store_packet(time:datetime, interface, packet:dict)->None:
    portnum = packet.get("decoded", {}).get("portnum")
    if portnum == "ADMIN_APP" and not log_admin:
        return  # config replies carry secrets, only kept with --log-admin
    raw = packet.get("raw")
    row = (
        time.timestamp(),
        packet.get("from"),
        packet.get("to"),
        None if portnum is None else str(portnum),
        packet.get("id"),
        getattr(interface, "devPath", None) or getattr(interface, "hostname", None),
        interface.localNode.nodeNum if interface.localNode else None,
        json.dumps(json_safe(packet), ensure_ascii=False),
        raw.SerializeToString() if raw is not None else None,
    )
    try:
        with db_lock:
            if db is None:
                return
            db.execute(
                "INSERT INTO packets (rx_time, from_node, to_node, portnum, packet_id, port, local_node, packet_json, packet_raw)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", row)
    except sqlite3.Error as ex:
        print(f"Error storing packet: {ex}", file=stderr)

def on_receive(packet, interface):
    """Called when a message is received"""
    rx_time = datetime.now()
    store_packet(rx_time, interface, packet)
    decoded = packet.get("decoded", {})
    if decoded.get("portnum") in (SNIFF_PORTNUM, str(SNIFF_PORTNUM)):
        payload = decoded.get("payload", b"")
        state = "on" if payload[:1] == b"\x01" else "off"
        print(f"Sniff mode: {state}")
        return
    if decoded.get("portnum") == "ADMIN_APP":
        handle_admin_packet(packet, interface)
    dbg(packet)
    if not quiet:
        print_message(rx_time, interface, packet)

def node_num_arg(value:str)->int:
    """argparse type for node IDs: !xxxxxxxx or a broadcast alias"""
    nodeid, errmsg = parse_node_id(value)
    if nodeid is None:
        raise argparse.ArgumentTypeError(errmsg)
    if nodeid == meshtastic.BROADCAST_ADDR:
        return meshtastic.BROADCAST_NUM
    return int(nodeid[1:], 16)

def date_arg(value:str)->float:
    """argparse type for dates, returned as unix epoch seconds to compare against rx_time"""
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        raise argparse.ArgumentTypeError("dates must look like 2026-01-01 or 2026-01-01T13:00")

def build_messages_parser()->argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="m", description="Browse the stored packet history")
    verbs = parser.add_subparsers(dest="verb", metavar="{list,find,show}")

    lst = verbs.add_parser("list", help="list stored packets by number (default: the most recent)",
                           description="m list [first [last]]: list packets by number. With no numbers, the most recent are shown.")
    lst.add_argument("first", nargs="?", type=int, help="first packet number")
    lst.add_argument("last", nargs="?", type=int, help="last packet number")
    lst.add_argument("--from", dest="from_num", type=int, help="first packet number (same as first)")
    lst.add_argument("--to", dest="to_num", type=int, help="last packet number (same as last)")
    lst.add_argument("--count", type=int, default=20, help="number of packets to show when the range is open-ended (default 20)")

    find = verbs.add_parser("find", help="find packets by text, node, type or date (most recent matches)")
    find.add_argument("text", nargs="?", help="message text to look for (not case sensitive, %% and _ match literally)")
    find.add_argument("--anywhere", action="store_true", help="search the whole JSON packet instead of just the message text")
    find.add_argument("--from", dest="from_node", type=node_num_arg, help="sender, !xxxxxxxx")
    find.add_argument("--to", dest="to_node", type=node_num_arg, help="recipient, !xxxxxxxx or ^all (also all, broadcast, *) for broadcasts")
    find.add_argument("--via", dest="via_node", type=node_num_arg, help="receiving device (the connected node), !xxxxxxxx")
    find.add_argument("--type", help="packet type (portnum), e.g. TEXT_MESSAGE_APP or 300")
    find.add_argument("--since", type=date_arg, help="received on or after this date/time, e.g. 2026-01-01 or 2026-01-01T13:00")
    find.add_argument("--until", type=date_arg, help="received before this date/time")
    find.add_argument("--count", type=int, default=20, help="maximum number of matches to show (default 20)")

    show = verbs.add_parser("show", help="show one packet in detail")
    show.add_argument("num", type=int, help="packet number, as shown by list")
    show.add_argument("--packet", action="store_true", help="also print the stored JSON packet")
    show.add_argument("--raw", action="store_true", help="also print the raw MeshPacket protobuf")
    return parser

def like_escape(text:str)->str:
    """Escape LIKE wildcards so user text matches literally (used with ESCAPE '\\')"""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

def select_packets(where:list, params:list, newest_first:bool, limit:int|None)->list:
    """Rows of (id, rx_time, packet_json), always returned oldest first"""
    sql = "SELECT id, rx_time, packet_json FROM packets"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY id {'DESC' if newest_first else 'ASC'}"
    params = list(params)
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    with db_lock:
        rows = db.execute(sql, params).fetchall()
    if newest_first:
        rows.reverse()
    return rows

def count_packets(where:list, params:list)->int:
    sql = "SELECT COUNT(*) FROM packets"
    if where:
        sql += " WHERE " + " AND ".join(where)
    with db_lock:
        return db.execute(sql, params).fetchone()[0]

def list_query(margs:argparse.Namespace)->list|None:
    if margs.first is not None and margs.from_num is not None:
        print("give the first packet number either as an argument or with --from, not both")
        return None
    if margs.last is not None and margs.to_num is not None:
        print("give the last packet number either as an argument or with --to, not both")
        return None
    first = margs.first if margs.first is not None else margs.from_num
    last = margs.last if margs.last is not None else margs.to_num

    if first is not None and last is not None:
        return select_packets(["id BETWEEN ? AND ?"], [first, last], newest_first=False, limit=None)
    if first is not None:
        return select_packets(["id >= ?"], [first], newest_first=False, limit=margs.count)
    if last is not None:
        return select_packets(["id <= ?"], [last], newest_first=True, limit=margs.count)
    return select_packets([], [], newest_first=True, limit=margs.count)

def find_query(margs:argparse.Namespace)->tuple[list, int]:
    """Most recent matching rows, and the total number of matches"""
    where = []
    params:list = []
    if margs.text is not None:
        # only fixed column expressions are put in the SQL text, user input always goes through parameters
        column = "packet_json" if margs.anywhere else "json_extract(packet_json, '$.decoded.text')"
        where.append(f"{column} LIKE ? ESCAPE '\\'")
        params.append(f"%{like_escape(margs.text)}%")
    if margs.from_node is not None:
        where.append("from_node = ?")
        params.append(margs.from_node)
    if margs.to_node is not None:
        where.append("to_node = ?")
        params.append(margs.to_node)
    if margs.via_node is not None:
        where.append("local_node = ?")
        params.append(margs.via_node)
    if margs.type is not None:
        where.append("portnum = ? COLLATE NOCASE")
        params.append(margs.type)
    if margs.since is not None:
        where.append("rx_time >= ?")
        params.append(margs.since)
    if margs.until is not None:
        where.append("rx_time < ?")
        params.append(margs.until)
    rows = select_packets(where, params, newest_first=True, limit=margs.count)
    return rows, count_packets(where, params)

def print_packet_row(interface, num:int, rx_time:float, packet:dict)->None:
    decoded = packet.get("decoded", {})
    portnum = decoded.get("portnum", "ENCRYPTED" if "encrypted" in packet else "UNKNOWN")
    line = (
        f"{num:>6} | {datetime.fromtimestamp(rx_time):%Y-%m-%d %H:%M:%S}  "
        f"{node_name(interface, packet.get('from'))} -> "
        f"{node_name(interface, packet.get('to'))}"
        f" @ {portnum}"
    )
    text = decoded.get("text")
    if text:
        line += f": {text}"
    print(line)

def list_packets(interface, margs:argparse.Namespace)->None:
    total = None
    if margs.verb == "find":
        rows, total = find_query(margs)
    else:
        rows = list_query(margs)
    if rows is None:
        return
    if not rows:
        print("no matching packets")
        return
    for num, rx_time, packet_json in rows:
        print_packet_row(interface, num, rx_time, json.loads(packet_json))
    if total is not None and total > len(rows):
        print(f"{total} matches, showing the most recent {len(rows)} (use --count to see more)")

def show_packet(interface, margs:argparse.Namespace)->None:
    with db_lock:
        row = db.execute("SELECT rx_time, local_node, packet_json, packet_raw FROM packets WHERE id = ?", (margs.num,)).fetchone()
    if row is None:
        print(f"no packet {margs.num}")
        return
    rx_time, local_node, packet_json, packet_raw = row
    packet = json.loads(packet_json)
    print(f"packet {margs.num}, received {datetime.fromtimestamp(rx_time):%Y-%m-%d %H:%M:%S} via {node_name(interface, local_node)}")
    print_message(datetime.fromtimestamp(rx_time), interface, packet)
    if margs.packet:
        print(json.dumps(packet, indent=2, ensure_ascii=False))
    if margs.raw:
        if packet_raw is None:
            print("no raw packet stored")
        else:
            print(mesh_pb2.MeshPacket.FromString(packet_raw))

def handle_admin_packet(packet, interface):
    global config_request
    if packet.get("from") != interface.localNode.nodeNum:
        # only a reply from our own node describes localConfig
        return
    admin = packet["decoded"]["admin"]["raw"]
    if admin.HasField("get_config_response"):
        cfg = admin.get_config_response
        section = cfg.WhichOneof("payload_variant")
        getattr(interface.localNode.localConfig, section).CopyFrom(getattr(cfg, section))
        request = config_request
        if request is not None and section in request["pending"]:
            print_config_section(section, getattr(cfg, section), request["unredacted"])
            request["pending"].discard(section)
            if not request["pending"]:
                config_request = None
    elif admin.HasField("get_device_connection_status_response"):
        print_connection_status(interface, admin.get_device_connection_status_response)

def request_connection_status(interface)->None:
    p = admin_pb2.AdminMessage()
    p.get_device_connection_status_request = True
    # the library has no public helper for this request, getMetadata() uses _sendAdmin the same way
    interface.localNode._sendAdmin(p, wantResponse=True)

def format_ip(ip:int)->str:
    # the firmware stores the address with the first octet in the low byte
    return ".".join(str((ip >> shift) & 0xFF) for shift in (0, 8, 16, 24))

def print_connection_status(interface, conn)->None:
    if conn.HasField("wifi"):
        wifi = conn.wifi
        if wifi.status.is_connected:
            print(f'wifi: connected to "{wifi.ssid}", {format_ip(wifi.status.ip_address)}, RSSI {wifi.rssi} dBm')
        else:
            enabled = interface.localNode.localConfig.network.wifi_enabled
            network = f'network "{wifi.ssid}"' if wifi.ssid else "no network set"
            print(f"wifi: not connected ({'enabled' if enabled else 'disabled'} in config, {network})")
    else:
        print("wifi: not in this firmware")
    if conn.HasField("ethernet"):
        eth = conn.ethernet.status
        print(f"ethernet: connected, {format_ip(eth.ip_address)}" if eth.is_connected else "ethernet: not connected")
    if conn.HasField("bluetooth"):
        print(f"bluetooth: {'connected' if conn.bluetooth.is_connected else 'not connected'}")
    else:
        print("bluetooth: not in this firmware")
    if conn.HasField("serial"):
        print(f"serial: {'connected' if conn.serial.is_connected else 'not connected'}, {conn.serial.baud} baud")

def request_config(interface, unredacted:bool)->None:
    """Print local info now, then ask the node for every config section (printed as the replies arrive)"""
    global config_request
    print(interface.myInfo)
    node = dict(interface.getMyNodeInfo() or {})
    if not unredacted:
        for field in REDACTED_NODE_FIELDS:
            if field in node:
                node[field] = "<redacted>"
    print(node)

    sections = [f for f in localonly_pb2.LocalConfig.DESCRIPTOR.fields if f.name != "version"]  # version can't be requested
    config_request = {"pending": {f.name for f in sections}, "unredacted": unredacted}
    print(f"requesting {len(sections)} config sections...")
    for field in sections:
        interface.localNode.requestConfig(field)

def print_config_section(section:str, values, unredacted:bool)->None:
    hidden = []
    if not unredacted:
        copy = type(values)()
        copy.CopyFrom(values)
        for field in REDACTED_CONFIG_FIELDS.get(section, []):
            if copy.HasField(field) if copy.DESCRIPTOR.fields_by_name[field].has_presence else getattr(copy, field):
                copy.ClearField(field)
                hidden.append(field)
        values = copy
    print(f"{section}:")
    for line in str(values).splitlines():
        print(f"  {line}")
    if hidden:
        print(f"  ({', '.join(hidden)} redacted, use \"c unredacted\" to show)")

def print_help():
    print("h help - prints this help")
    print("status - shows the node's wifi, bluetooth and serial connection status")
    print("c config [unredacted] - prints local device config (keys, passwords and position hidden unless unredacted)")
    print("n nodes [node_id] - list nodes or shows node details")
    print("q quit - quits")
    print("t traceroute <node_id> - sends traceroute message to node")
    print("m messages [list|find|show] ... - browse stored packets (m -h, m list -h, etc. for options)")
    print("s send <node_id> <message> - sends text message to node")
    print("r request <node_id> - sends info request to node")
    print("d debug [on|off] - extra debugging messages (including sent and received packets)")
    print("quiet [on|off] - stops printing received packets as they arrive (they are still stored)")
    print()
    print("hops [hop_count] - sets the message hop limit to specify when sending")
    print("sniff [on|off] - receive and report packets that are addressed to other nodes")
    print("reboot - reboots the node")
    print("shutdown - shuts down the node and quits")
    print()
    print("node addresses are in the format !xxxxxxxx")
    print("^all, ^any, all, any, broadcast, or * are also allowed as a node ID")
    print("and will broadcast the message - use with responsibility")

def print_nodes(nodes)->None:
    for id, node in nodes.items():
        user = node.get("user", {})
        name = user.get("longName") or user.get("shortName", "<unknown>")
        model = user.get("hwModel", "<unknown>")
        position = node.get("position", {})
        last_heard = node.get("lastHeard") or position.get("lastHeard") or position.get("time")
        if last_heard is None:
            last_heard = ""
        else:
            last_heard = f"{datetime.fromtimestamp(last_heard):%Y-%m-%d %H:%M:%S}"
        
        print(f"{id}\t{name:<24}\t{model:<24}\t{last_heard}")

def parse_node_id(id:str)->Tuple[str|None,str]:
    if (id.lower() in ("any", "all", "^any", "^all", "broadcast", "*")):
        return meshtastic.BROADCAST_ADDR, "success"

    if (len(id) != 9):
        return None, "node IDs must be in the format !xxxxxxxx"
    if (id[0] != "!"):
        return None, "node IDs must start with !"

    try:
        nodeid = int(id[1:], 16)
    except ValueError:
        return None, "node IDs must be 8 hex characters"
    return f"!{nodeid:08x}", "success"

def print_dict(d, indent=0):

    for k, v in d.items():
        if isinstance(v, dict):
            print(f"{" " * indent} {k}:")
            print_dict(v, indent + 2)
        else:
            print(f"{" " * indent} {k} = {v}")

def dbg(msg:Any)->None:
    global debug_enabled
    if (not debug_enabled):
        return
    print(f"{ANSIColor.YELLOW}{msg}{ANSIColor.END}")

# commands that talk to the node, refused while reconnecting
NODE_COMMANDS = {"c", "settings", "config", "status", "t", "traceroute", "tracert", "trace", "s", "send",
                 "r", "request", "sniff", "reboot", "shutdown"}

def open_interface(args:argparse.Namespace):
    if args.host:
        return TCPInterface(args.host)
    return SerialInterface(args.port)

class Connection:
    """Holds the current interface and replaces it when the library reports the connection lost"""

    def __init__(self, args:argparse.Namespace, interface):
        self.args = args
        self.interface = interface
        self.closing = False
        self.reconnecting = False
        self.lock = threading.Lock()
        self.reboot_count = interface.myInfo.reboot_count if interface.myInfo else None
        pub.subscribe(self.on_connection_lost, "meshtastic.connection.lost")

    @property
    def connected(self)->bool:
        return not self.reconnecting and self.interface.isConnected.is_set()

    def on_connection_lost(self, interface):
        with self.lock:
            if self.closing or self.reconnecting or interface is not self.interface:
                return
            self.reconnecting = True
        threading.Thread(target=self._reconnect, args=(interface,), daemon=True).start()

    def _reconnect(self, old):
        target = self.args.host or self.args.port
        print(f"{ANSIColor.YELLOW}Connection to {target} lost, reconnecting...{ANSIColor.END}")
        # closing the dead interface also stops its heartbeat timer
        with contextlib.suppress(Exception):
            old.close()

        new = None
        delay = 2
        while new is None and not self.closing:
            try:
                new = open_interface(self.args)
            except (OSError, meshtastic.mesh_interface.MeshInterface.MeshInterfaceError) as ex:
                dbg(f"reconnect to {target} failed ({ex}), retrying in {delay}s")
                sleep(delay)
                delay = min(delay * 2, 60)
        if new is None:
            return
        if self.closing:
            with contextlib.suppress(Exception):
                new.close()
            return

        reboot_count = new.myInfo.reboot_count if new.myInfo else None
        self.interface = new
        self.reconnecting = False
        if self.reboot_count is not None and reboot_count is not None and reboot_count > self.reboot_count:
            print(f"{ANSIColor.YELLOW}Reconnected to {target}, the node rebooted "
                  f"(reboot count {self.reboot_count} -> {reboot_count}){ANSIColor.END}")
        else:
            print(f"{ANSIColor.YELLOW}Reconnected to {target}{ANSIColor.END}")
        self.reboot_count = reboot_count
        if sniff_requested:
            # sniff mode lives in the node's RAM, so a reboot turned it off
            new.sendData(b"\x01", destinationId=new.localNode.nodeNum, portNum=SNIFF_PORTNUM, wantResponse=True)

    def close(self):
        self.closing = True
        with contextlib.suppress(Exception):
            self.interface.close()

def main(args: argparse.Namespace)->int:
    global debug_enabled, quiet, log_admin, sniff_requested, db

    debug_enabled = args.debug
    quiet = args.quiet
    log_admin = args.log_admin

    try:
        db = open_db(args.db)
    except sqlite3.Error as ex:
        print(f"Can't open database {args.db}: {ex}", file=stderr)
        return 1
    dbg(f"Storing packets in {args.db}")

    if args.purge_admin:
        try:
            removed = purge_admin_packets(db)
        except sqlite3.Error as ex:
            print(f"Purging admin packets failed: {ex}", file=stderr)
            return 1
        print(f"Removed {removed} admin packets from {args.db}")
        if not (args.port or args.host):
            db.close()
            return 0

    prompt_session = PromptSession()
    messages_parser = build_messages_parser()

    dbg(f"subscribing to {MESSAGE_RX_SUBSCRIPTION}")
    pub.subscribe(on_receive, MESSAGE_RX_SUBSCRIPTION)

    hop_limit:int = args.hops

    target = args.host or args.port
    dbg(f"Connecting to {target}")

    try:
        interface = open_interface(args)
    except FileNotFoundError as ex:
        print(f"{args.port} not found on this system ({ex})", file=stderr)
        return 1
    except OSError as ex:
        # TCP: refused, unreachable, unknown host
        print(f"failed to connect to {target} ({ex})", file=stderr)
        return 1
    except meshtastic.mesh_interface.MeshInterface.MeshInterfaceError:
        print(f"failed to connect to {target}, the device may be shut down", file=stderr)
        return 1

    conn = Connection(args, interface)
    try:
        dbg(f"{len(interface.nodes)} nodes currently known)")
        print("use n to list known nodes")
        print("Use ? or help for commands")
        print("Listening for messages")
        
        while True:
            try:
                cmdline = prompt_session.prompt(":").strip()
            except KeyboardInterrupt:
                print("Quitting")
                break
            except EOFError:
                # clear input line
                continue
            except Exception as ex:
                print(f"Error: {ex}")
                continue

            # only the command word is case insensitive, arguments (like message text) keep their case
            cmd, _, rest = cmdline.partition(" ")
            cmd = cmd.lower()
            rest = rest.strip()
            cmdargs = rest.split()

            interface = conn.interface  # may have been replaced by a reconnect
            if cmd in NODE_COMMANDS and not conn.connected:
                print("Not connected to the node right now (reconnecting), try again shortly")
                continue

            if cmd in ("n", "nodes"):
                if len(cmdargs) == 0:
                    print_nodes(interface.nodes)
                else:
                    node = interface.nodes.get(cmdargs[0].lower())
                    if node is not None:
                        print_dict(node)
            elif cmd in ("q", "exit", "quit"):
                break
            elif cmd in ("c", "settings", "config"):
                if len(cmdargs) > 0 and cmdargs[0].lower() != "unredacted":
                    print("usage: c [unredacted]")
                    continue
                request_config(interface, unredacted=len(cmdargs) > 0)
            elif cmd == "status":
                request_connection_status(interface)
            elif cmd in ("t", "traceroute", "tracert", "trace"):
                if len(cmdargs) == 0:
                    print("must provide a node ID in the format !xxxxxxxx")
                    continue
                nodeid, errmsg = parse_node_id(cmdargs[0])
                if nodeid is None:
                    print(errmsg)
                    continue
                print(f"Sending traceroute to {nodeid} (if the node is offline, this may take some time before it fails - press CTRL+C to cancel)")
                try:
                    sent_packet = interface.sendTraceRoute(dest=nodeid, hopLimit=hop_limit)
                    dbg(sent_packet)
                except meshtastic.mesh_interface.MeshInterface.MeshInterfaceError as e:
                    print(f"Traceroute failed: {e}")
                except KeyboardInterrupt:
                    continue
            elif cmd in ("m", "messages"):
                try:
                    margs = messages_parser.parse_args(shlex.split(rest))
                except SystemExit:
                    continue  # argparse already printed the usage or error
                except ValueError as ex:  # e.g. unbalanced quotes
                    print(f"Error: {ex}")
                    continue
                if margs.verb is None:
                    margs = messages_parser.parse_args(["list"])
                try:
                    if margs.verb == "show":
                        show_packet(interface, margs)
                    else:
                        list_packets(interface, margs)
                except sqlite3.Error as ex:
                    print(f"Database error: {ex}")
                except KeyboardInterrupt:
                    # CTRL+C stops a long listing instead of quitting the program
                    print("\n(output stopped)")
            elif cmd in ("s", "send"):
                if len(cmdargs) < 2:
                    print("recipient node id and message required")
                    continue
                nodeid, errmsg = parse_node_id(cmdargs[0])
                if nodeid is None: 
                    print(errmsg)
                    continue
                text = rest.split(None, 1)[1]
                print(f"sending '{text}' to {nodeid}")
                sent_packet = interface.sendText(destinationId=nodeid, text=text, wantAck=True, wantResponse=False, hopLimit=hop_limit)
                dbg(sent_packet)
            elif cmd in ("r", "request"):
                if len(cmdargs) == 0:
                    print("node id required")
                    continue
                nodeid, errmsg = parse_node_id(cmdargs[0])
                if nodeid is None:
                    print(errmsg)
                    continue
                print(f"sending info request to {nodeid}")
                sent_packet = interface.sendData(b"", destinationId=nodeid, portNum=portnums_pb2.NODEINFO_APP, wantAck=True, wantResponse=True, hopLimit=hop_limit)
                dbg(sent_packet)
            elif cmd in ("d", "debug"):
                if len(cmdargs) == 0:
                    print(f"Debug printing: {"enabled" if debug_enabled else "disabled"}")
                    continue
                if cmdargs[0].lower() in ("enabled", "on", "true", "enable", "1", "y", "yes"):
                    debug_enabled = True
                    dbg("debug printing enabled")
                elif cmdargs[0].lower() in ("disabled", "off", "false", "disable", "0", "n", "no"):
                    debug_enabled = False
                    print("debug printing disabled")
                else:
                    print("invalid argument")
                    continue
            elif cmd == "quiet":
                if len(cmdargs) == 0:
                    print(f"Quiet mode: {"enabled" if quiet else "disabled"}")
                    continue
                if cmdargs[0].lower() in ("enabled", "on", "true", "enable", "1", "y", "yes"):
                    quiet = True
                    print("quiet mode enabled, received packets are stored but not printed")
                elif cmdargs[0].lower() in ("disabled", "off", "false", "disable", "0", "n", "no"):
                    quiet = False
                    print("quiet mode disabled")
                else:
                    print("invalid argument")
                    continue
            elif cmd == "sniff":
                if len(cmdargs) == 0:
                    payload = b"\x02"  # query only
                elif cmdargs[0].lower() in ("enabled", "on", "true", "enable", "1", "y", "yes"):
                    payload = b"\x01"
                    sniff_requested = True
                elif cmdargs[0].lower() in ("disabled", "off", "false", "disable", "0", "n", "no"):
                    payload = b"\x00"
                    sniff_requested = False
                else:
                    print("invalid argument")
                    continue
                sent_packet = interface.sendData(payload, destinationId=interface.localNode.nodeNum, portNum=SNIFF_PORTNUM, wantResponse=True)
                dbg(sent_packet)
            elif cmd == "hops":
                if len(cmdargs) == 0:
                    print(f"Current hop limit: {hop_limit}")
                    continue
                try:
                    newhoplimit = int(cmdargs[0])
                    if newhoplimit < 0:
                        print("hop limit must be positive")
                        continue
                    hop_limit = newhoplimit
                    print(f"hop limit set to {hop_limit}")
                except ValueError:
                    print("hop limit must be a positive integer")
                    continue
            elif cmd == "shutdown":
                print("Shutting down node...")
                interface.localNode.shutdown(1)
                break
            elif cmd == "reboot":
                print("Rebooting node...")
                interface.localNode.reboot(1)
                break
            elif cmd == "":
                continue
            else:
                print_help()
        if sniff_requested and conn.connected:
            # sniff mode is for this script only, don't leave it on for the next client
            conn.interface.sendData(b"\x00", destinationId=conn.interface.localNode.nodeNum, portNum=SNIFF_PORTNUM)
            sleep(0.5)
        dbg("Quitting")
    finally:
        conn.close()
    with db_lock:
        db.close()
        db = None
    dbg("Done")
    return 0

if __name__ == "__main__":
    with patch_stdout.patch_stdout(raw=True):
        exit(main(parse_args()))