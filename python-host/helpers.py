import fcntl
import logging
import os
import struct
import sys
from typing import Tuple

from constants import *
from scapy.fields import *
from scapy.layers.bluetooth import *
from scapy.packet import *


class LE3BytesField(Field):
    """Little-endian 3-byte (24-bit) field for BLE extended advertising intervals."""

    def __init__(self, name, default):
        Field.__init__(self, name, default, "<I")  # Use int for internal repr

    def addfield(self, pkt, s, val):
        # Pack as little-endian, take only first 3 bytes
        return s + struct.pack("<I", val)[:3]

    def getfield(self, pkt, s):
        # Read 3 bytes, pad to 4 bytes for unpacking
        return s[3:], struct.unpack("<I", s[:3] + b"\x00")[0]


def hci_cmd_get(cmd):
    return HCI_Hdr() / HCI_Command_Hdr() / cmd


class HCI_Cmd_LE_Set_Public_Address(Packet):
    name = "LE Set Public Address"
    fields_desc = [LEMACField("address", None)]


class HCI_Cmd_LE_Custom_Command(Packet):
    name = "LE Custom Command"
    fields_desc = [LEShortField("opcode", 0)]


# class SM_Security_Request(Packet):
#     name = "Security Request"
#     fields_desc = [BitField("authentication", 0, 8)]


class HCI_Cmd_LE_Set_Event_Mask(Packet):
    name = "HCI_LE_Set_Event_Mask"
    fields_desc = [
        StrFixedLenField("mask", b"\xff\x1f\x0a\x03\x00\x00\x00\x00", 8)
    ]  # noqa: E501


class HCI_Cmd_LE_Set_Extended_Scan_Parameters(Packet):
    name = "HCI_LE_Set_Extended_Scan_Parameters"
    fields_desc = [
        # 1. Own Address Type (0x01 = Random)
        ByteEnumField(
            "atype",
            0,
            {0: "public", 1: "random", 2: "rpa (pub)", 3: "rpa (random)"},
        ),
        # 2. Filter Policy (0x00 = Accept all)
        ByteEnumField(
            "policy",
            0,
            {0: "all", 1: "whitelist", 2: "undirected_rpa", 3: "whitelist_rpa"},
        ),
        # 3. PHYs (0x05 = 1M (bit 0) | Coded (bit 2))
        # Note: If you change this value, you technically need to add/remove the
        # config blocks below. This structure assumes 0x05.
        ByteField("scanning_phys", 0x01),
        # --- Entry 0: LE 1M Config ---
        ByteEnumField("type", 0, {0: "passive", 1: "active"}),
        XLEShortField("interval", 0x0012),  # 22.5 ms
        XLEShortField("window", 0x0012),  # 11.25 ms
        # --- Entry 1: LE Coded Config ---
        # Note: These fields only exist because bit 2 was set in scanning_phys
        # ByteEnumField("type_coded", 1, {0: "passive", 1: "active"}),
        # XLEShortField("interval_coded", 0x006C),  # 67.5 ms
        # XLEShortField("window_coded", 0x0036),  # 33.75 ms
    ]


class HCI_Cmd_LE_Set_Extended_Scan_Enable(Packet):
    name = "HCI_LE_Set_Extended_Scan_Enable"
    fields_desc = [
        # 1. Enable (0x01 = Enabled)
        ByteEnumField("enable", 1, {0: "disabled", 1: "enabled"}),
        # 2. Filter Duplicates (0x01 = Enabled)
        ByteEnumField(
            "filter_dups", 1, {0: "disabled", 1: "enabled", 2: "reset_period"}
        ),
        # 3. Duration (0x0000 = Continuous)
        # Unit is 10ms. 0 means scan until disabled.
        XLEShortField("duration", 500),
        # 4. Period (0x0000 = No period)
        # Unit is 1.28s. 0 means continuous.
        XLEShortField("period", 0),
    ]


# --- 1. Define the Parameters Command (Opcode 0x2036) ---
class HCI_Cmd_LE_Set_Extended_Advertising_Parameters(Packet):
    name = "HCI_LE_Set_Extended_Advertising_Parameters"
    fields_desc = [
        ByteField("handle", 0),
        # Properties: 0x0010 = Use Legacy PDUs (backward compat), 0x0000 = Connectable
        # Use 0x0000 for standard Extended Adv (Connectable)
        XLEShortField("properties", 0x0013),
        LE3BytesField("pri_interval_min", 160),  # 100ms (3 bytes per BT spec)
        LE3BytesField("pri_interval_max", 160),  # 100ms (3 bytes per BT spec)
        ByteField("pri_channel_map", 7),  # 37, 38, 39
        ByteEnumField("own_addr_type", 0, {0: "public", 1: "random"}),
        ByteEnumField("peer_addr_type", 0, {0: "public", 1: "random"}),
        LEMACField("peer_addr", None),
        ByteEnumField("filter_policy", 0, {0: "all"}),
        ByteField("tx_power", 127),  # 127 = No preference
        # PHY Configuration
        ByteEnumField("pri_phy", 1, {1: "1M", 3: "Coded"}),  # Primary PHY
        ByteField("sec_max_skip", 0),
        ByteEnumField("sec_phy", 1, {1: "1M", 2: "2M", 3: "Coded"}),  # Secondary PHY
        ByteField("sid", 0),  # Set ID
        ByteField("scan_req_notify_enable", 0),
    ]


bind_layers(
    HCI_Command_Hdr,
    HCI_Cmd_LE_Set_Extended_Advertising_Parameters,
    ogf=0x08,
    ocf=0x0036,
)


# --- LE Extended Create Connection (Opcode 0x2043) ---
class HCI_Cmd_LE_Extended_Create_Connection(Packet):
    name = "HCI_LE_Extended_Create_Connection"
    fields_desc = [
        # Initiator_Filter_Policy
        ByteEnumField("filter", 0, {0: "peer_addr", 1: "filter_accept_list"}),
        # Own_Address_Type
        ByteEnumField(
            "atype", 0, {0: "public", 1: "random", 2: "rpa_pub", 3: "rpa_random"}
        ),
        # Peer_Address_Type
        ByteEnumField("patype", 0, {0: "public", 1: "random"}),
        # Peer_Address
        LEMACField("paddr", None),
        # Initiating_PHYs (bit 0=1M, bit 1=2M, bit 2=Coded)
        ByteField("init_phys", 0x01),
        # --- PHY parameters for LE 1M (when bit 0 set) ---
        LEShortField("scan_interval", 96),
        LEShortField("scan_window", 96),
        LEShortField("min_interval", 40),
        LEShortField("max_interval", 80),
        LEShortField("latency", 0),
        LEShortField("timeout", 500),
        LEShortField("min_ce", 0),
        LEShortField("max_ce", 0),
        # Note: Add additional blocks for 2M/Coded if init_phys includes those bits
    ]


bind_layers(
    HCI_Command_Hdr, HCI_Cmd_LE_Extended_Create_Connection, ogf=0x08, ocf=0x0043
)


# --- LE Enhanced Connection Complete Event (Subevent 0x0A) ---
class HCI_LE_Meta_Enhanced_Connection_Complete(Packet):
    name = "LE Enhanced Connection Complete"
    fields_desc = [
        ByteEnumField("status", 0, {0: "success"}),
        LEShortField("handle", 0),
        ByteEnumField("role", 0, {0: "master", 1: "slave"}),
        ByteEnumField("patype", 0, {0: "public", 1: "random"}),
        LEMACField("paddr", None),
        LEMACField("local_rpa", None),  # Local Resolvable Private Address
        LEMACField("peer_rpa", None),  # Peer Resolvable Private Address
        LEShortField("interval", 54),
        LEShortField("latency", 0),
        LEShortField("supervision", 42),
        XByteField("clock_latency", 5),
    ]

    def answers(self, other):
        if HCI_Cmd_LE_Extended_Create_Connection not in other:
            return False
        return (
            other[HCI_Cmd_LE_Extended_Create_Connection].patype == self.patype
            and other[HCI_Cmd_LE_Extended_Create_Connection].paddr == self.paddr
        )


bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete, event=0x0A)


# --- 2. Define the Enable Command (Opcode 0x2039) ---
# Note: This is different from Legacy Enable! It takes a list of sets.
class HCI_Cmd_LE_Set_Extended_Advertising_Enable(Packet):
    name = "HCI_LE_Set_Extended_Advertising_Enable"
    fields_desc = [
        ByteEnumField("enable", 1, {0: "disable", 1: "enable"}),
        ByteField("num_sets", 1),
        ByteField("handle", 0),
        XLEShortField("duration", 0),  # 0 = Continuous
        ByteField("max_events", 0),
    ]


bind_layers(
    HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Advertising_Enable, ogf=0x08, ocf=0x0039
)


# --- LE Set Advertising Set Random Address (Opcode 0x2035) ---
class HCI_Cmd_LE_Set_Advertising_Set_Random_Address(Packet):
    name = "HCI_LE_Set_Advertising_Set_Random_Address"
    fields_desc = [
        ByteField("handle", 0),
        LEMACField("random_addr", None),
    ]


bind_layers(
    HCI_Command_Hdr,
    HCI_Cmd_LE_Set_Advertising_Set_Random_Address,
    ogf=0x08,
    ocf=0x0035,
)


class HCI_Cmd_LE_Set_Extended_Advertising_Data(Packet):
    name = "HCI_LE_Set_Extended_Advertising_Data"
    fields_desc = [
        # 1. Advertising Handle (0x00 - 0xEF)
        # Identifies which advertising set this data belongs to.
        ByteField("handle", 0),
        # 2. Operation
        # 0=Intermediate, 1=First, 2=Last, 3=Complete, 4=Unchanged
        # Use 3 (Complete) if your data fits in one packet (<= 251 bytes)
        ByteEnumField(
            "operation",
            3,
            {
                0: "intermediate_frag",
                1: "first_frag",
                2: "last_frag",
                3: "complete",
                4: "unchanged_data",
            },
        ),
        # 3. Fragment Preference
        # 0=Controller may fragment, 1=Controller should not fragment
        ByteEnumField("frag_pref", 1, {0: "allow_frag", 1: "no_frag"}),
        # 4. Data Length (Auto-calculated)
        FieldLenField("data_len", None, length_of="data", fmt="B"),
        # 5. Advertising Data
        PacketListField("data", [], EIR_Hdr, length_from=lambda pkt: pkt.len),
    ]


# Bind to Opcode 0x2037
bind_layers(
    HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Advertising_Data, ogf=0x08, ocf=0x0037
)

# Bind Parameters command to Opcode 0x2041
bind_layers(
    HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Scan_Parameters, ogf=0x08, ocf=0x0041
)

# Bind Enable command to Opcode 0x2042
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Scan_Enable, ogf=0x08, ocf=0x0042)

bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Event_Mask, ogf=0x08, ocf=0x0001)

bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Public_Address, ogf=0x08, ocf=0x0004)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Custom_Command, ogf=0x08, ocf=0x009E)
bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0B)


def l2cap_send(sock: BluetoothUserSocket, handle: int, cmd, cid: int):
    pkt = HCI_Hdr() / HCI_ACL_Hdr(handle=handle) / L2CAP_Hdr(cid=cid) / cmd
    sock.send(pkt)


def acl_send(sock: BluetoothUserSocket, handle: int, cmd: L2CAP_Hdr):
    sock.send(HCI_Hdr() / HCI_ACL_Hdr(handle=handle) / cmd)


def sm_send(sock: BluetoothUserSocket, handle: int, pkt):
    l2cap_send(cmd=SM_Hdr() / pkt, cid=BLE_L2CAP_CID_SM)


def l2cap_fragment_reassemble(
    frag_buf: bytes, frag_tot_size: int, pkt: Packet
) -> Tuple[bytes, int, Packet]:
    if pkt.type != 2 or not L2CAP_Hdr in pkt:
        return b"", 0, pkt

    if pkt.PB == 2 and pkt[L2CAP_Hdr].len > pkt[HCI_ACL_Hdr].len:
        return raw(pkt), pkt[L2CAP_Hdr].len, None

    if pkt.PB == 1 and len(frag_buf) > 0:
        prev = HCI_Hdr(frag_buf)
        frag_buf += raw(pkt[HCI_ACL_Hdr:][1:])  # Maybe this can be done differently
        if (
            len(raw(prev[L2CAP_Hdr:][1:])) + len(raw(pkt[HCI_ACL_Hdr:][1:]))
            == frag_tot_size
        ):
            return b"", 0, HCI_Hdr(frag_buf)
        else:
            return frag_buf, frag_tot_size, None

    return b"", 0, pkt


def find_device_by_name(name: str, pkt) -> Tuple[str, str]:
    if len(pkt.data) > 0:
        for hdr in pkt.data:
            if EIR_CompleteLocalName in hdr or EIR_ShortenedLocalName in hdr:
                print(hdr.local_name.decode())
                return hdr.local_name.decode() == name
    return False


def dev_down(id):
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
    sock.bind((id,))
    fcntl.ioctl(sock.fileno(), HCI_DEV_DOWN, id)
    sock.close()


def get_socket(id):
    try:
        return BluetoothUserSocket(id)
    except BluetoothSocketError:
        if os.getuid() != 0:
            sys.exit("Please run as root")
        else:
            dev_down(id)
            try:
                return BluetoothUserSocket(id)
            except BluetoothSocketError as e:
                sys.exit(f"Unable to open socket hci{id}: {e}")


# def att_send(self, cmd):
#     self.l2cap_send(cmd=ATT_Hdr() / cmd, cid=BLE_L2CAP_CID_ATT)
