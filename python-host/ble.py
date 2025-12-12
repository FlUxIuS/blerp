#!./pyble/bin python
import argparse
import asyncio
import datetime
import fcntl
import logging
import signal
import socket
import sys
from operator import add

from att import ATTManager
from constants import *
from hci import wait_event
from helpers import *
from scapy.compat import raw
from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *
from smp import SecurityManager

# Scapy does not support enhanced connection complete event
# bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete, event=10)
# Custom HCI command, we want to set the public address at runtime
# bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Public_Address, opcode=0x2004)

# bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Custom_Command, opcode=0x209E)

logging.basicConfig(
    format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S", level=logging.INFO
)


class Device:
    pairing_task = None

    def __init__(
        self,
        id: int,
        role: int,
        addr: str,
        addr_type: int,
    ):
        self.id = id
        self.role = role
        self.handle = None
        self.sm = SecurityManager(role)
        self.att = ATTManager()
        self.forwarding = False
        self.sock = None
        self.mtu = 23  # TODO update this dinamically
        self.addr = addr
        self.addr_type = addr_type
        self.start_time = 0
        self.encrypted = False
        self.forwarded_packets = 0
        self.initialized = False
        self.legacy = False

    @property
    def own_address(self):
        return bytes(self.addr.replace(":", ""), "utf-8")

    def set_role(self, role):
        self.role = role

    def send_hci_cmd(self, cmd):
        self.sock.send_command(HCI_Hdr() / HCI_Command_Hdr() / cmd)

    def wait_for(self, evt):
        # Convert single event to list for uniform handling
        events = evt if isinstance(evt, list) else [evt]
        while True:
            pkt = self.sock.recv()
            if HCI_Event_Hdr not in pkt:
                continue
                # Check if any of the expected events are in the packet
            for event in events:
                if event in pkt:
                    status = getattr(pkt, "status", 0)
                    return pkt if status == 0 else None

    def initialize(self, addr=None, addr_type=None):
        # TODO: Check get_socket
        if not self.sock:
            self.sock = get_socket(self.id)
        self.send_hci_cmd(HCI_Cmd_Reset())
        self.send_hci_cmd(HCI_Cmd_Set_Event_Mask())

        if not self.legacy:
            self.send_hci_cmd(HCI_Cmd_LE_Set_Event_Mask())

        if addr and addr_type:
            self.set_address(addr, addr_type)
        else:
            self.set_address(self.addr, self.addr_type)

        # Enable blerp encreq rejection (TODO: make it optional)
        self.send_hci_cmd(HCI_Cmd_LE_Custom_Command(opcode=1))

        if self.legacy:
            self.send_hci_cmd(
                HCI_Cmd_LE_Set_Advertising_Parameters(oatype=self.addr_type),
            )
            self.send_hci_cmd(HCI_Cmd_LE_Set_Scan_Parameters())
        else:
            self.send_hci_cmd(
                HCI_Cmd_LE_Set_Extended_Advertising_Parameters(
                    handle=1, own_addr_type=self.addr_type
                ),
            )
            if self.addr_type == 1:
                self.send_hci_cmd(
                    HCI_Cmd_LE_Set_Advertising_Set_Random_Address(
                        handle=1, random_addr=self.addr
                    )
                )
            self.send_hci_cmd(HCI_Cmd_LE_Set_Extended_Scan_Parameters(type=1))

        self.initialized = True

    # def set_peripheral_mode(self, addr, addr_type, adv_data: list = []):
    #     if not self.initialized:
    #         self.initialize()

    #     # if addr is None:
    #     #     self.copy_advertising_data(target_name=name)
    #     #     self.set_address(self.addr, self.addr_type)
    #     #     # self.set_advertising_data()
    #     # else:
    #     self.set_address(addr, addr_type)

    #     # else:
    #     #     self.set_address(addr, addr_type)
    #     #     self.set_advertising_data(appearance=appearance, name=name)

    #     self.send_hci_cmd(HCI_Cmd_LE_Custom_Command(opcode=1))

    #     # TODO: channel_map settings?
    #     self.send_hci_cmd(
    #         HCI_Cmd_LE_Set_Extended_Advertising_Parameters(
    #             handle=1, own_addr_type=self.addr_type
    #         ),
    #     )
    #     self.set_adv_data(addr, addr_type, adv_data)

    #     self.stop_advertising()
    #     self.start_advertising()

    def start_advertising(self):
        if self.role == BLE_ROLE_PERIPHERAL:
            self.send_hci_cmd(
                HCI_Cmd_LE_Set_Extended_Advertising_Enable(handle=1, enable=1),
            )
            logging.info("Peripheral: Advertising started")
            pkt = wait_event(self.sock, HCI_LE_Meta_Enhanced_Connection_Complete)
            if pkt is not None:
                self.handle = pkt.handle
                self.sm.set_peer_address(pkt.paddr, pkt.patype)

                logging.info("Peripheral: Connection complete")
                # tmp = L2CAP_Connection_Parameter_Update_Request(min_interval=20, max_interval=36, slave_latency=4, timeout_mult=90)
                # l2cap_send(self.sock, self.handle, tmp, 5)
                # print("Sent L2CAP_Connection_Parameter_Update_Request")
            # Send a L2CAP connection parameter update request
            else:
                logging.warning("Connection failed")

    def stop_advertising(self):
        self.send_hci_cmd(
            HCI_Cmd_LE_Set_Extended_Advertising_Enable(handle=1, enable=0)
        )

    def copy_adv_data(self, pkt: Packet):
        if HCI_LE_Meta_Advertising_Report in pkt:
            pass
        elif HCI_LE_Meta_Extended_Advertising_Report in pkt:
            pass

    def set_adv_data(self, addr, addr_type, raw_data: list = []):
        # Set address
        self.addr = addr
        self.addr_type = addr_type

        # If no data is passed, copy a generic mouse
        if len(raw_data) == 0:
            appearance = 962
            service = 0x1812
            raw_data = [
                EIR_Hdr()
                / EIR_Flags(flags=["general_disc_mode", "br_edr_not_supported"]),
                EIR_Hdr() / EIR_CompleteList16BitServiceUUIDs(svc_uuids=[service]),
                EIR_Hdr() / EIR_CompleteLocalName(local_name="SIMOLANERO"),
                EIR_Hdr(type="appearance")
                / EIR_Raw(data=appearance.to_bytes(2, byteorder="little")),
            ]

        self.send_hci_cmd(
            HCI_Cmd_LE_Set_Extended_Advertising_Data(handle=1, data=raw_data)
        )

    def start_scanning(self):
        try:
            if self.legacy:
                self.send_hci_cmd(HCI_Cmd_LE_Set_Scan_Enable(filter_dups=0))
            else:
                self.send_hci_cmd(HCI_Cmd_LE_Set_Extended_Scan_Enable(filter_dups=0))
            logging.info("Central: Scanning started")
        except Exception as e:
            logging.info(f"Could not enable scanning: {e}")
            # self.stop_scanning()
        # self.scanning = True

    def stop_scanning(self):
        try:
            if self.legacy:
                self.send_hci_cmd(HCI_Cmd_LE_Set_Scan_Enable())
            else:
                self.send_hci_cmd(HCI_Cmd_LE_Set_Extended_Scan_Enable(enable=0))
            logging.info("Central: Scanning stopped")
        except:
            logging.info("Could not disable scanning, probably already off...")
        # self.scanning = False

    # EIR_Hdr
    def scan_result(self):
        pass

    def start_targeted_scan(
        self,
        bdaddr: str = None,
        bname: str = None,
        get_data: bool = False,
        timeout: int = 5,
    ):
        self.start_scanning()
        dev_list = set()
        start_time = time.time()
        while True:
            if timeout and (time.time() - start_time) > timeout:
                self.stop_scanning()
                logging.warning(f"Scan timeout after {timeout}s")
                return None, None, None

            pkt = wait_event(
                self.sock,
                [
                    HCI_LE_Meta_Advertising_Report,
                    HCI_LE_Meta_Extended_Advertising_Report,
                ],
            )
            addr = None
            addr_type = None
            adv_type = "Legacy"
            if pkt is None:
                continue

            if HCI_LE_Meta_Extended_Advertising_Report in pkt:
                adv_type = "Extended"
                pkt = pkt[HCI_LE_Meta_Extended_Advertising_Report]
                addr = pkt.address
                addr_type = pkt.address_type
            elif HCI_LE_Meta_Advertising_Report in pkt:
                pkt = pkt[HCI_LE_Meta_Advertising_Report]
                addr = pkt.addr
                addr_type = pkt.atype

            # if addr not in dev_list:
            #     dev_list.add(addr)
            logging.info(f"Found device: {addr} type: {adv_type}")

            found = False
            if bdaddr and bdaddr.lower() == addr.lower():
                found = True
                logging.info(f"Target address acquired: {addr}")
            elif bname:
                if addr.lower() == "dd:4c:ba:15:c1:79":
                    print(bname)
                found = find_device_by_name(bname, pkt)

            if found:
                logging.info(f"Target name '{bname}' acquired: {addr}")
                self.stop_scanning()
                if get_data:
                    return addr, addr_type, pkt.data
                return addr, addr_type, None

    def set_address(self, addr, addr_type):
        self.addr = addr
        self.addr_type = addr_type
        self.sm.set_own_address(addr, addr_type)
        cmd = (
            HCI_Cmd_LE_Set_Random_Address(address=addr)
            if addr_type == 1
            else HCI_Cmd_LE_Set_Public_Address(address=addr)
        )
        self.send_hci_cmd(cmd)

    def connect(self, bdaddr, addr_type=1, extended: bool = True):
        if self.role == BLE_ROLE_CENTRAL:
            self.send_hci_cmd(
                HCI_Cmd_LE_Extended_Create_Connection(
                    patype=addr_type,
                    paddr=bdaddr,
                ),
            )
            print("Central: Sent connection request.")
            pkt = wait_event(
                self.sock,
                HCI_LE_Meta_Enhanced_Connection_Complete,
            )  # We block until we get connection complete

            if pkt is not None:
                self.handle = pkt.handle
                self.sm.set_peer_address(pkt.paddr, pkt.patype)
                logging.info(f"Central: Connection complete")

                # time.sleep(1)
                # if not self.mitm:
                # self.sm.pair(self.sock, self.handle)
            # pair_req = self.sm.pair(bdaddr, addr_type)[0]
            # self.sm_send(pair_req)

    def disconnect(self):
        if self.send_hci_cmd(HCI_Cmd_Disconnect(handle=self.handle, reason=0x13)):
            wait_event(self.sock, HCI_Event_Disconnection_Complete)
            logging.info("Disconnected")

    def reset(self):
        return self.send_hci_cmd(HCI_Cmd_Reset())

    def receive(self, timeout=None) -> HCI_Hdr:
        frag_buffer = b""
        frag_total_size = 0

        while True:
            frag_buffer, frag_total_size, pkt = l2cap_fragment_reassemble(
                frag_buffer, frag_total_size, self.sock.recv()
            )
            if pkt is not None:
                return pkt

    def forward(self, pkt: Packet):
        pkt = pkt.getlayer(L2CAP_Hdr)
        role = "Central" if self.role == BLE_ROLE_CENTRAL else "Peripheral"
        logging.debug(f"Forwarded to {role}: {pkt}")

        acl_send(self.sock, self.handle, pkt)
        # self.forwarded_packets += 1
        # print(f"Forwarded packets to {role}: {self.forwarded_packets}", end="\r")

    def start_pairing(self, block: bool = True):
        if self.role == BLE_ROLE_CENTRAL:
            self.sm.pair(self.sock, self.handle)
            logging.info("Central starting pairing procedure")
        else:
            logging.info("Peripheral starting pairing procedure")
        if not block:
            return

        self.listen()

    def hci_handler(self, pkt: Packet):
        if HCI_LE_Meta_Long_Term_Key_Request in pkt:
            # assert self.sm.ltk is not None
            if self.role == BLE_ROLE_PERIPHERAL:
                # logging.info(f"Long Term Key Request")
                if self.sm.stk is None:
                    self.send_hci_cmd(
                        HCI_Cmd_LE_Long_Term_Key_Request_Negative_Reply(
                            handle=pkt.handle
                        ),
                    )
                else:
                    self.send_hci_cmd(
                        HCI_Cmd_LE_Long_Term_Key_Request_Reply(
                            handle=pkt.handle, ltk=self.sm.stk
                        ),
                    )
            # logging.info(f"Long Term Key Request")
        elif HCI_Event_Encryption_Change in pkt:
            if not self.encrypted and pkt.status == 0:
                self.sm.distribute_keys(self.sock, self.handle)
                self.encrypted = True
                logging.info(
                    f"{'Peripheral' if self.role else 'Central'}: encryption enabled"
                )
        elif HCI_LE_Meta_Connection_Update_Complete in pkt:
            if pkt.status == 255 and self.role == BLE_ROLE_PERIPHERAL:
                self.sm.pair(self.sock, self.handle)
                logging.info(f"Peripheral: sent security request")
        elif HCI_Event_Disconnection_Complete in pkt:
            logging.info(f"Disconnected: reason {pkt.reason} error: {pkt.status}")

    def on_message_rx(self, pkt: Packet):
        if pkt is None:
            return None
        # we want to handle the ATT and SM packets locally if forwarding is disabled

        if HCI_ACL_Hdr in pkt:
            if SM_Hdr in pkt:
                self.sm.on_message_rx(self.sock, self.handle, pkt)
            elif ATT_Hdr in pkt and not self.forwarding:
                self.att.on_message_rx(self.sock, self.handle, pkt)
            elif L2CAP_CmdHdr in pkt:
                return None
            else:
                if ATT_Read_Request in pkt:
                    if pkt.gatt_handle == 0x001F:
                        logging.info("Tampering with battery level")
                if ATT_Read_Response in pkt:
                    if pkt.value == b"d":
                        pkt.setfieldval("value", b"E")
                    # print(f"Forwarding packet {pkt}")
                return pkt
        elif HCI_Event_Hdr in pkt:
            self.hci_handler(pkt)

        return None
        #         self.pairing_task.cancel()

    def listen(self):
        print("Listening")
        while True:
            self.on_message_rx(self.receive())
            if self.encrypted and not self.sm.complete:
                self.sm.complete = True
                logging.info("Pairing completed")
                break

    # def __del__(self):
    #     if self.sock is not None:
    #         # self.disconnect()
    #         self.sock.flush()
    #         self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if self.sock is not None:
            self.sock.flush()
            self.sock.close()


def signal_handler(sig, frame):
    sys.stdout.flush()
    logging.info("Exiting...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(description="BLE Central/Peripheral tool")
    parser.add_argument(
        "--role",
        choices=["central", "peripheral"],
        required=True,
        help="Device role",
    )
    parser.add_argument(
        "--impersonate",
        action="store_true",
        help="Impersonate target device (peripheral only)",
    )
    parser.add_argument(
        "--hci",
        type=int,
        default=0,
        help="HCI device number (default: 0 for hci0)",
    )
    parser.add_argument(
        "--addr",
        default="F8:1A:2B:3F:27:2F",
        help="Own Bluetooth address (default: F8:1A:2B:3F:27:2F)",
    )
    parser.add_argument(
        "--addr-type",
        type=int,
        choices=[0, 1],
        default=0,
        help="Own address type: 0=public, 1=random (default: 0)",
    )
    parser.add_argument(
        "--target",
        type=str,
        help="Target device name to scan for (central mode only)",
    )

    args = parser.parse_args()

    role = BLE_ROLE_CENTRAL if args.role == "central" else BLE_ROLE_PERIPHERAL

    with Device(
        id=args.hci, role=role, addr=args.addr, addr_type=args.addr_type
    ) as dev:
        dev.initialize()

        if role == BLE_ROLE_CENTRAL:
            target_name = args.target if args.target else "SIMOLANER"
            addr, addr_type, data = dev.start_targeted_scan(
                bname=target_name, get_data=True
            )

            if addr is None:
                logging.error(f"Target device '{target_name}' not found")
                sys.exit(1)

            dev.connect(bdaddr=addr, addr_type=addr_type)
            logging.info("Devices connected")
            dev.sm.pair(dev.sock, dev.handle)
            dev.listen()
        else:
            adv_data = None
            if args.impersonate and args.target:
                addr, addr_type, adv_data = dev.start_targeted_scan(
                    bname=args.target, get_data=True
                )

            dev.stop_advertising()

            dev.initialize(addr, addr_type)
            # dev.set_address(addr, addr_type)

            dev.set_adv_data(addr, addr_type, adv_data)

            dev.start_advertising()

            dev.listen()

            # dev.set_peripheral_mode(
            #     addr=args.addr, addr_type=args.addr_type, adv_data=adv_data
            # )
