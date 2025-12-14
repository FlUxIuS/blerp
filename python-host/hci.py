import logging
from typing import final

from scapy.layers.bluetooth import *
from scapy.layers.bluetooth4LE import *

# def send_cmd(sock: BluetoothSocket, cmd: Packet):
#     pkt = HCI_Hdr() / HCI_Command_Hdr() / cmd
#     # opcode = pkt.opcode

#     sock.send(pkt)
#     while True:
#         r = sock.recv()
#         if r.type == 0x04 and r.code in (0xE, 0x0F):  # and r.opcode == opcode:
#             if r.status != 0:
#                 logging.warning(f"Command failed {cmd}")
#                 return False
#             return r


# def on_message_rx(dev: Device, sock: BluetoothSocket, cmd: Packet):
#     if cmd is None:
#         return False

#     if HCI_LE_Meta_Long_Term_Key_Request in cmd:
#         assert dev.ltk is not None or dev.stk is not None
#         send_cmd(sock, HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=cmd.handle, ltk=dev.sm.stk))
#         # logging.info(f"Long Term Key Request")
#         return False

#     if HCI_Event_Encryption_Change in cmd:
#         # logging.info(f"Encryption {'enabled' if cmd.enabled else 'disabled'}")
#         return True

#     if HCI_Event_Number_Of_Completed_Packets in cmd:
#         return False

#     return False


def wait_event(sock: BluetoothSocket, evt):
    """
    Wait for one or more events.

    Args:
        sock: BluetoothSocket to receive from
        evt: Either a single Packet type or a list of Packet types to wait for

    Returns:
        The received packet if successful, None if status indicates failure
    """
    # Convert single event to list for uniform handling
    events = evt if isinstance(evt, list) else [evt]
    while True:
        pkt = sock.recv()
        if HCI_Event_Hdr not in pkt:
            continue
            # Check if any of the expected events are in the packet
        for event in events:
            if event in pkt:
                status = getattr(pkt, "status", 0)
                return pkt if status == 0 else None
