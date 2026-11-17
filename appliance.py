# DO NOT modify or add any import statements
from __future__ import annotations
import os
import sys
import struct
import random
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, Tuple, Optional, List, Any
from support import *

# -----------------------------------------------------------------------------

"""
[1] GeeksforGeeks, “Convert Bytes to Bits in Python,” GeeksforGeeks, [Online].
    Available: https://www.geeksforgeeks.org/python/convert-bytes-to-bits-in-python/.
[2] C. Mayer, “Converting Python Bytes to MAC Address – 5 Effective Methods,” Finxter, [Online].
    Available: https://blog.finxter.com/converting-python-bytes-to-mac-address-5-effective-methods/./
[3] Stack Overflow, “MAC address conversion into byte array in Python,” Stack Overflow, [Online].
    Available: https://stackoverflow.com/questions/12538199/mac-address-conversion-into-byte-array-in-python.
[4] GeeksforGeeks, “to_bytes() in Python,” GeeksforGeeks, [Online].
    Available: https://www.geeksforgeeks.org/python/to-bytes-in-python/.
[5] Python Software Foundation, “ipaddress — IPv4/IPv6 manipulation library,” Python Documentation, [Online].
    Available: https://docs.python.org/3/library/ipaddress.html.
[6] GeeksforGeeks, “Convert Hex String to Bytes in Python,” GeeksforGeeks, [Online].
    Available: https://www.geeksforgeeks.org/python/convert-hex-string-to-bytes-in-python/.
"""
# -----------------------------------------------------------------------------
class Interface:
    """Instantiates the each of the 4 NICs for the appliance."""
    def __init__(self, name: str, mac: str, ip: str, mask: str):
        self.mac = mac
        self.ip = ip
        self.mask = mask
        self.default = ip
        self.interface_name = name
    
    def get_mac(self) -> str:
        """
        Returns the MAC address as a string of 6 lowercase hexadecimal pairs separated
        by colons "xx:xx:xx:xx:xx:xx".
        """
        return self.mac

    def set_mac(self, mac_address: str) -> None:
        """
        Sets the MAC address to the given mac_address string.
        Returns the MAC address as a string of 6 lowercase hexadecimap pairs separated
        by colons "xx:xx:xx:xx:xx:xx".
        """
        self.mac = mac_address

    def get_ip(self) -> str:
        """
        Returns the IP address as a string of the IPv4 dotted quad.
        """
        return self.ip

    def set_ip(self, ip_address: str) -> None:
        """
        Sets the IP address to the given ip_address string.
        Returns the IP address as a string of the IPv4 dotted quad.
        """
        self.ip = ip_address

    def get_mask(self) -> str:
        """
        Returns the netmask as a string of the IPv4 dotted quad.
        """
        return self.mask

    def set_mask(self, netmask: str) -> None:
        """
        Sets the netmask to the given netmask string.
        """
        self.mask = netmask

    def get_default(self) -> str:
        """
        Returns the default route IP address as a string of the IPv4 dotted quad.
        """
        return self.default

    def set_default(self, ip_address: str) -> None:
        """
        Sets the default route IP address as a string of the IPv4 dotted quad.
        """
        self.default = ip_address

    def send_packet(self, packet: bytes) -> None:
        """
        Simulates sending a packet (supplied as raw bytes) out that interface,
        by printing a message in the format: "mgt|int|dmz|ext: sent packet" + packet as a string in hex.
        """
        print(f"{self.interface_name}: sent packet {packet.hex()}")


class InterfaceHandler:
    """Handles reading packets from a file and simulates sending or absorbing packets."""
    def __init__(self, cap_file: str):
        self.interface_names = ["mgt", "int", "dmz", "ext"]
        self.interfaces = {
            "mgt": Interface("mgt", "28:ee:52:85:f2:3a", "192.168.96.23", "255.255.240.0"),
            "int": Interface("int", "28:ee:52:e2:b7:30", "10.0.0.1", "255.255.0.0"),
            "dmz": Interface("dmz", "28:ee:52:4c:4d:70", "10.1.0.1", "255.255.255.0"),
            "ext": Interface("ext", "28:ee:52:9c:61:ab", "130.102.184.1", "255.255.255.0"),
        }
        self.current_interface = None
        self.packets = []
        self.packet_num = 0
        with open(cap_file, "r") as file:
            for line in file:
                self.packets.append(line.strip())
                self.packet_num += 1
        self.current_packet_idx = None

    def next_packet(self):
        """
        Read packets from "traffic.spcap" file.
        [6] Used bytes.fromhex() to convert hex string to bytes.
        """
        if self.current_packet_idx is None:
            self.current_packet_idx = 0
        else:
            self.current_packet_idx += 1
            if self.current_packet_idx == self.packet_num:
                return None
        return bytes.fromhex(self.packets[self.current_packet_idx])  # return as bytes

    def send_packet(self, interface: str, packet: bytes):
        """
        "Send out" packets via the appropriate interface's send packet method.
        """
        the_interface = self.interfaces[interface]
        the_interface.send_packet(packet)

    def mgt_packet(self, packet: bytes):
        """
        To be "actioned" by the simulated appliance itself, print a message
        "Actioned management packet" + packet.
        """
        print(f"Actioned management packet {packet.hex()}")

class PatTable:
    """Handles port-address-translation (PAT)"""
    def __init__(self):
        # key: (in_address, in_port)
        # value: out_port
        self.table = {}
        self.used_port = set()
        self.nic_to_port = {}  # {(from_nic, to_nic): out_port}

    def set_pat(self, in_address: str, in_port: int, out_port: int):
        """
        Adds the PAT translation to the table.
        """
        self.table[(in_address, in_port)] = out_port
        if out_port not in self.used_port:
            self.used_port.add(out_port)


    def get_unused_port(self):
        """
        Returns a random ephemeral port number (port 49152-65535) that is not already in the table.
        """
        while True:
            port = random.randint(49152, 65535)
            if port not in self.used_port:
                self.used_port.add(port)
                return port


    def get_pat_in(self, out_port: int):
        """
        Returns the IP:port as a string of the IPv4 dotted quad port:string.
        """
        for (in_address, in_port), port in self.table.items():
            if port == out_port:
                return f"{in_address}:{in_port}"
        return f"{""}:{0}"


    def get_pat_out(self, in_address: str, in_port: str):
        """
        Returns the external port number.
        """
        return self.table.get((in_address, in_port))


    def set_out_port_from_nic(self, src_nic: str, dst_nic: str, dst_ip: str, out_port: int):
        self.nic_to_port[(src_nic, dst_nic, dst_ip)] = out_port


    def get_out_port_from_nic(self, src_nic: str, dst_nic: str, src_ip: str):
        return self.nic_to_port[(src_nic, dst_nic, src_ip)]

class PacketEngine:
    """Handles processing the packet."""
    def __init__(self, interface_handler: InterfaceHandler):
        self.ih = interface_handler
        self.current_packet = {}
        self.ping_requests = {}
        self.nonping_requests = {}
        self.connections = Connections()
        self.SNAT = {}
        self.PAT = PatTable()
        self.route = RouteTable()
        self.new_packet = None

    def process_packet(self, packet: bytes):
        """
        Manages all the processing: performs security checks or routing the "packets" to the correct interfaces.
        """
        self.create_packet_class(packet)  # creates self.current_packet
        self.check_packet(packet)  # routing will be handled in here


    def check_packet(self, packet: bytes):
        """
        Performs security checks (possibly raising alerts).
        """
        interface = self.current_packet["interface_name"]
        protocol = self.current_packet["protocol_name"]
        self.new_packet = None
        
        if protocol == "ICMP":
            self.check_icmp_traffic(packet)  # route packet is already handled
            return
        
        src_ip = self.current_packet["src_ip"]
        dst_ip = self.current_packet["dst_ip"]
        src_port = self.current_packet["src_port"]
        des_port = self.current_packet["des_port"]
        route_to = self.route.resolve(dst_ip)  # not fixed

        if protocol == "TCP" and interface == "mgt" and des_port == 22 and src_ip == '192.168.96.9':
            self.ih.mgt_packet(packet)  # alert and send packet in here
            return
        elif interface in ["int", "ext"] and des_port in [80, 443, 22]:
            if interface == "int":
                if route_to == "ext":
                    self.http_dns_int_ext(packet)
                else:
                    route_to = "dmz"
            elif interface == "ext":
                if self.http_ssh_ext_dmz(packet):
                    route_to = "dmz"
        elif interface in ["ext", "dmz"] and src_port in [80, 443, 22]:
            if interface == "dmz":
                if self.http_ssh_dmz_ext(packet):
                    route_to = "ext"
                elif self.http_dmz_int(packet):
                    route_to = "int"
            else:
                self.http_dns_ext_int(packet)
                route_to = "int"
        elif interface in ["int", "dmz"] and des_port == 53:
            route_to = "ext"
            if interface == "int":
                self.http_dns_int_ext(packet)
            else:
                self.dns_dmz_ext(packet)
        elif interface == "ext" and src_port == 53:
            if self.http_dns_ext_int(packet):
                route_to = "int"
            elif self.dns_ext_dmz(packet):
                route_to = "dmz"
        else:
            print("ALERT drop: new incoming TCP not allowed by policy")
            return
        
        self.route_packet(route_to, self.new_packet) if self.new_packet else None


    def ext_icmp(self, packet: bytes):
        icmp_type = 0  # 8 -> 0, echo request -> echo reply
        self.new_packet = bytes([packet[0]]) + packet[7:13] + packet[1:7] + packet[13:16] + packet[20:24] + (
                packet[16:20] + bytes([icmp_type]) + packet[25:])
        self.route_packet(self.current_packet["interface_name"], self.new_packet)


    def http_dns_int_ext(self, packet: bytes):
        protocol = self.current_packet["ip_protocol"]
        src_ip = self.current_packet["src_ip"]
        src_port = self.current_packet["src_port"]
        des_port = self.current_packet["des_port"]
        dst_ip = self.current_packet["dst_ip"]
        dst_p = self.current_packet["des_port"]
        flags = self.current_packet.get("flags", {})
        syn = flags.get("syn", 0)
        ack = flags.get("ack", 0)

        first_byte = "10101011"  # default to "ext" 
        dummy_mac_dst = mac_address_to_bytes("98:76:54:32:10:ab")
        mac_src = self.ih.interfaces["ext"].get_mac()  # 28:ee:52:9c:61:ab
        out_port = self.PAT.get_unused_port()
        new_src_ip = self.ih.interfaces["ext"].get_ip()  # 130.102.184.1
        status_int = self.connections.state("int", protocol, src_ip, src_port, dst_ip, dst_p)
        if status_int is None and ((syn == 1 and ack == 0) or des_port == 53):
            # Store PAT
            self.PAT.set_pat(src_ip, src_port, out_port)
            print(f"NAT: allocate {src_ip}:{src_port} -> {new_src_ip}:{out_port}")
            # Store NIC
            self.PAT.set_out_port_from_nic("int", "ext", dst_ip, out_port)
            status_set = "established" if des_port == 53 else "new"
            self.connections.add_or_update("int", protocol, src_ip, src_port, dst_ip, dst_p, status_set)
        elif syn == 0 and ack == 1:
            if status_int == "syn__sent":
                self.connections.add_or_update("int", protocol, src_ip, src_port, dst_ip, dst_p, "established")
        self.new_packet = (
            bin_to_bytes(first_byte) +
            dummy_mac_dst +
            mac_address_to_bytes(mac_src) +  # new mac_src
            packet[13:16] +
            ip_to_bytes(new_src_ip) +  
            packet[20:24] +           # keep dst_ip
            int_to_bytes(out_port) +  # convert new src_port
            packet[26:]
        )


    def http_int_dmz(self, packet: bytes):  # no PAT
        protocol = self.current_packet["ip_protocol"]
        src_ip = self.current_packet["src_ip"]
        src_port = self.current_packet["src_port"]
        dst_ip = self.current_packet["dst_ip"]
        dst_p = self.current_packet["des_port"]
        flags = self.current_packet.get("flags", {})
        syn = flags.get("syn", 0)
        ack = flags.get("ack", 0)

        first_byte = "10101010"  # to "dmz"
        dummy_mac_dst = mac_address_to_bytes("98:76:54:32:10:ab")
        mac_src = self.ih.interfaces["dmz"].get_mac()
        status = self.connections.state("int", protocol, src_ip, src_port, dst_ip, dst_p)
        if status is None and syn == 1 and ack == 0:
            self.connections.add_or_update("int", protocol, src_ip, src_port, dst_ip, dst_p, "new")
        elif syn == 0 and ack == 1:
            if status == "syn__sent":
                self.connections.add_or_update("int", protocol, src_ip, src_port, dst_ip, dst_p, "established")
        self.new_packet = (
            bin_to_bytes(first_byte) +
            dummy_mac_dst +
            mac_address_to_bytes(mac_src) +  # new mac_src
            packet[13:]                      # keep the rest
        )


    def http_dmz_int(self, packet: bytes):
        protocol = self.current_packet["ip_protocol"]
        src_ip = self.current_packet["src_ip"]
        src_port = self.current_packet["src_port"]
        dst_ip = self.current_packet["dst_ip"]
        dst_p = self.current_packet["des_port"]
        flags = self.current_packet.get("flags", {})
        syn = flags.get("syn", 0)
        ack = flags.get("ack", 0)

        first_byte = "10101001"  # to int
        dummy_mac_dst = mac_address_to_bytes("ab:12:cd:34:ef:56")
        mac_src = self.ih.interfaces["int"].get_mac()  # 28:ee:52:9c:61:ab

        responding = True if syn == 1 and ack == 1 else False
        status = self.connections.state("int", protocol, dst_ip, dst_p, src_ip, src_port)
        if (status == "new" and responding) or (  # SYN-ACK, reply to int
            (status == "established" and ack == 1 and syn == 0)):     # established connection
            if responding:
                self.connections.add_or_update("int", protocol, dst_ip, dst_p, src_ip, src_port, "syn__sent")
            self.new_packet = (
                bin_to_bytes(first_byte) +  # bin -> int -> bytes
                dummy_mac_dst +
                mac_address_to_bytes(mac_src) +
                packet[13:]
            )
            return True
        return False

    def route_packet(self, interface: str, packet: bytes):
        """
        Simulates sending a packet to that interface for sending.
        """
        print(f"ROUTE to {interface}")
        self.ih.send_packet(interface, packet)


    def http_ssh_ext_dmz(self, packet: bytes):
        protocol = self.current_packet["ip_protocol"]
        src_ip = self.current_packet["src_ip"]
        src_port = self.current_packet["src_port"]
        dst_ip = self.current_packet["dst_ip"]
        dst_p = self.current_packet["des_port"]
        flags = self.current_packet.get("flags", {})
        syn = flags.get("syn", 0)
        ack = flags.get("ack", 0)

        first_byte = "10101010"  # to dmz
        dummy_mac_dst = mac_address_to_bytes("56:12:78:34:90:cd")
        mac_src = self.ih.interfaces["dmz"].get_mac()  # 28:ee:52:4c:4d:70
        webserver_ip = "10.1.0.54" if dst_p != 22 else "10.1.0.92"
        # Create a new packet
        self.new_packet = (
            bin_to_bytes(first_byte) +  # bin -> int -> bytes
            dummy_mac_dst +
            mac_address_to_bytes(mac_src) +
            packet[13:20] +  # include ip_protocol & src_ip
            ip_to_bytes(webserver_ip) +
            packet[24:]
        )
        dmz = True
        # Add a connection
        status = self.connections.state("ext", protocol, src_ip, src_port, webserver_ip, dst_p)  # status with dmz
        if status is None and syn == 1 and ack == 0:  # SYN, start with dmz
            # Store SNAT
            self.store_snat(webserver_ip, dst_ip)
            self.connections.add_or_update("ext", protocol, src_ip, src_port, webserver_ip, dst_p, "new")

        elif syn == 0 and ack == 1:  # ACK, end with dmz
            if status == "syn__sent":
                self.connections.add_or_update("ext", protocol, src_ip, src_port, webserver_ip, dst_p, "established")
        else:
            self.new_packet = None
            dmz = False
        return dmz


    def http_dns_ext_int(self, packet: bytes):
        protocol = self.current_packet["ip_protocol"]
        src_ip = self.current_packet["src_ip"]
        src_port = self.current_packet["src_port"]
        flags = self.current_packet.get("flags", {})
        syn = flags.get("syn", 0)
        ack = flags.get("ack", 0)

        first_byte = "10101001"  # to int
        dummy_mac_dst = mac_address_to_bytes("ab:12:cd:34:ef:56")
        mac_src = self.ih.interfaces["int"].get_mac()  # 28:ee:52:9c:61:ab
        out_port = self.PAT.get_out_port_from_nic("int", "ext", src_ip)
        in_address, in_port = self.PAT.get_pat_in(out_port).split(":") # for int -> ext
        in_port = int(in_port) # for int -> ext
        # Add a connection
        status = self.connections.state("int", protocol, in_address, in_port, src_ip, src_port)

        if (status == "new" and syn == 1 and ack == 1) or (  # SYN-ACK, reply to int
            (status == "established" and ack == 1 and syn == 0)) or (     # established connection
            src_port == 53 and status == "established"
        ):  
            if status == "new":
                self.connections.add_or_update("int", protocol, in_address, in_port, src_ip, src_port, "syn__sent")
            self.new_packet = (
                bin_to_bytes(first_byte) +  # bin -> int -> bytes
                dummy_mac_dst +
                mac_address_to_bytes(mac_src) +
                packet[13:16] +
                ip_to_bytes(src_ip) +
                ip_to_bytes(in_address) +  # dst_ip
                packet[24:26] +
                int_to_bytes(in_port) +    # dst port
                packet[28:]
            )
            return True
        return False


    # Helper
    def create_packet_class(self, packet: bytes):
        self.current_packet = {}  # reset
        # Convert to bits first
        bits = bytes_to_bits(bytes([packet[0]]))
        if bits[:6] != "101010":
            print(f"ERROR: First 6 bits should be 101010! Not {bits[:6]}")
            return
        interface_num = bits[6:8]  # bits 6-8 of byte 0
        self.current_packet["interface_num"] = interface_num
        self.current_packet["interface_name"] = self.ih.interface_names[int(interface_num, 2)]
        self.current_packet["mac_dst"] = bytes_to_mac_address(packet[1:7])
        self.current_packet["mac_src"] = bytes_to_mac_address(packet[7:13])
        self.current_packet["ip_protocol"] = packet[15]
        self.current_packet["src_ip"] = str(ipaddress.ip_address(packet[16:20]))
        self.current_packet["dst_ip"] = str(ipaddress.ip_address(packet[20:24]))

        if self.current_packet["ip_protocol"] == 6:  # TCP Frame
            self.current_packet["protocol_name"] = "TCP"
            self.current_packet.update({
                "src_port": int.from_bytes(packet[24:26], "big"),      # next 2 bytes
                "des_port": int.from_bytes(packet[26:28], "big"),      # next 2 bytes
                "sequence_num": int.from_bytes(packet[28:32], "big"),  # next 4 bytes
                "ack_num": int.from_bytes(packet[32:36], "big"),       # next 4 bytes
            })

            flags_bits = bytes_to_bits(bytes([packet[36]]))
            self.current_packet["flags"] = {
                "cwr": int(flags_bits[0]), # Congestion Window Reduced
                "ece": int(flags_bits[1]), # ECN Congestion Experienced
                "urg": int(flags_bits[2]), # Urgent
                "ack": int(flags_bits[3]), # Acknowledgment
                "psh": int(flags_bits[4]), # Push
                "rst": int(flags_bits[5]), # Reset
                "syn": int(flags_bits[6]), # Synchronize
                "fin": int(flags_bits[7]), # Finish
            }
            self.current_packet["payload"] = packet[37:]

        elif self.current_packet["ip_protocol"] == 17:  # UDP
            self.current_packet["protocol_name"] = "UDP"
            self.current_packet.update({
                "src_port": int.from_bytes(packet[24:26], "big"),
                "des_port": int.from_bytes(packet[26:28], "big"),
                "payload": packet[28:],
            })

        elif self.current_packet["ip_protocol"] == 1:  # ICMP
            self.current_packet["protocol_name"] = "ICMP"
            self.current_packet.update({
                "icmp_type": int(packet[24]),
                "icmp_code": int(packet[25]),
                "header_content": packet[26:30],
                "payload": packet[30:],
            })

        # Set interface
        interface_name = self.ih.interface_names[int(interface_num, 2)]
        self.ih.current_interface = self.ih.interfaces[interface_name]


    def check_icmp_traffic(self, packet: bytes):
        icmp_type = self.current_packet["icmp_type"]
        icmp_code = self.current_packet["icmp_code"]
        src_ip = self.current_packet["src_ip"]
        payload_len = len(self.current_packet["payload"])

        # Check ICMP echo request
        if not (icmp_type == 8 and icmp_code == 0):
            print(f"ALERT drop: ICMP type {icmp_type}:{icmp_code} not allowed by policy")
            if self.ping_requests.get(src_ip, 0) > 0:  # check if there are ongoing ping requests count
                self.nonping_requests[src_ip] = self.nonping_requests.get(src_ip, 0) + 1  # +1 subsequent nonping
                if self.nonping_requests[src_ip] >= 5:  # reset both counter to 0
                    self.ping_requests[src_ip] = 0
                    self.nonping_requests[src_ip] = 0
            return

        # Check oversize ping (> 64 bytes)
        if payload_len > 64:
            print(f"ALERT drop: oversize ping from {src_ip} ({payload_len} bytes)")
            return

        # reset subsequent nonping as this is a ping request
        self.nonping_requests[src_ip] = 0
        self.ping_requests[src_ip] = self.ping_requests.get(src_ip, 0) + 1
        # print(f"Self ping request: {self.ping_requests}")
        if self.ping_requests[src_ip] > 5:  # check ping rate limit
            print(f"ALERT drop: ping rate limit from {src_ip}")
        else:
            self.ext_icmp(packet)


    def http_ssh_dmz_ext(self, packet: bytes):
        proto = self.current_packet["ip_protocol"]
        src_ip = self.current_packet["src_ip"]
        src_port = self.current_packet["src_port"]
        dst_ip = self.current_packet["dst_ip"]
        dst_p = self.current_packet["des_port"]
        webserver_ip = "10.1.0.54" if src_port != 22 else "10.1.0.92"
        syn, ack = self.current_packet["flags"]["syn"], self.current_packet["flags"]["ack"]
        responding = True if syn == 1 and ack == 1 else False
        status = self.connections.state("ext", proto, dst_ip, dst_p, webserver_ip, src_port)
        if (responding and status == "new") or (
            ack == 1 and syn == 0 and status == "established"
        ):
            if responding:
                self.connections.add_or_update("ext", proto, dst_ip, dst_p, webserver_ip, src_port, "syn__sent")

            # Perform routing here
            first_byte = "10101011"  # to ext
            dummy_mac_dst = mac_address_to_bytes("98:76:54:32:10:ab")
            mac_src = self.ih.interfaces["ext"].get_mac()  # 28:ee:52:9c:61:ab
            src_ip = self.apply_snat(src_ip)
            # Create a new packet
            self.new_packet = (
                bin_to_bytes(first_byte) +  # bin -> int -> bytes
                dummy_mac_dst +
                mac_address_to_bytes(mac_src) +
                packet[13:16] +
                ip_to_bytes(src_ip) +
                packet[20:]  # include dst_ip and so on
            )
            return True
        return False


    def dns_dmz_ext(self, packet: bytes):
        proto = self.current_packet["ip_protocol"]
        src_ip = self.current_packet["src_ip"]
        src_port = self.current_packet["src_port"]
        dst_ip = self.current_packet["dst_ip"]
        dst_p = self.current_packet["des_port"]
        status = self.connections.state("ext", proto, src_ip, src_port, dst_ip, dst_p)
        if status is None:
            self.connections.add_or_update("ext", proto, src_ip, src_port, dst_ip, dst_p, "established")

        # Perform routing here
        first_byte = "10101010"  # to ext
        dummy_mac_dst = mac_address_to_bytes("98:76:54:32:10:ab")
        mac_src = self.ih.interfaces["ext"].get_mac()  # 28:ee:52:9c:61:ab
        src_ip = self.apply_snat(src_ip)
        out_port = self.PAT.get_unused_port()
        new_src_ip = self.ih.interfaces["ext"].get_ip()  # 130.102.184.1
        # Store PAT
        self.PAT.set_pat(src_ip, src_port, out_port)
        print(f"NAT: allocate {src_ip}:{src_port} -> {new_src_ip}:{out_port}")
        # Store NIC
        self.PAT.set_out_port_from_nic("dmz", "ext", dst_ip, out_port)
        # Create a new packet
        self.new_packet = (
            bin_to_bytes(first_byte) +
            dummy_mac_dst +
            mac_address_to_bytes(mac_src) +
            packet[13:16] +
            ip_to_bytes(new_src_ip) +
            packet[20:24] +
            int_to_bytes(out_port) +  # convert new src_port
            packet[26:]
        )


    def dns_ext_dmz(self, packet: bytes):
        src_ip = self.current_packet["src_ip"]

        first_byte = "10101010"  # to dmz
        dummy_mac_dst = mac_address_to_bytes("56:12:78:34:90:cd")
        mac_src = self.ih.interfaces["dmz"].get_mac()  # 28:ee:52:4c:4d:70
        out_port = self.PAT.get_out_port_from_nic("dmz", "ext", src_ip)
        in_address, in_port = self.PAT.get_pat_in(out_port).split(":") # for int -> ext
        in_port = int(in_port) # for dmz -> ext
        # Create a new packet
        self.new_packet = (
            bin_to_bytes(first_byte) +  # bin -> int -> bytes
            dummy_mac_dst +
            mac_address_to_bytes(mac_src) +
            packet[13:16] +
            ip_to_bytes(src_ip) +
            ip_to_bytes(in_address) +  # dst_ip
            packet[24:26] +
            int_to_bytes(in_port) +    # dst port
            packet[28:]
        )


    def store_snat(self, ip_out: str, ip_in: str):
        self.SNAT[ip_out] = ip_in


    def apply_snat(self, ip_out: str):
        return self.SNAT[ip_out]


class RouteTable:
    """Handles the appliance's route table."""
    def __init__(self):
        self.interface_names = ["ext", "dmz", "int"]
        self.ips = ["130.102.184.1", "10.1.0.1", "10.0.0.1"]

    def resolve(self, ip: str):
        """
        Returns the egress interface name for the destination IP address - longest prefix match
        among local subnets, else 'ext' (default external).
        [5] Utilise ipaddress library to compare values.
        """
        for idx, ip_addr in enumerate(self.ips):
            if ipaddress.IPv4Address(ip) == ipaddress.IPv4Address(ip_addr) or (
                ipaddress.IPv4Address(ip) > ipaddress.IPv4Address(ip_addr)
            ):
                return self.interface_names[idx]
        return "ext"


class Connections:
    """Manages the appliance's current and half-open connections."""
    def __init__(self):
        # key = (interface, protocol, src_ip, src_port, dst_ip, dst_port)
        # value = state
        self.connections = {}

    def add_or_update(self, nic: str, proto: int, src_ip: str, src_port: int, dst_ip: str, dst_p: int, state: str):
        """
        For:
        - interface: mgt/int/dmz/ext
        - protocol
        - source address & port
        - destination address & port
        - connection state: new, syn__sent, established, closed
        """
        self.connections[(nic, proto, src_ip, src_port, dst_ip, dst_p)] = state

    def state(self, nic: str, proto: int, src_ip: str, src_port: int, dst_ip: str, dst_p: int):
        """
        Returns the connection state or null if no entry is found.
        """
        return self.connections.get((nic, proto, src_ip, src_port, dst_ip, dst_p))

# ------------------- Helper -------------------
def bytes_to_bits(packet: bytes):
    """
    Convert bytes to bits (binary string).
    [1] Used join() and format :08b to convert bytes to bits.
    """
    binary_str = ''.join(f"{byte:08b}" for byte in packet)
    return binary_str

def bytes_to_mac_address(packet: bytes):
    """
    Convert bytes to MAC address in format xx:xx:xx:xx:xx:xx.
    [2] Used join() and format :02x to convert bytes to mac address.
    """
    return ':'.join(f"{byte:02x}" for byte in packet)

def mac_address_to_bytes(address: str):
    """
    Convert MAC address (string) to bytes.
    [3] Used replace() and to_bytes() to convert MAC address to bytes.
    """
    return int(address.replace(":",""), 16).to_bytes(6)

def bin_to_bytes(bin: str):
    """
    [4] Used to_bytes() and int(str, 2) to convert binary string to int to bytes.
    """
    return int(bin, 2).to_bytes(1, byteorder='big')

def ip_to_bytes(address: str):
    """
    [5] Utilise library to convert IP address to bytes
    """
    return ipaddress.IPv4Address(address).packed

def int_to_bytes(port: int):
    """
    [4] Used to_bytes() to convert intefer to bytes
    """
    return port.to_bytes(2, byteorder='big')

# ------------------- Simulator runner -------------------
def run_appliance(cap_file: str) -> None:
    ih = InterfaceHandler(cap_file)
    pe = PacketEngine(ih)
    while True:
        raw = ih.next_packet()
        if raw is None:
            break
        pe.process_packet(raw)

# --------------- Main ---------------

def main():
    run_appliance("traffic.spcap")

if __name__ == "__main__":
    main()
