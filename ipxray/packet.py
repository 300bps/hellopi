# Package: ipxray
# Package handles simple internet protocol dissection and parsing.
#
# David Smith
# 4/15/21

import enum
from itertools import islice
import struct
from typing import Union, Optional



# ** Layer 5 Protocols (Application Layer)

class INETPacket:
    """
    Generic internet tcp/ip protocol dissector. Decodes each of the layers in the stack.
    """

    class ProtocolLayer(enum.Enum):
        ETHERNET = enum.auto()
        IP = enum.auto()


    def __init__(self, *,
                 enet_packet: Optional[Union[bytes, bytearray]] = None,
                 ip_packet: Optional[Union[bytes, bytearray]] = None):
        """
        Pass in EITHER an ethernet packet/frame OR an ip packet to create an object that attempts to
        dissect the packet into the various layers of the internet packet stack.
        :param enet_packet: Raw ethernet frame data
        :param ip_packet: Raw ip packet data
        """

        if not any([enet_packet, ip_packet]):
            raise ValueError("No packet parameter passed.")
        elif not any([isinstance(enet_packet, (bytes, bytearray)), isinstance(ip_packet, (bytes, bytearray))]):
            raise TypeError("Packet parameters must be of type 'bytes' or 'bytearray'.")

        # Handles to the various layers
        self.enet = None
        self.ip = None

        # One of the following layers will be populated (unless some other, less common layer 4 protocol is used)
        self.icmp = None
        self.udp = None
        self.tcp = None

        # Select parsing/decoding starting at the specified layer
        if enet_packet:
            # Use memoryview so data can be used in a zero-copy fashion
            self.raw_packet = memoryview(enet_packet)

            # Parse out the various components of the packet
            self._parse(self.raw_packet, self.ProtocolLayer.ETHERNET)

        elif ip_packet:
            # Use memoryview so data can be used in a zero-copy fashion
            self.raw_packet = memoryview(ip_packet)

            # Parse out the various components of the packet
            self._parse(self.raw_packet, self.ProtocolLayer.IP)


    def _parse(self, raw_packet: Union[bytes, bytearray, memoryview], base_layer: ProtocolLayer):
        """
        Attempt to parse the packet one layer at a time starting at the ethernet layer (layer 2) up through the
        tcp/udp/icmp (layer 4)
        :param raw_packet: Raw ethernet or ip packet as specified in base_layer
        :param base_layer: Enum ProtocolLayer specifying raw_packet lowest layer is ethernet (layer 2) or ip (layer 3)
        :return:
        """

        # Parse as much of the packet as possible as long as there are no exceptions
        try:
            # Specify if packet data lowest level is ethernet or ip. If not ETHERNET (layer 2), assume IP (layer 3)
            if base_layer == self.ProtocolLayer.ETHERNET:
                # OSI Layer 2 (ethernet)
                self.enet = ENETPacket(raw_packet)

                # OSI Layer 3 (internet protocol)
                self.ip = IPPacket(self.enet.payload)

            elif base_layer == self.ProtocolLayer.IP:
                # raw_packet base layer starts at the ip (layer 3) - doesn't contain ethernet (layer 2)
                # OSI Layer 3 (internet protocol)
                self.ip = IPPacket(raw_packet)

            else:
                raise ValueError("Invalid protocol layer specified")

            # OSI Layer 4 (TCP, UDP, or others)
            # (ICMP is technically layer 3 but is decoded here)
            if self.ip.protocol == "icmp":
                self.icmp = ICMPPacket(self.ip.payload)
            elif self.ip.protocol == "tcp":
                self.tcp = TCPPacket(self.ip.payload)
            elif self.ip.protocol == "udp":
                self.udp = UDPPacket(self.ip.payload)

        except Exception as ex:
            pass


    def __str__(self):
        """
        Return the string representation of the layers of the packet.
        :return:
        """
        # Layer 2
        val = f"{str(self.enet):s}\n" if self.enet else ""
        # Layer 3
        val += f"{str(self.ip):s}\n" if self.ip else ""
        # Layer 4
        if self.icmp:
            val += f"{self.icmp}"
        elif self.tcp:
            val += f"{self.tcp}"
        elif self.udp:
            val += f"{self.udp}"

        return val



class DHCPPacket:
    """
    DHCP packet decoder.
    """

    CLIENT_HW_ADDRESS_OFFSET = 28
    OPTIONS_OFFSET = 240


    class Options(enum.IntEnum):
        """
        Option number assignments
        """
        DHCP_MESSAGETYPE = 53
        SERVER_ID = 54
        REQUEST_IPADDRESS = 50
        HOSTNAME = 12


    class OptionMessageType(enum.IntEnum):
        """
        Messagetype option fields
        """
        DHCPDiscover = 1
        DHCPOffer = 2
        DHCPRequest = 3
        DHCPDecline = 4
        DHCPAck = 5
        DHCPNak = 6
        DHCPRelease = 7
        DHCPInform = 8


    def __init__(self, udp_payload: Union[bytes, bytearray]):
        """
        Pass in a udp packet payload containing a DHCP message to create an object to
        decode the dhcp packet.
        :param udp_payload: udp packet payload containing dhcp message to decode.
        """

        self.is_dhcp = False
        self.client_hw_address = None
        self.options = []
        self.message_type = None
        self.hostname = None
        self.requested_ip = None
        self.dhcpserver_ip = None

        self._parse(udp_payload)


    def _parse(self, udp_payload):
        """
        Attempt to parse the udp_payload containing a dhcp message (layer 5).
        :param udp_payload: udp packet payload containing the dhcp message to decode.
        :return:
        """

        try:
            # Parse the mac address of the client
            self.client_hw_address = struct.unpack_from("!6s", udp_payload, self.CLIENT_HW_ADDRESS_OFFSET)[0]

            # Create iterator at the beginning of options field
            option_iter = islice(udp_payload, self.OPTIONS_OFFSET, None)

            # Attempt to parse options fields
            while True:
                # DHCP option code
                o_code = next(option_iter)

                # Code of 0 signals empty option (padding)
                if o_code == 0:
                    continue
                # Code of 255 signals end of options section
                elif o_code == 255:
                    raise StopIteration()

                # Parse the option
                o_len = next(option_iter)
                o_data = [next(option_iter) for i in range(o_len)]
                option = (o_code, o_len, bytes(o_data))

                # Add to list of decoded options
                self.options.append(option)

                # Look for specific option codes
                try:
                    if o_code == self.Options.DHCP_MESSAGETYPE:
                        # Indicate that this is truly a DHCP packet
                        self.is_dhcp = True

                        # Attempt to convert message type num to enum
                        self.message_type = self.OptionMessageType(o_data[0])

                    elif o_code == self.Options.REQUEST_IPADDRESS:
                        self.requested_ip = bytes(o_data)

                    elif o_code == self.Options.SERVER_ID:
                        self.dhcpserver_ip = bytes(o_data)

                    elif o_code == self.Options.HOSTNAME:
                        # Convert source hostname to string
                        self.hostname = bytes(o_data).decode(encoding="utf-8")

                except (TypeError, ValueError):
                    pass

        except StopIteration:
            pass
        except Exception:
            pass


    def __str__(self):
        mtype = self.message_type.name if self.message_type else "dhcp"
        if self.is_dhcp:
            return f"<{mtype}: option codes={[o[0] for o in self.options]}>"
        else:
            return f"<Not DHCP>"



# ** Layer 4 Protocols (Transport Layer)

class TCPPacket:
    """
    TCP packet decoder.
    """

    def __init__(self, tcp_packet: Union[bytes, bytearray]):
        """
        Pass in a tcp packet to decode it.
        :param tcp_packet: tcp packet to decode.
        """

        self.src_port = None
        self.dst_port = None
        self.seq_num = None
        self.ack_num = None
        self.payload = None

        self._parse(tcp_packet)


    def _parse(self, tcp_packet: Union[bytes, bytearray]):
        """
        Attempt to parse the tcp packet (layer 4).
        :param tcp_packet: tcp packet to decode.
        :return:
        """

        self.src_port, self.dst_port, self.seq_num, self.ack_num = struct.unpack_from("!H H L L", tcp_packet, 0)

        # Read data offset field and convert from num longs to num bytes
        data_offset = 4 * (struct.unpack_from("!B", tcp_packet, 12)[0] >> 4)

        self.payload = memoryview(tcp_packet)[data_offset:]


    def __str__(self):
        return (f"<tcp layer: src port={self.src_port}\t"
               f"dst port={self.dst_port}>")



class UDPPacket:
    """
    UDP packet decoder.
    """

    def __init__(self, udp_packet: Union[bytes, bytearray]):
        """
        Pass in a udp packet to decode it.
        :param udp_packet: udp packet to decode.
        """

        self.src_port = None
        self.dst_port = None
        self.length = None
        self.checksum = None
        self.payload = None

        self._parse(udp_packet)


    def _parse(self, udp_packet: Union[bytes, bytearray]):
        """
        Attempt to parse the udp packet (layer 4).
        :param udp_packet: udp packet to decode.
        :return:
        """

        self.src_port, self.dst_port = struct.unpack_from("!H H", udp_packet, 0)
        self.length, self.checksum = struct.unpack_from("!H H", udp_packet, 4)

        self.payload = memoryview(udp_packet)[8:]


    def __str__(self):
        return (f"<udp layer: src port={self.src_port}\t"
               f"dst port={self.dst_port}\tlength={self.length}>")



# ** Layer 3 Protocols (Internet Layer)

class IPPacket:
    """
    IP packet decoder.
    """

    # Convert protocol field values to protocol names
    PROTOCOL_ASSIGNMENTS = {1: "icmp", 6: "tcp", 17: "udp"}


    def __init__(self, ip_packet: Union[bytes, bytearray]):
        """
        Pass in an ip packet to decode it.
        :param ip_packet: ip packet to decode.
        """
        self.src_ip = None
        self.dst_ip = None
        self.protocol = None
        self.payload = None

        self._parse(ip_packet)


    @staticmethod
    def format_ip_addr(ip_addr: Union[bytes, bytearray]) -> str:
        return ".".join((f"{b:d}" for b in ip_addr))


    def _parse(self, ip_packet: Union[bytes, bytearray]):
        """
        Attempt to parse the ip packet (layer 3).
        :param ip_packet: ip packet to decode.
        :return:
        """

        # Decode IHL to get start of data location in packet
        ip_header_length = struct.unpack_from("!B", ip_packet, 0)[0]
        ip_header_length = (ip_header_length & 0x0F) * 4

        # Total packet length including header
        packet_length = struct.unpack_from("!H", ip_packet, 2)

        # Identify the next-higher layer protocol
        protocol = struct.unpack_from("!B", ip_packet, 9)[0]
        self.protocol = self.PROTOCOL_ASSIGNMENTS.get(protocol, None)

        # Ip addresses
        header = struct.unpack_from("!4s 4s", ip_packet, 12)
        self.src_ip = header[0]
        self.dst_ip = header[1]

        self.payload = memoryview(ip_packet)[ip_header_length:]


    def __str__(self):
        return (f"<ip layer: src ip={self.format_ip_addr(self.src_ip):s}\t"
               f"dst ip={self.format_ip_addr(self.dst_ip):s}\tprotocol={self.protocol}>")



class ICMPPacket:
    """
    ICMP packet decoder.
    """

    # Convert ICMP type code to description
    ICMP_TYPE = {0: "ping reply", 3: "dest unreachable", 4: "source quench", 5: "redirect", 8: "ping"}


    def __init__(self, ip_packet: Union[bytes, bytearray]):
        """
        Pass in an ip packet containing an icmp message to have it decoded.
        :param ip_packet: ip packet containing icmp message to decode.
        """
        self.icmp_type = None

        self._parse(ip_packet)


    def _parse(self, ip_packet: Union[bytes, bytearray]):
        """
        Attempt to parse the icmp packet (layer 3).
        :param ip_packet: ip packet containing dhcp message to decode.
        :return:
        """

        # Decode ICMP type
        self.icmp_type = struct.unpack_from("!B", ip_packet, 0)[0]
        self.icmp_type = self.ICMP_TYPE.get(self.icmp_type, self.icmp_type)


    def __str__(self):
        return f"<icmp layer: type={self.icmp_type}>"



# ** Layer 2 Protocols (Link Layer)

class ENETPacket:
    """
    ETHERNET packet decoder.
    """

    # Location of payload data in the packet
    PAYLOAD_OFFSET = 14
    CRC_CHECKSUM_LEN = 4


    def __init__(self, enet_frame: Union[bytes, bytearray]):
        """
        Pass in an ethernet frame to decode it.
        :param enet_frame: ethernet frame to decode.
        """
        self.src_mac = None
        self.dst_mac = None
        self.ether_type = None
        self.crc_checksum = None
        self.payload = None

        self._parse(enet_frame)


    @staticmethod
    def format_mac_addr(mac_addr: Union[bytes, bytearray]) -> str:
        return ":".join((f"{b:02x}" for b in mac_addr))


    def _parse(self, enet_frame: Union[bytes, bytearray]):
        """
        Attempt to parse the ethernet packet (frame) (layer 2).
        :param enet_frame: ethernet packet (frame) to decode.
        :return:
        """

        # Decode ethernet header (dest mac, source mac, ether type)
        header = struct.unpack_from("!6s 6s h", enet_frame, 0)

        self.dst_mac = header[0]
        self.src_mac = header[1]
        self.ether_type = header[2]

        # Last 4-bytes are crc-checksum
        self.crc_checksum =  struct.unpack("!I", enet_frame[-4:])[0]

        self.payload = memoryview(enet_frame)[self.PAYLOAD_OFFSET:-self.CRC_CHECKSUM_LEN]


    def __str__(self):
        return (f"<ethernet layer: src mac={self.format_mac_addr(self.src_mac):s}\t"
                f"dst mac={self.format_mac_addr(self.dst_mac):s}>")
