from enum import Enum


class ParseError(Exception):
    """
    This exception is raised when there is an issue while parsing a packet
    """
    pass


class Packet:
    PacketType = Enum('PacketType',
                      ['Ethernet_802_2', 'Ethernet_802_3', 'ARP', 'ICMP',
                       'CDP', 'IPv4', 'TCP', 'UDP', 'STP'])

    def __init__(self, type: PacketType):
        self.type = type

    def __str__(self):
        return ''


class Ethernet_802_2(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.Ethernet_802_2)
        byte_step = 2

        # parse header fields
        self.dst_mac = ':'.join([hex_data[i:i+byte_step] for i in range(0, 10 + byte_step, byte_step)])
        self.src_mac = ':'.join([hex_data[i:i+byte_step] for i in range(12, 22 + byte_step, byte_step)])
        self.ether_type = int(hex_data[24:28], 16)
        self.data = hex_data[28:-8]
        self.fcs = hex_data[-8:]

        # parse encapsulated packet
        if self.ether_type == 0x806:
            self.encap = ARP(self.data)
        elif self.ether_type == 0x800:
            self.encap = IPv4(self.data)
        elif self.ether_type == 0x8181:
            self.encap = STP(self.data)
        else:
            raise ParseError('Unrecognized EtherType 0x{:04x}!'.format(self.ether_type))

    def __str__(self):
        return ""


class Ethernet_802_3(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.Ethernet_802_3)
        byte_step = 2

        # parse header fields
        self.dst_mac = ':'.join([hex_data[i:i + byte_step] for i in range(0, 10 + byte_step, byte_step)])
        self.src_mac = ':'.join([hex_data[i:i + byte_step] for i in range(12, 22 + byte_step, byte_step)])
        self.length = int(hex_data[24:28], 16)
        self.dsap = int(hex_data[28:30], 16)
        self.ssap = int(hex_data[30:32], 16)

        iframe = 0b0
        supervisory_frame = 0b01
        unnumbered_frame = 0b11
        first_control = int(hex_data[32:34], 16)
        control_end = 0
        # find out the type of frame to get proper control field
        if first_control & 0b1 == iframe or first_control & 0b11 == supervisory_frame:
            control_end = 36
            self.control = int(hex_data[32:36], 16)
        elif first_control & 0b11 == unnumbered_frame:
            control_end = 34
            self.control = int(hex_data[32:34], 16)
        else:
            raise ParseError('Unknown control field 0x{:02x}'.format(first_control))

        # parse encapsulated packet
        if self.ssap == 0xaa:  # SNAP header extension
            header_end = control_end + 10
            self.org_code = ':'.join([hex_data[i:i + byte_step] for i in range(control_end, control_end + 6 + byte_step, byte_step)])
            self.pid = int(hex_data[control_end + 6:header_end], 16)
            self.data = hex_data[control_end + 10:-8]
            self.encap = CDP(self.data)
        elif self.ssap == 0x42:
            self.data = hex_data[control_end:-8]
            self.encap = STP(self.data)
        else:
            raise ParseError('Unknown source service access point (SSAP) 0x{:02x}'.format(self.ssap))

        self.fcs = hex_data[-8:]

class ARP(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.ARP)

    def __str__(self):
        return ""


class ICMP(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.ICMP)

    def __str__(self):
        return ""


class CDP(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.CDP)

    def __str__(self):
        return ""


class IPv4(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.IPv4)

    def __str__(self):
        return ""


class TCP(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.TCP)

    def __str__(self):
        return ""


class UDP(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.UDP)

    def __str__(self):
        return ""


class STP(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.STP)

    def __str__(self):
        return ""
