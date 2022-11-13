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
        self.data = hex_data[28:]

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
        str_rep = 'Ethernet II Frame:\n'
        str_rep += '    Destination MAC Address: {}\n'.format(self.dst_mac)
        str_rep += '    Source MAC Address: {}\n'.format(self.src_mac)
        str_rep += '    EtherType: 0x{:04x}\n'.format(self.ether_type)
        str_rep += '    Data: {}\n'.format(self.data)
        return str_rep


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
            self.org_code = ':'.join([hex_data[i:i + byte_step] for i in range(control_end, control_end + 6, byte_step)])
            self.pid = int(hex_data[control_end + 6:header_end], 16)
            self.data = hex_data[control_end + 10:]
            self.encap = CDP(self.data)
        elif self.ssap == 0x42:
            self.data = hex_data[control_end:]
            self.encap = STP(self.data)
        else:
            raise ParseError('Unknown source service access point (SSAP) 0x{:02x}'.format(self.ssap))

    def __str__(self):
        str_rep = 'IEEE 802.3 Ethernet Frame:\n'
        str_rep += '    Destination MAC Address: {}\n'.format(self.dst_mac)
        str_rep += '    Source MAC Address: {}\n'.format(self.src_mac)
        str_rep += '    Length: {}\n'.format(self.length)
        str_rep += '    Destination Service Access Pointer (DSAP): 0x{:04x}\n'.format(self.dsap)
        str_rep += '    Source Service Access Pointer (SSAP): 0x{:04x}\n'.format(self.ssap)
        str_rep += '    Control: 0x{:02x}\n'.format(self.control)
        if self.ssap == 0xaa:
            str_rep += '    Organization Code: {}\n'.format(self.org_code)
            str_rep += '    PID: 0x{:04x}\n'.format(self.pid)
        str_rep += '    Data: {}\n'.format(self.data)
        return str_rep

class ARP(Packet):
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.ARP)
        byte_step = 2

        self.hw_type = int(hex_data[0:4], 16)
        self.protocol_type = int(hex_data[4:8], 16)
        self.hw_addr_length = int(hex_data[8:10], 16)
        self.protocol_addr_length = int(hex_data[10:12], 16)
        self.opcode = int(hex_data[12:16], 16)

        # parse sender addresses
        sender_hw_addr_end = 16 + self.hw_addr_length * 2
        self.sender_hw_addr = ':'.join([hex_data[i:i + byte_step] for i in range(16, sender_hw_addr_end, byte_step)])
        sender_protocol_addr_end = sender_hw_addr_end + self.protocol_addr_length * 2
        self.sender_protocol_addr = '.'.join([str(int(hex_data[i:i + byte_step], 16)) for i in range(sender_hw_addr_end, sender_protocol_addr_end, byte_step)])

        # parse target addresses
        target_hw_addr_end = sender_protocol_addr_end + self.hw_addr_length * 2
        self.target_hw_addr = ':'.join([hex_data[i:i + byte_step] for i in range(sender_protocol_addr_end, target_hw_addr_end, byte_step)])
        target_protocol_addr_end = target_hw_addr_end + self.protocol_addr_length * 2
        self.target_protocol_addr = '.'.join([str(int(hex_data[i:i + byte_step], 16)) for i in range(target_hw_addr_end, target_protocol_addr_end, byte_step)])

    def __str__(self):
        str_rep = 'ARP Packet:\n'
        str_rep += '    Hardware Type: {}\n'.format(self.hw_type)
        str_rep += '    Protocol Type: 0x{:04x}\n'.format(self.protocol_type)
        str_rep += '    Hardware Address Size: {}\n'.format(self.hw_addr_length)
        str_rep += '    Protocol Address Size: {}\n'.format(self.protocol_addr_length)
        str_rep += '    Opcode: {}\n'.format(self.opcode)
        str_rep += '    Sender Hardware Address: {}\n'.format(self.sender_hw_addr)
        str_rep += '    Sender Protocol Address: {}\n'.format(self.sender_protocol_addr)
        str_rep += '    Target Hardware Address: {}\n'.format(self.target_hw_addr)
        str_rep += '    Target Protocol Address: {}\n'.format(self.target_protocol_addr)
        return str_rep


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
