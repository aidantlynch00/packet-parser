from enum import Enum


class ParseError(Exception):
    """
    This exception is raised when there is an issue while parsing a packet
    """
    pass


class Packet:
    """
    Base class for packets
    """
    PacketType = Enum('PacketType',
                      ['Ethernet_802_2', 'Ethernet_802_3', 'ARP', 'ICMP',
                       'CDP', 'IPv4', 'TCP', 'UDP', 'STP'])

    def __init__(self, type: PacketType, length: int):
        self.type = type
        self.length = length

    def __str__(self):
        return ''


class Ethernet_802_2(Packet):
    """
    Class representing an Ethernet II frame
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.Ethernet_802_2, len(hex_data) / 2)
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
        str_rep += '    Data: 0x{}\n'.format(self.data)
        return str_rep


class Ethernet_802_3(Packet):
    """
    Class representing an IEEE 802.3 Ethernet frame
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.Ethernet_802_3, len(hex_data) / 2)
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
        str_rep += '    Data: 0x{}\n'.format(self.data)
        return str_rep


class ARP(Packet):
    """
    Class representing an ARP packet
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.ARP, len(hex_data) / 2)
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
    """
    Class representing an ICMP packet
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.ICMP, len(hex_data) / 2)

        self.message_type = int(hex_data[0:2], 16)
        self.code = int(hex_data[2:4], 16)
        self.checksum = hex_data[4:8]
        self.extra_fields = hex_data[8:16]
        self.data = hex_data[16:]

    def __str__(self):
        str_rep = 'ICMP Packet:\n'
        str_rep += '    Type: {}\n'.format(self.message_type)
        str_rep += '    Code: {}\n'.format(self.code)
        str_rep += '    Checksum: 0x{}\n'.format(self.checksum)
        str_rep += '    Extra Fields: 0x{}\n'.format(self.extra_fields)
        str_rep += '    Data: 0x{}\n'.format(self.data)
        return str_rep


class CDP(Packet):
    """
    Class representing a CDP packet
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.CDP, len(hex_data) / 2)
        byte_step = 2

        self.version = int(hex_data[0:2], 16)
        self.ttl = int(hex_data[2:4], 16)
        self.checksum = hex_data[4:8]
        self.tlvs = []
        i = 8
        while i < len(hex_data):
            type_field = hex_data[i:i + 4]
            length = int(hex_data[i + 4:i + 8], 16)
            value = hex_data[i + 8:i + 8 + (length - 4) * 2]
            self.tlvs.append((type_field, length, value))
            i = i + 8 + (length - 4) * 2

    def __str__(self):
        str_rep = 'CDP Packet:\n'
        str_rep += '    Version: {}\n'.format(self.version)
        str_rep += '    Time-to-Live: {} seconds\n'.format(self.ttl)
        str_rep += '    Checksum: 0x{}\n'.format(self.checksum)
        str_rep += '    List of Type-Length-Value tuples:\n'
        for (type_field, length, value) in self.tlvs:
            str_rep += '        Type: 0x{}\n'.format(type_field)
            str_rep += '        Length: {}\n'.format(length)
            str_rep += '        Value: 0x{}\n\n'.format(value)
        return str_rep


class IPv4(Packet):
    """
    Class representing an IPv4 packet
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.IPv4, len(hex_data) / 2)
        byte_step = 2

        self.version = int(hex_data[0], 16)
        self.header_length = int(hex_data[1], 16) * 4
        self.diff_services = hex_data[2:4]
        self.total_length = int(hex_data[4:8], 16)
        self.id = hex_data[8:12]
        self.flags = hex_data[12:14]
        self.ttl = int(hex_data[16:18], 16)
        self.protocol = int(hex_data[18:20], 16)
        self.header_checksum = hex_data[20:24]
        self.src_addr = '.'.join([str(int(hex_data[i:i + byte_step], 16)) for i in range(24, 32, byte_step)])
        self.dst_addr = '.'.join([str(int(hex_data[i:i + byte_step], 16)) for i in range(32, 40, byte_step)])
        self.options = hex_data[40:self.header_length * 2]
        self.data = hex_data[self.header_length * 2:]

        if self.protocol == 1:
            self.encap = ICMP(self.data)
        elif self.protocol == 6:
            self.encap = TCP(self.data)
        elif self.protocol == 17:
            self.encap = UDP(self.data)

    def __str__(self):
        str_rep = 'IPv4 Packet:\n'
        str_rep += '    Version: {}\n'.format(self.version)
        str_rep += '    Header Length: {} bytes\n'.format(self.header_length)
        str_rep += '    Differentiated Services Field: 0x{}\n'.format(self.diff_services)
        str_rep += '    Total Length: {}\n'.format(self.total_length)
        str_rep += '    Identification: 0x{}\n'.format(self.id)
        str_rep += '    Flags: 0x{}\n'.format(self.flags)
        str_rep += '    Time to Live: {}\n'.format(self.ttl)
        str_rep += '    Protocol: {}\n'.format(self.protocol)
        str_rep += '    Header Checksum: 0x{}\n'.format(self.header_checksum)
        str_rep += '    Source Address: {}\n'.format(self.src_addr)
        str_rep += '    Destination Address: {}\n'.format(self.dst_addr)
        if len(self.options) > 0:
            str_rep += '    Options: 0x{}\n'.format(self.options)
        str_rep += '    Data: 0x{}\n'.format(self.data)
        return str_rep


class TCP(Packet):
    """
    Class representing a TCP packet
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.TCP, len(hex_data) / 2)

        self.src_port = int(hex_data[0:4], 16)
        self.dst_port = int(hex_data[4:8], 16)
        self.seq_num = int(hex_data[8:16], 16)
        self.ack_num = int(hex_data[16:24], 16)
        self.data_offset = int(hex_data[24], 16)
        self.flags = hex_data[25:28]
        self.window_size = int(hex_data[28:32], 16)
        self.checksum = hex_data[32:36]
        self.urgent_ptr = int(hex_data[36:40], 16)
        self.options = hex_data[40:40 + self.data_offset * 8]
        self.data = hex_data[40 + self.data_offset * 8:]

    def __str__(self):
        str_rep = 'TCP Packet:\n'
        str_rep += '    Source Port: {}\n'.format(self.src_port)
        str_rep += '    Destination Port: {}\n'.format(self.dst_port)
        str_rep += '    Sequence Number: {}\n'.format(self.seq_num)
        str_rep += '    Acknowledgement Number: {}\n'.format(self.ack_num)
        str_rep += '    Data Offset: {}\n'.format(self.data_offset)
        str_rep += '    Flags: 0x{}\n'.format(self.flags)
        str_rep += '    Window Size: {}\n'.format(self.window_size)
        str_rep += '    Checksum: 0x{}\n'.format(self.checksum)
        str_rep += '    Urgent Pointer: {}\n'.format(self.urgent_ptr)
        if len(self.options) > 0:
            str_rep += '    Options: 0x{}\n'.format(self.options)
        if len(self.data) > 0:
            str_rep += '    Data: 0x{}\n'.format(self.data)
        return str_rep


class UDP(Packet):
    """
    Class representing a UDP packet
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.UDP, len(hex_data) / 2)

        self.src_port = int(hex_data[0:4], 16)
        self.dst_port = int(hex_data[4:8], 16)
        self.length = int(hex_data[8:12], 16)
        self.checksum = hex_data[12:16]
        self.data = hex_data[16:]

    def __str__(self):
        str_rep = 'UDP Packet:\n'
        str_rep += '    Source Port: {}\n'.format(self.src_port)
        str_rep += '    Destination Port: {}\n'.format(self.dst_port)
        str_rep += '    Length: {}\n'.format(self.length)
        str_rep += '    Checksum: 0x{}\n'.format(self.checksum)
        str_rep += '    Data: 0x{}\n'.format(self.data)
        return str_rep


class STP(Packet):
    """
    Class representing an STP packet
    """
    def __init__(self, hex_data: str):
        super().__init__(Packet.PacketType.STP, len(hex_data) / 2)
        byte_step = 2

        self.protocol_id = hex_data[0:4]
        self.protocol_version_id = int(hex_data[4:6], 16)
        self.bpdu_type = hex_data[6:8]
        self.flags = hex_data[8:10]
        root_ext = int(hex_data[12:14], 16)
        root_priority = int(hex_data[10:14], 16) - root_ext
        self.root_id = ' / '.join([str(root_priority), str(root_ext), ':'.join([hex_data[i:i + byte_step] for i in range(14, 26, byte_step)])])
        self.root_path_cost = int(hex_data[26:34], 16)
        bridge_ext = int(hex_data[36:38], 16)
        bridge_priority = int(hex_data[34:38], 16) - bridge_ext
        self.bridge_id = ' / '.join([str(bridge_priority), str(bridge_ext), ':'.join([hex_data[i:i + byte_step] for i in range(38, 50, byte_step)])])
        self.port_id = hex_data[50:54]
        self.message_age = int(hex_data[54:58], 16) / 256
        self.max_age = int(hex_data[58:62], 16) / 256
        self.hello_time = int(hex_data[62:66], 16) / 256
        self.forward_delay = int(hex_data[66:70], 16) / 256

    def __str__(self):
        str_rep = 'STP Packet:\n'
        str_rep += '    Protocol Identifier: 0x{}\n'.format(self.protocol_id)
        str_rep += '    Protocol Version Identifier: {}\n'.format(self.protocol_version_id)
        str_rep += '    BPDU Type: 0x{}\n'.format(self.bpdu_type)
        str_rep += '    BPDU flags: 0x{}\n'.format(self.flags)
        str_rep += '    Root Identifier: {}\n'.format(self.root_id)
        str_rep += '    Root Path Cost: {}\n'.format(self.root_path_cost)
        str_rep += '    Bridge Identifier: {}\n'.format(self.bridge_id)
        str_rep += '    Port Identifier: 0x{}\n'.format(self.port_id)
        str_rep += '    Message Age: {:.0f}\n'.format(self.message_age)
        str_rep += '    Max Age: {:.0f}\n'.format(self.max_age)
        str_rep += '    Hello Time: {:.0f}\n'.format(self.hello_time)
        str_rep += '    Forward Delay: {:.0f}\n'.format(self.forward_delay)
        return str_rep
