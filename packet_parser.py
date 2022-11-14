"""
Author: Aidan Lynch (atl4849)

Parses 802.2, 802.3, ARP, ICMP, CDP, IPv4, TCP, UDP, STP packets and displays statistics
such as the number of packets, protocol distribution, max/min/avg packet sizes, and conversations.
"""

import sys
from enum import Enum

import packet_types
from packet_types import *


def print_usage():
    print('usage: packet_parser.py dataset')
    print('\tdataset: path to text file containing packet data')


'''
Enum to keep track of the step in the dataset parsing process
'''
Step = Enum('Step', ['NO_PACKET', 'TIMESTAMP', 'DATA'])


def parse_dataset(lines: list[str]) -> (list[Packet], list[int]):
    """
    Parse timestamps and packets from the data in the lines of the dataset file.
    :param lines: lines in the dataset file
    :return: list of parsed packets and a list of associated timestamps
    """
    timestamps: list[int] = []
    packets: list[Packet] = []
    step = Step.NO_PACKET
    for line in lines:
        if step == Step.NO_PACKET:
            if line.startswith('+---------+---------------+----------+'):
                step = Step.TIMESTAMP
            else:
                continue
        elif step == Step.TIMESTAMP:
            [hour_str, min_str, sec_str] = line.split(':')
            timestamp = int(hour_str) * 60 * 60 * 1000000
            timestamp += int(min_str) * 60 * 1000000
            [mill_str, thou_str, num_str] = sec_str[:11].split(',')
            timestamp += int(mill_str) * 1000000
            timestamp += int(thou_str) * 1000
            timestamp += int(num_str)
            timestamps.append(timestamp)
            step = Step.DATA
        elif step == Step.DATA:
            data_str = ''.join(line.strip().split('|')[2:])  # remove preamble bytes
            length = int(data_str[24:28], 16)
            packet = Ethernet_802_3(data_str) if length < 1500 else Ethernet_802_2(data_str)
            packets.append(packet)
            step = Step.NO_PACKET

    return (packets, timestamps)


def main():
    """
    Workhorse of the program. Calls the parsing routine. Sorts through the
    resulting packets to collect statistics and then prints them.
    """

    # exit the program if we are not provided with a dataset path
    if len(sys.argv) != 2:
        print_usage()
        exit()

    path = sys.argv[1]

    try:
        with open(path, 'r') as file:  # open dataset file
            lines = file.readlines()
            (packets, timestamps) = parse_dataset(lines)

            # count the number of specific packets for stats
            last_timestamp = timestamps[0]
            packet_map: {Packet.PacketType: (Packet, int)} = {}
            ip_conversations: list[(str, str)] = []
            mac_conversations: list[(str, str)] = []
            port_conversations: list[(int, int)] = []
            total_packets = len(packets)
            eth2_stats = [0, 0, 0, 0]  # count, total length, min length, max length
            eth3_stats = [0, 0, 0, 0]
            arp_stats = [0, 0, 0, 0]
            eth2_stp_stats = [0, 0, 0, 0]
            ipv4_stats = [0, 0, 0, 0]
            icmp_stats = [0, 0, 0, 0]
            tcp_stats = [0, 0, 0, 0]
            udp_stats = [0, 0, 0, 0]
            cdp_stats = [0, 0, 0, 0]
            eth3_stp_stats = [0, 0, 0, 0]
            for i, packet in enumerate(packets):  # go through each packet
                if packet.type not in packet_map:  # add unseen packets to map
                    packet_map.update({packet.type: (packet, timestamps[i] - last_timestamp)})

                # add MAC conversation
                if not ((packet.dst_mac, packet.src_mac) in mac_conversations or (packet.src_mac, packet.dst_mac) in mac_conversations):
                    mac_conversations.append((packet.dst_mac, packet.src_mac))

                if packet.type == Packet.PacketType.Ethernet_802_2:  # stats for Ethernet II
                    eth2_stats[0] += 1
                    eth2_stats[1] += packet.length
                    if eth2_stats[3] == 0 or packet.length < eth2_stats[2]:
                        eth2_stats[2] = packet.length
                    if packet.length > eth2_stats[3]:
                        eth2_stats[3] = packet.length

                    if packet.encap is not None:  # get encapsulated packet
                        encap: Packet = packet.encap
                        if encap.type not in packet_map:
                            packet_map.update({encap.type: (encap, timestamps[i] - last_timestamp)})

                        if encap.type == Packet.PacketType.ARP:  # stats for ARP
                            arp_stats[0] += 1
                            arp_stats[1] += encap.length
                            if arp_stats[3] == 0 or encap.length < arp_stats[2]:
                                arp_stats[2] = encap.length
                            if packet.length > arp_stats[3]:
                                arp_stats[3] = encap.length
                        elif encap.type == Packet.PacketType.STP:  # stats for Ethernet II STP
                            eth2_stp_stats[0] += 1
                            eth2_stp_stats[1] += encap.length
                            if eth2_stp_stats[3] == 0 or encap.length < eth2_stp_stats[2]:
                                eth2_stp_stats[2] = encap.length
                            if packet.length > eth2_stp_stats[3]:
                                eth2_stp_stats[3] = encap.length
                        elif encap.type == Packet.PacketType.IPv4:  # stats for IPv4
                            # add IP conversation
                            if not ((encap.dst_addr, encap.src_addr) in ip_conversations or (encap.src_addr, encap.dst_addr) in ip_conversations):
                                ip_conversations.append((encap.dst_addr, encap.src_addr))

                            ipv4_stats[0] += 1
                            ipv4_stats[1] += encap.length
                            if ipv4_stats[3] == 0 or encap.length < ipv4_stats[2]:
                                ipv4_stats[2] = encap.length
                            if packet.length > ipv4_stats[3]:
                                ipv4_stats[3] = encap.length

                            if encap.encap is not None:  # get encapsulated packet in IPv4
                                protocol = encap.encap
                                if protocol.type not in packet_map:
                                    packet_map.update({protocol.type: (protocol, timestamps[i] - last_timestamp)})

                                # add port conversations
                                if protocol.type == Packet.PacketType.TCP or protocol.type == Packet.PacketType.UDP:
                                    if not ((protocol.dst_port, protocol.src_port) in port_conversations or (protocol.src_port, protocol.dst_port) in port_conversations):
                                        port_conversations.append((protocol.dst_port, protocol.src_port))

                                if protocol.type == Packet.PacketType.ICMP:  # stats for ICMP
                                    icmp_stats[0] += 1
                                    icmp_stats[1] += protocol.length
                                    if icmp_stats[3] == 0 or protocol.length < icmp_stats[2]:
                                        icmp_stats[2] = protocol.length
                                    if packet.length > icmp_stats[3]:
                                        icmp_stats[3] = protocol.length
                                elif protocol.type == Packet.PacketType.TCP:  # stats for TCP
                                    tcp_stats[0] += 1
                                    tcp_stats[1] += protocol.length
                                    if tcp_stats[3] == 0 or protocol.length < tcp_stats[2]:
                                        tcp_stats[2] = protocol.length
                                    if packet.length > tcp_stats[3]:
                                        tcp_stats[3] = protocol.length
                                elif protocol.type == Packet.PacketType.UDP:  # stats for UDP
                                    udp_stats[0] += 1
                                    udp_stats[1] += protocol.length
                                    if udp_stats[3] == 0 or protocol.length < udp_stats[2]:
                                        udp_stats[2] = protocol.length
                                    if packet.length > udp_stats[3]:
                                        udp_stats[3] = protocol.length

                if packet.type == Packet.PacketType.Ethernet_802_3:  # stats for Ethernet 802.3
                    eth3_stats[0] += 1
                    eth3_stats[1] += packet.length
                    if eth3_stats[3] == 0 or packet.length < eth3_stats[2]:
                        eth3_stats[2] = packet.length
                    if packet.length > eth3_stats[3]:
                        eth3_stats[3] = packet.length

                    if packet.encap is not None:  # get encapsulated packet
                        encap: Packet = packet.encap
                        if encap.type not in packet_map:  # add unseen packets to map
                            packet_map.update({encap.type: (encap, timestamps[i] - last_timestamp)})

                        if encap.type == Packet.PacketType.CDP:  # stats for CDP
                            cdp_stats[0] += 1
                            cdp_stats[1] += encap.length
                            if cdp_stats[3] == 0 or encap.length < cdp_stats[2]:
                                cdp_stats[2] = encap.length
                            if packet.length > cdp_stats[3]:
                                cdp_stats[3] = encap.length
                        elif encap.type == Packet.PacketType.STP:  # stats for STP
                            eth3_stp_stats[0] += 1
                            eth3_stp_stats[1] += encap.length
                            if eth3_stp_stats[3] == 0 or encap.length < eth3_stp_stats[2]:
                                eth3_stp_stats[2] = encap.length
                            if packet.length > eth3_stp_stats[3]:
                                eth3_stp_stats[3] = encap.length

                last_timestamp = timestamps[i]

            # print packet hierarchy
            print('Packet Hierarchy: {} total frames'.format(total_packets))
            if eth2_stats[0] > 0:
                percent_eth2 = (eth2_stats[0] / total_packets) * 100
                avg_eth2 = eth2_stats[1] / eth2_stats[0]
                print('Ethernet II ({:2.2f}%) - {} frames ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_eth2, eth2_stats[0], avg_eth2, eth2_stats[2], eth2_stats[3]))

                if arp_stats[0] > 0:
                    percent_arp = (arp_stats[0] / eth2_stats[0]) * 100
                    avg_arp = arp_stats[1] / arp_stats[0]
                    print('|\n|----ARP ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_arp, arp_stats[0], avg_arp, arp_stats[2], arp_stats[3]))
                if eth2_stp_stats[0] > 0:
                    percent_eth2_stp = (eth2_stp_stats[0] / eth2_stats[0]) * 100
                    avg_eth2_stp = eth2_stp_stats[1] / eth2_stp_stats[0]
                    print('|----STP ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_eth2_stp, eth2_stp_stats[0], avg_eth2_stp, eth2_stp_stats[2], eth2_stp_stats[3]))
                if ipv4_stats[0] > 0:
                    percent_ipv4 = (ipv4_stats[0] / eth2_stats[0]) * 100
                    avg_ipv4 = ipv4_stats[1] / ipv4_stats[0]
                    print('|----IPv4 ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_ipv4, ipv4_stats[0], avg_ipv4, ipv4_stats[2], ipv4_stats[3]))
                    if icmp_stats[0] > 0:
                        percent_icmp = (icmp_stats[0] / ipv4_stats[0]) * 100
                        avg_icmp = icmp_stats[1] / icmp_stats[0]
                        print('|    |\n|    |----ICMP ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_icmp, icmp_stats[0], avg_icmp, icmp_stats[2], icmp_stats[3]))
                    if tcp_stats[0] > 0:
                        percent_tcp = (tcp_stats[0] / ipv4_stats[0]) * 100
                        avg_tcp = tcp_stats[1] / tcp_stats[0]
                        print('|    |----TCP ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_tcp, tcp_stats[0], avg_tcp, tcp_stats[2], tcp_stats[3]))
                    if udp_stats[0] > 0:
                        percent_udp = (udp_stats[0] / ipv4_stats[0]) * 100
                        avg_udp = udp_stats[1] / udp_stats[0]
                        print('|    |----UDP ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)\n|    |\n|'.format(percent_udp, udp_stats[0], avg_udp, udp_stats[2], udp_stats[3]))
            if eth3_stats[0] > 0:
                percent_eth3 = (eth3_stats[0] / total_packets) * 100
                avg_eth3 = eth3_stats[1] / eth3_stats[0]
                print('Ethernet 802.3 ({:2.2f}%) - {} frames ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_eth3, eth3_stats[0], avg_eth3, eth3_stats[2], eth3_stats[3]))

                if cdp_stats[0] > 0:
                    percent_cdp = (cdp_stats[0] / eth3_stats[0]) * 100
                    avg_cdp = cdp_stats[1] / cdp_stats[0]
                    print('|\n|----CDP ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)'.format(percent_cdp, cdp_stats[0], avg_cdp, cdp_stats[2], cdp_stats[3]))
                if eth3_stp_stats[0] > 0:
                    percent_eth3_stp = (eth3_stp_stats[0] / eth3_stats[0]) * 100
                    avg_eth3_stp = eth3_stp_stats[1] / eth3_stp_stats[0]
                    print('|----STP ({:2.2f}%) - {} packets ({:.0f} avg length, {:.0f} min, {:.0f} max)\n|\n'.format(percent_eth3_stp, eth3_stp_stats[0], avg_eth3_stp, eth3_stp_stats[2], eth3_stp_stats[3]))

            # print field values for one of each packet type
            for (packet, delta_time) in packet_map.values():
                print('Time since last packet: {:.7f} seconds'.format(delta_time / (60 * 60 * 1000000)))
                print(packet)

            print('Conversations by MAC address:')
            for (mac1, mac2) in mac_conversations:
                print('{} <=> {}'.format(mac1, mac2))

            print('\nConversations by IP address:')
            for (ip1, ip2) in ip_conversations:
                print('{} <=> {}'.format(ip1, ip2))

            print('\nConversations by port number:')
            for (port1, port2) in port_conversations:
                print('{} <=> {}'.format(port1, port2))

    except IOError:  # handle error
        print('Could not open file {}!'.format(path))
        exit()


if __name__ == '__main__':
    main()
