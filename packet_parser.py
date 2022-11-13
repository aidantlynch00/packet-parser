"""
Author: Aidan Lynch (atl4849)

TODO: DESCRIPTION OF PROGRAM HERE
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


def parse_dataset(lines: list[str]) -> list[Packet]:
    packets: list[Packet] = []
    step = Step.NO_PACKET
    for line in lines:
        if step == Step.NO_PACKET:
            if line.startswith('+---------+---------------+----------+'):
                step = Step.TIMESTAMP
            else:
                continue
        elif step == Step.TIMESTAMP:
            step = Step.DATA
        elif step == Step.DATA:
            data_str = ''.join(line.strip().split('|')[2:])  # remove preamble bytes
            length = int(data_str[24:28], 16)
            packet = Ethernet_802_3(data_str) if length < 1500 else Ethernet_802_2(data_str)
            packets.append(packet)
            step = Step.NO_PACKET

    return packets


def main():
    # exit the program if we are not provided with a dataset path
    if len(sys.argv) != 2:
        print_usage()
        exit()

    path = sys.argv[1]

    try:
        with open(path, 'r') as file:  # open dataset file
            lines = file.readlines()
            packets = parse_dataset(lines)

            total_packets = len(packets)
            num_eth2 = 0
            num_eth3 = 0
            num_arp = 0
            num_eth2_stp = 0
            num_ipv4 = 0
            num_cdp = 0
            num_eth3_stp = 0
            for packet in packets:
                if packet.type == Packet.PacketType.Ethernet_802_2:
                    num_eth2 += 1
                    if packet.encap is not None:
                        encap: Packet = packet.encap
                        num_arp += encap.type == Packet.PacketType.ARP
                        num_eth2_stp += encap.type == Packet.PacketType.STP
                        if encap.type == Packet.PacketType.IPv4:
                            num_ipv4 += 1

                if packet.type == Packet.PacketType.Ethernet_802_3:
                    num_eth3 += 1
                    if packet.encap is not None:
                        encap: Packet = packet.encap
                        num_cdp += encap.type == Packet.PacketType.CDP
                        num_eth3_stp += encap.type == Packet.PacketType.STP

            # calculate percentages
            percent_eth2 = (num_eth2 / total_packets) * 100
            percent_eth3 = (num_eth3 / total_packets) * 100
            percent_arp = (num_arp / num_eth2) * 100
            percent_eth2_stp = (num_eth2_stp / num_eth2) * 100
            percent_ipv4 = (num_ipv4 / num_eth2) * 100
            percent_cdp = (num_cdp / num_eth3) * 100
            percent_eth3_stp = (num_eth3_stp / num_eth3) * 100

            print('Packet Hierarchy: {} total frames'.format(total_packets))
            print('Ethernet II ({:2.2f}%) - {} frames'.format(percent_eth2, num_eth2))
            print('|\n| ARP ({:2.2f}%) - {} packets'.format(percent_arp, num_arp))
            print('| STP ({:2.2f}%) - {} packets'.format(percent_eth2_stp, num_eth2_stp))
            print('| IPv4 ({:2.2f}%) - {} packets'.format(percent_ipv4, num_ipv4))
            print('| |\n| | TCP (%) - packets'.format())
            print('| | UDP (%) - packets\n| |\n|'.format())
            print('Ethernet 802.3 (% of total): {:2.2f}'.format(percent_eth3, num_eth3))
            print('|\n| CDP ({:2.2f}%) - {} packets'.format(percent_cdp, num_cdp))
            print('| STP ({:2.2f}%) - {} packets\n|'.format(percent_eth3_stp, num_eth3_stp))

    except IOError:  # handle error
        print('Could not open file {}!'.format(path))
        exit()


if __name__ == '__main__':
    main()
