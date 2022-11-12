"""
Author: Aidan Lynch (atl4849)

TODO: DESCRIPTION OF PROGRAM HERE
"""

import sys
from enum import Enum
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

    except IOError:  # handle error
        print('Could not open file {}!'.format(path))
        exit()


if __name__ == '__main__':
    main()
