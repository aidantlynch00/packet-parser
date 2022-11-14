# packet-parser (CSCI 351 Programming Assignment)
Python script that parses 802.2, 802.3, ARP, ICMP, CDP, IPv4, TCP, UDP, STP 
packets and displays statistics such as the number of packets, protocol 
distribution, max/min/avg packet sizes, and conversations.

### Program Execution:
Run the script by executing the command `python packet_parser.py` to run the
script. The script expects one command line argument: the path to the dataset
file. The full command should look like 
`python packet_parser.py /path/to/dataset.txt`. This script does not require
the installation of any additional libraries in order to run.

### Sources:
Frame/packet formats were sourced from class materials, RFCs, and the
occasional Cisco website. Some packet formats are not fully supported since
parsing was limited to the packet types listed above.