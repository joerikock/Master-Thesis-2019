#!/usr/bin/env python3

import sys
from scapy.all import *
import time


def has_flag(packet):
	return True


if __name__ == '__main__':
	start = time.time()
	
	if len(sys.argv) == 2:
		traffic = sys.argv[1]
	else:
		raise ValueError('No PCAP file specified')
	
	packets = rdpcap(traffic)
	count = 0
	for packet in enumerate(packets):
		if has_flag(packet):
			count += 1
	print(count)

	end = time.time()
	print('This took me', end-start, 'seconds.')