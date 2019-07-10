#!/usr/bin/env python3

import sys
import os
import time
import subprocess


def has_flag(packet):
	return True


if __name__ == '__main__':
	start = time.time()
	
	if len(sys.argv) == 2:
		pcap = sys.argv[1]
	else:
		raise ValueError('No PCAP file specified')
	
	# path = os.path.basename(pcap)
	# print(sys.argv[1])

	subprocess.call(["make","-f","makefile","all"])
	subprocess.call(["./read", sys.argv[1]])

	end = time.time()
	print('This took me', end-start, 'seconds.')