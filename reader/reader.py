#!/usr/bin/env python3

import sys
import os
import time
import subprocess


if __name__ == '__main__':
	start = time.time()
	
	if len(sys.argv) == 2:
		pcap = sys.argv[1]
	else:
		raise ValueError('No PCAP file specified')

	subprocess.call(["make","-f","makefile","all"])
	subprocess.call(["./read", sys.argv[1]])
	# Clean up
	subprocess.call(["make","-f","makefile","clean"])
	
	end = time.time()
	print('This took me', end-start, 'seconds.')