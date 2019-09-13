#!/usr/bin/env python3

import sys
import os
import json
import random
import time
import socket
import struct
import subprocess
import shutil


def uint32_to_ip(ipn):
	t = struct.pack('I', ipn)
	return socket.inet_ntoa(t)


def ip_to_uint32(ip):
	t = socket.inet_aton(ip)
	return struct.unpack('I', t)[0]


def generateTxts(fp, overlap):
	ip_list = []
	for item in fp['src_ips']:
		ip_list.append(ip_to_uint32(item['ip']))
	resultList = random.sample(ip_list, round((len(ip_list)/100*overlap)))
	filename = str(overlap) + '.txt'
	with open(os.path.join('./',filename), 'w') as f:
		for ip in resultList:
			f.write('%s\n' % ip)


if __name__ == '__main__':
	start = time.time()
	overlap_set = [25,50,75]

	# Load fingerprint from argv
	if len(sys.argv) == 2:
		f = open(sys.argv[1], 'r')
		fingerprint = json.loads(f.read())
	else:
		raise ValueError('No fingerprint file supplied.')
	
	# This line extracts the ID from the fingerprint file (might use later)
	filename = os.path.splitext(os.path.basename(sys.argv[1]))[0]

	for overlap in overlap_set:
		generateTxts(fingerprint, overlap)
	subprocess.call(["make","-f","makefile","all"])
	for overlap in overlap_set:
		print("Generating PCAP for",overlap,"percent overlap")
		subprocess.call(["./randomize", str(overlap), str(filename)])

	# Clean up
	subprocess.call(["make","-f","makefile","clean"])

	end = time.time()
	print('This took me', end-start, 'seconds.')
