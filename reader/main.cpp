#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "fstream"
#include <vector>
#include <iterator>
#include <iostream>
#include <stdlib.h>
#include <string>

using namespace std;

int main(int argc, char *argv[])
{	
	// open a pcap file for reading
	pcpp::PcapFileReaderDevice reader(argv[1]);
	if (!reader.open()) {
		printf("Error opening the pcap file\n");
		exit(1);
	}
	int tn = 0;
	int fn = 0;
	pcpp::RawPacket rawPacket;
	while (reader.getNextPacket(rawPacket)) {
		//parse the raw packet into a parsed packet
		pcpp::Packet parsedPacket(&rawPacket);

		// verify the packet is IPv4
		if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
			pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
			if (ipLayer->getIPv4Header()->typeOfService == 255) {
				tn += 1;
			}
			else {
				fn += 1;
			}
		}
	}
	// close the file
	reader.close();
	cout << "True negatives: " << tn << "\n";
	cout << "False negatives: " << fn << "\n";
	return 0;
}