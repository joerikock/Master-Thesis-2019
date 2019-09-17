#include "IPv4Layer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "fstream"
#include <vector>
#include <iterator>
#include <iostream>
#include <stdlib.h>
#include <string>
#include <fstream>
#include <sstream>
#include <algorithm>

using namespace std;

std::vector<std::string> split(const std::string &s, char delim) {
	std::stringstream ss(s);
	std::string item;
	std::vector<std::string> elems;
	while (std::getline(ss, item, delim)) {
		elems.push_back(item);
	}
	return elems;
}

int main(int argc, char *argv[])
{	
	// open a pcap file for reading
	pcpp::PcapNgFileReaderDevice reader(argv[1]);
	if (!reader.open()) {
		printf("Error opening the pcap file\n");
		exit(1);
	}
	int tn = 0;
	int fn = 0;

	// Get metadata from comment field
	std::string commentData = reader.getCaptureFileComment();
	// cout << "Comment data: " << commentData << "\n";

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
	cout << "Normal packets: " << tn << "\n";
	cout << "DDoS packets: " << fn << "\n";

	char delim = '|';
	std::vector<std::string> commentSplitted = split(commentData, delim);

	std::ofstream outputfile;
    outputfile.open("results.csv", std::ios_base::app);
	outputfile << commentSplitted[0] << "," << commentSplitted[1] << "," << tn << "," << fn << "\n";
    outputfile.close();
	return 0;
}
