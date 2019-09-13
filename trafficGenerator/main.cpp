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

//functions to get random element from vector (not used)
int random_int(int min, int max)
{
    return rand() % (max - min + 1) + min;
}

//template<class int>
int random_element(std::vector<uint32_t>& elements)
{
    return elements[random_int(0, elements.size() - 1)];
}

int main(int argc, char *argv[])
{
	// Get overlap percentage from argument 1
	int f = atof(argv[1]);

    // Get fingerprint ID from argument 2
    std::string fingerprint_id = argv[2];
    
    int i = 1;
	
    // Generate txt output file name
	std::string textfilename = ".txt";
	textfilename.insert(0,argv[1]);
	
    //load current "file.txt" and uint32 IP addresses in a vector
    using isii = std::istream_iterator<uint32_t>;
    std::ifstream in{ textfilename};
	std::vector<uint32_t> ints{ isii{ in }, isii{} };
	
	int attacksize = ints.size();

	std::string outputname = "normal.pcapng";
	outputname.insert(6,argv[1]);

    // Build the comment field, which has the fingerprint ID and overlap percentage
    std::string commentData = fingerprint_id;
    commentData += "|";
    commentData += std::to_string(f);
	
    // pcpp::PcapFileWriterDevice pcapWriter(outputname.c_str(), pcpp::LINKTYPE_ETHERNET);
    pcpp::PcapNgFileWriterDevice pcapWriter(outputname.c_str());

    // try to open the file for writing
    if (!pcapWriter.open("", "", "", commentData.c_str())) {
        printf("Cannot open output.pcap for writing\n");
        exit(1);
    }

    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("bigFlows.pcap");
    if (!reader.open()) {
        printf("Error opening the pcap file\n");
        exit(1);
    }
    int i2 = 0;
    pcpp::RawPacket rawPacket;

    while (reader.getNextPacket(rawPacket)) {
        i += 1;
        i = i % 1000;

        //parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        // verify the packet is IPv4
        if (parsedPacket.isPacketOfType(pcpp::IPv4)) {
            pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            ipLayer->setDstIpAddress(pcpp::IPv4Address(std::string("1.1.1.1")));
            ipLayer->getIPv4Header()->typeOfService = 255;
			srand(((unsigned)time(NULL))+i);
			int r = random_int(0,100);
            if (f > r) {
                ipLayer->setSrcIpAddress(pcpp::IPv4Address(ints[i2]));
                // for testing (this changes the QoS field to only the overlap packets instead of all packets):
                // ipLayer->getIPv4Header()->typeOfService = 255;
                i2 += 1;
                i2 = i2 % attacksize;
            }
            pcapWriter.writePacket(rawPacket);
        }
    }
    reader.close();
    pcapWriter.close();
    return 0;
}
