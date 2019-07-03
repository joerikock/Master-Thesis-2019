# Traffic generator

Generate 'normal' internet traffic based on a DDoS fingerprint from DDoSDB and a file bigFlows.pcap. A percentage of 'overlap' is specified, and the code updates the source IPs of bigFlows to overlap partly with the IP addresses from the fingerprint.

## Prerequisites

A machine with Ubuntu 18.04 LTS is required.

Download bigFlows.pcap from [here](http://tcpreplay.appneta.com/wiki/captures.html) and place it in the root folder. You can also use smallFlows.pcap, but bigFlows is more realistic.

Next, install gcc:

```bash
sudo apt update
sudo apt install build-essential
```
The gcc version should be 7.4.0. Check this by typing
```bash
gcc --version
```
Download PcapPlusPlus from [here](https://github.com/seladb/PcapPlusPlus/releases/tag/v19.04). Make sure to select the release for Ubuntu 18.04 and gcc 7. Extract the .tar.gz and change into the directory.

Install libpcap-dev:
```bash
sudo apt-get install libpcap-dev
```
Install PcapPlusPlus by running:
```bash
sudo ./install.sh
```
## Usage

In trafficGenerator.py, specify the values in overlap_set. The generator will create a PCAP file for each value of overlap.
```bash
./trafficGenerator.py <fingerprint>
```
