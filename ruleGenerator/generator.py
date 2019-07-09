#!/usr/bin/env python3

import sys
import math
import json
import random
from bitstring import BitArray
from ipaddress import ip_network, ip_address
from socket import inet_aton
import itertools

def convertIpAddressesIntoCdirMaxRules(ipAddresses, maxRuleAmount):
    currentPrefixSize = 32
    
    binaryIpAddresses = [BitArray(inet_aton(ipAddress)).bin for ipAddress in ipAddresses]
    binaryIpAddresses.sort()

    prefixIdCounter = activePrefixIds = len(binaryIpAddresses)
    prefixIdMemory = [[32, i] for i in range(1, prefixIdCounter + 1)]
    
    def updatePrefixIdMemoryRange(startIndex, endIndex, newPrefixSize):
        nonlocal prefixIdCounter, activePrefixIds, prefixIdMemory
        prefixIdsToRemove = len(set([memoryValue[1] for memoryValue in prefixIdMemory[startIndex:endIndex + 1]])) - 1
    
        if prefixIdsToRemove > 0:
            # print(prefixIdsToRemove, prefixIdMemory, startIndex, endIndex, newPrefixSize)
            
            prefixIdCounter = prefixIdCounter + 1
            activePrefixIds -= prefixIdsToRemove
            newPrefixIdMemoryValue = [newPrefixSize, prefixIdCounter]

            endIndex += 1
            prefixIdMemory[startIndex:endIndex] = itertools.repeat(newPrefixIdMemoryValue, (endIndex - startIndex))
                
    while activePrefixIds > maxRuleAmount:
        currentPrefixSize = currentPrefixSize - 1

        # Make a list scoped to the current prefix size
        currentPrefixList = [ipAddress[0:currentPrefixSize] for ipAddress in binaryIpAddresses]
        
        # Loop through the list with prefixes and check for duplicates
        oldestEqualPrefixListIndex = 0
        oldestEqualPrefixListValue = currentPrefixList[0]
        
        for currentPrefixListIndex, currentPrefixListValue in enumerate(currentPrefixList):            
            # Check if sequence has been broken
            if activePrefixIds <= maxRuleAmount:
                break
            if currentPrefixListValue != oldestEqualPrefixListValue:
                # Check if multiple equal values
                if oldestEqualPrefixListIndex != currentPrefixListIndex - 1:
                    # We have matches, check amount of overlap with prefixIdMemory
                    updatePrefixIdMemoryRange(oldestEqualPrefixListIndex, currentPrefixListIndex - 1, currentPrefixSize) 
                
                # Reset memory
                oldestEqualPrefixListIndex = currentPrefixListIndex
                oldestEqualPrefixListValue = currentPrefixListValue
            elif currentPrefixListIndex == len(currentPrefixList) - 1:
                # Check if multiple equal values
                if oldestEqualPrefixListValue == currentPrefixListValue:
                    # We have matches, check amount of overlap with prefixIdMemory
                    updatePrefixIdMemoryRange(oldestEqualPrefixListIndex, currentPrefixListIndex, currentPrefixSize) 
                
                # Reset memory
                oldestEqualPrefixListIndex = currentPrefixListIndex
                oldestEqualPrefixListValue = currentPrefixListValue

    # Initialize a list with resulting prefixes
    resultList = []
    passedMemoryEntries = set()
    for memoryIndex, memoryEntry in enumerate(prefixIdMemory):
        if memoryEntry[1] not in passedMemoryEntries:
            passedMemoryEntries.add(memoryEntry[1])
            
            # Get the prefix size for the current prefix
            prefixSize = memoryEntry[0]
            slicedBinaryIpAddress = binaryIpAddresses[memoryIndex][0:prefixSize]

            # Pad the IP address with zeroes again and convert it into a decimal representation
            decimalIpAddress = str(ip_address(int(slicedBinaryIpAddress.ljust(32, '0'), 2)))

            # Add the prefix to the result list
            resultList.append('{}/{}'.format(decimalIpAddress, prefixSize))

    return resultList


def getSourceIps(fingerprintSourceIps):
    ip_set = []
    for ip in fingerprintSourceIps:
        ip_set.append(ip['ip'])
    return ip_set


# Generate Type 3 rule component
# TODO: Support more protocols?
def getIpProtocols(fingerprintProtocol):
    ipProtocols = []

    if fingerprintProtocol in ['TCP', 'DNS', 'Chargen']:
        ipProtocols.append(6)
    if fingerprintProtocol in ['UDP', 'DNS', 'Chargen', 'QUIC', 'NTP', 'SSDP']:
        ipProtocols.append(17)
    if fingerprintProtocol in ['ICMP']:
        ipProtocols.append(1)

    return ipProtocols

# Generate Type 5 or Type 6 rule component
def getPorts(fingerprintPorts):
    ports = []

    for port in fingerprintPorts:
        if not math.isnan(port):
            ports.append(int(port))

    return ports

# Generate Type 7 rule component
def getIcmpType(fingerprintIcmpType):
    return int(float(fingerprintIcmpType))

# Generate Type 9 rule component
def getTcpFlag(fingerprintTcpFlag):
    filteredTcpFlag = fingerprintTcpFlag.replace('\u00b7', '')

    tcpFlags = []

    for flag in filteredTcpFlag:
        if flag == 'S':
            tcpFlags.append('syn')
        elif flag == 'E':
            tcpFlags.append('ecn')
        elif flag == 'C':
            tcpFlags.append('cwr')
        elif flag == 'U':
            tcpFlags.append('urg')
        elif flag == 'A':
            tcpFlags.append('ack')
        elif flag == 'P':
            tcpFlags.append('psh')
        elif flag == 'R':
            tcpFlags.append('rst')
        elif flag == 'F':
            tcpFlags.append('fin')
        else:
            raise ValueError('Encountered flag with unknown format')

    return tcpFlags

# Parser (IL to Junos OS)
def parseRuleToJunos(rule):
    def wrapMatchStatement(statement):
        return "            " + statement + ";\n"
    
    matchBlock = ""
    # Destination
    if 'type1' in rule.keys():
        matchBlock += wrapMatchStatement("destination " + rule['type1'])
    if 'type2' in rule.keys():
        matchBlock += wrapMatchStatement("source " + rule['type2'])
    if 'type3' in rule.keys():
        protocolMap = {
            1: "icmp",
            6: "tcp",
            17: "udp"
        }
        for protocol in rule['type3']:
            matchBlock += wrapMatchStatement("protocol " + protocolMap[protocol])
    if 'type5' in rule.keys():
        matchBlock += wrapMatchStatement("destination-port " + str(rule['type5'][0]))
    if 'type6' in rule.keys():
        matchBlock += wrapMatchStatement("source-port " + str(rule['type6'][0]))
    if 'type7' in rule.keys():
        matchBlock += wrapMatchStatement("icmp-type " + str(rule['type7']))
    if 'type9' in rule.keys():
        for flag in rule['type9']:
            matchBlock += wrapMatchStatement("tcp-flag " + flag)

    return f"""
flow {{
    term-order standard;
    route {random.randint(0,1000000)} {{
        match {{
{matchBlock}        }}
        then discard;
    }}
}}"""

# Rule generator
def main():
    fingerprint = None
    destinationIp = '1.1.1.1'
    rule_limit = 6000

    # Read the fingerprint file
    if (len(sys.argv) == 2):
        f = open(sys.argv[1], 'r')
        fingerprint = json.loads(f.read())
    else:
        raise ValueError('Please supply a fingerprint file path as argument')

    # Resulting array
    flowspecRules = []

    # Rule that will be used as template
    baseFlowspecRule = {}

    # Collect Type 1 (Destination IP)
    baseFlowspecRule['type1'] = '{}/32'.format(destinationIp)

    # Type 2 will be dynamically generated and added to the resulting ruleset later
    # TODO: Create (weighted) algorithm for reducing fingerprint source IPs into prefixes
    source_ips = getSourceIps(fingerprint['src_ips'])
    baseFlowspecRule['type2'] = None

    # Collect Type 3 (IP protocol)
    type3 = getIpProtocols(fingerprint['protocol'])
    baseFlowspecRule['type3'] = type3

    # Collect type 5 (Destination ports)
    if 'dst_ports' in fingerprint:
        type5 = getPorts(fingerprint['dst_ports'])

        # Only add if a single port occurs
        if (len(type5) == 1):
            baseFlowspecRule['type5'] = type5

    # Collect type 6 (Source ports)
    if 'src_ports' in fingerprint:
        type6 = getPorts(fingerprint['src_ports'])

        # Only add if a single port occurs
        if (len(type6) == 1):
            baseFlowspecRule['type6'] = type6

    # If ICMP, collect its ICMP information
    if 1 in type3:

        # Collect type 7
        baseFlowspecRule['type7'] = getIcmpType(fingerprint['additional']['icmp_type'])

    # If TCP, collect its flag information
    if 6 in type3:

        # Collect type 9
        baseFlowspecRule['type9'] = getTcpFlag(fingerprint['additional']['tcp_flag'])

    source_ips = convertIpAddressesIntoCdirMaxRules(source_ips, rule_limit)
    for ip in source_ips:
        baseFlowspecRule['type2'] = ip
        flowspecRules.append(baseFlowspecRule)

    return flowspecRules

if __name__ == '__main__':
    ruleset = main()

    result = []
    for rule in ruleset:
        result.append(parseRuleToJunos(rule))

    print(result)
    
    # print(main())
