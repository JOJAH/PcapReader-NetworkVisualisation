from scapy.all import *
import json
#READ PCAP (CHANGE NAME OF PCAP FILE FOR READING OF DESIRED PCAP FILE)
packets = rdpcap('pcaps/OT.pcap')
#SETS INITIAL DICTIONARIES AND VARIABLES 
devices = {}
nodeCount = 1
connections = {}

mostSentPackets = 0
mostRecievedPackets = 0
mostTotalPackets = 0

uniqueProtocols = set()

connectionCountHigh = 0 

# ITERATERS THROUGH PACKETS 
for packet in packets:
    # FINDS PACKETS SOURCE AND DESITNATION MAC AND IP ADDRESSES, AND PROTOCOL
    if packet.haslayer(Ether):
        sourceMac = packet[Ether].src
        destinationMac = packet[Ether].dst
        protocol = packet[Ether].getlayer(1).name
    
        if packet.haslayer(IP):
            sourceIP = packet[IP].src
            destinationIP = packet[IP].dst
            protocol = packet[IP].getlayer(1).name
        else:
            sourceIP = '-'
            destinationIP = '-' 

    #RECORDS IF SOURCE AND DESTINATION DEVICES HAVE BEEN RECORDED BEFORE, SETS AMOUNT OF SENT AND RECIEVED PACKETS, AND GIVES UNIQUE DEVICE IDS 
        if sourceIP != '-':
            if sourceIP not in devices:
                devices[sourceIP] = {'macAddresses': set(), 'sent': 0, 'recieved': 0, 'packetTotal': 0 ,'id':nodeCount}
                nodeCount += 1
            devices[sourceIP]['macAddresses'].add(sourceMac)
            devices[sourceIP]['sent'] += 1
            mostSentPackets = max(mostSentPackets, devices[sourceIP]['sent'])

            devices[sourceIP]['packetTotal'] = devices[sourceIP]['sent'] + devices[sourceIP]['recieved']
            mostTotalPackets = max(mostTotalPackets, devices[sourceIP]['packetTotal'])

        if destinationIP != '-':
            if destinationIP not in devices:
                devices[destinationIP] = {'macAddresses': set(), 'sent': 0, 'recieved': 0, 'packetTotal': 0, 'id':nodeCount}
                nodeCount += 1
            devices[destinationIP]['macAddresses'].add(destinationMac)
            devices[destinationIP]['recieved'] += 1
            mostRecievedPackets = max(mostRecievedPackets, devices[destinationIP]['recieved'])

            devices[destinationIP]['packetTotal'] = devices[destinationIP]['sent'] + devices[destinationIP]['recieved']
            mostTotalPackets = max(mostTotalPackets, devices[destinationIP]['packetTotal'])
        #RECORDS IF PROTOCOL IS UNIQUE
            uniqueProtocols.add(protocol)
        #RECORDS CONNECTION DATA
            connection = (devices[sourceIP]['id'], devices[destinationIP]['id'], protocol, sourceIP, destinationIP, sourceMac, destinationMac)
        #CHECKS IF CONNECTION HAS BEEN RECORDED BEFORE,  UPDATES THE NUMBER OF TIMES ITS OCCURED
        if connection not in connections:
            connections[connection] = {'count': 1}
        else:
            connections[connection]['count'] += 1
    
#RECORDS HIGHEST CONNECTION COUNT
for connection, info in connections.items():
    count = info['count']
    if count > connectionCountHigh:
        connectionCountHigh = count
        
# PREPARES RECORDED DATA FOR JSON FILE CREATION        
nodes = [{'ip':ip, 'mac': '/'.join(info['macAddresses']),'sent': info['sent'], 'recieved':info['recieved'],'packetTotal':info['packetTotal'], 'nodeNumber': info['id'] } for ip, info in devices.items()]

connectionList = [{'source':i[0], 'target':i[1], 'protocol': i[2], 'sourceIp': i[3], 'destinationIp': i[4], 'sourceMac': i[5], 'destinationMac': i[6], 'count':info['count']} for i, info in connections.items()]

jsonData = {'nodes':nodes,
             'connections':connectionList,
               'uniqueProtocols': list(uniqueProtocols),
                 'connectionCountLevel':connectionCountHigh/5,
                   'packetsSentLevel': mostSentPackets/20,
                   'packetsRecievedLevel':mostRecievedPackets/20,
                    'totalPacketLevel':mostTotalPackets/20}

#CREATES OUTPUT.JSON FILE AND POPULATES WITH RECORDED DATA 
with open('readerOutput/output.json', 'w') as jsonFile:
    json.dump(jsonData, jsonFile, indent=4) 