import dpkt
import sys
import os
import socket

synCount = {} #ip: n
synAckCount = {} # ip: n
def findAnom(filepath):
	f = open(filepath)
	pcap = dpkt.pcap.Reader(f)


	for _, d in pcap:
		try:
			ether = dpkt.ethernet.Ethernet(d)
			if isinstance(ether, dpkt.ethernet.Ethernet):
				ip = ether.data
				if isinstance(ip, dpkt.ip.IP):
					tcp = ip.data
					if isinstance(tcp, dpkt.tcp.TCP):
						if (tcp.flags & dpkt.tcp.TH_ACK) and (tcp.flags & dpkt.tcp.TH_SYN): #syn/ack
							DST = socket.inet_ntoa(ip.dst)
							try:
								synAckCount[DST] += 1
							except:
								synAckCount[DST] = 1
						elif (tcp.flags & dpkt.tcp.TH_SYN): #syn
							SRC =  socket.inet_ntoa(ip.src)
							try:
								synCount[SRC] += 1
							except:
								synCount[SRC] = 1
		except:
			pass





	for i in synCount:
		try:
			if synCount[i] > 3*synAckCount[i]:
				print i
		except:
			print i
			
	

findAnom(sys.argv[1])
