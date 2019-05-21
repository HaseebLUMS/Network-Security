import dpkt

f = open('new.pcap')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
	eth = dpkt.ethernet.Ethernet(buf)
	print isinstance(eth.data, dpkt.ip.IP)
	print isinstance(eth.data, dpkt.icmp.ICMP)
	
	ip = eth.data
	print isinstance(ip.data, dpkt.icmp.ICMP)
	print isinstance(ip.data, dpkt.tcp.TCP)
	icmp = ip.data
	print repr(icmp.data)
	print icmp.code
	print icmp.type

f.close()
