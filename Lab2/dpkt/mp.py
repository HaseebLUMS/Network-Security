#!/usr/bin/env python

import dpkt
import socket, random


tcp = dpkt.tcp.TCP()
tcp.flags = dpkt.tcp.TH_SYN
tcp.seq = 1
tcp.ack = 1

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, dpkt.ip.IP_PROTO_ICMP)
s.connect(('10.130.61.93', 1))
sent = s.send(str(tcp))

print 'sent %d bytes' % sent
