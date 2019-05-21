import socket
import sys
import datetime
import time
import threading
import os

total_ports = 65535
IP    = "127.0.0.1"
Ports    = {}
Services = {}
sema = threading.Semaphore(500)
def scanIt(port):
	global Ports
	global IP
	global sema
	#freq = [] #append frequently used here, do freq = [] if any concern
	sock   = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(10)
	#if port in freq:
	#	sock.settimeout(3)
	closed = sock.connect_ex((IP, port))
	#ser = "unknown"
	if not closed:
		#print "\nPort ", port, " Open\n"
		Ports[port] = "Open"
		try:
			ser = socket.getservbyport(port)
			print ser, " running on open port # ", port

			Services[port] = ser
		except:
			print "unknown ", " running on open port # ", port

			Services[port] = "unknown"
	sock.close()
	sema.release()


def main():
	#os.system("ulimit -n 3072") 
	global IP
	global Ports
	print "If output seems mal-formated, then please re-run the program.\nAlthough, at the end, formated output will be shown anyway."
	print "If ports seem missing, then please re-run it."
	print "Inspecting Name..."
	HOSTNAME = sys.argv[1]
	try:
		print "1.."
		IP   = socket.gethostbyname(HOSTNAME)
		print "2.."
	except:
		IP = HOSTNAME
	print "Scanning ", IP, "..."
	t1 = datetime.datetime.now()
	newThreads = []
	for port in range(1, total_ports):
		try:
			sema.acquire(1)
			thread1 = threading.Thread(target=scanIt, args=(port, ))
			newThreads.append(thread1)
			thread1.start()
		except:
			pass
	sema.acquire(500)
	t2 = datetime.datetime.now()
	print Ports
	print Services
	print "Total Time:               ", t2-t1
	print "Ports Scanned Per Second: ", (((t2-t1)/65000).total_seconds())
	
main()
