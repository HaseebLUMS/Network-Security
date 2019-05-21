import socket
import sys
import datetime
import time
import threading
import os

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
	#sock.settimeout(7)
	#if port in freq:
	#	sock.settimeout(3)
	try:
		closed = sock.connect((IP, port))

		#ser = "unknown"
		if not closed:
			#print "\nPort ", port, " Open\n"
			#Ports[port] = "Open"
			try:
				ser = socket.getservbyport(port)
				print ser, " running on open port # ", port
				#Services[port] = ser
			except:
				print "unknown running on open ", port
				#Services[port] = "unknown"
		sock.close()
	except:
		pass
	sema.release()


def main():
	#os.system("ulimit -n 3072") 
	global IP
	global Ports
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
	for port in range(1, 65535):
		sema.acquire(1)
		thread1 = threading.Thread(target=scanIt, args=(port, ))
		newThreads.append(thread1)
		thread1.start()
	sema.acquire(500)
	t2 = datetime.datetime.now()
	print Ports
	print Services
	print "Total Time:               ", t2-t1
	print "Ports Scanned Per Second: ", ((t2-t1)/65000).total_seconds()
	
main()
