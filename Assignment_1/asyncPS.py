import asyncio
import socket
import datetime
import time
import os
import sys
import threading

ports = {}
tasks = {}
total = 10000
IP = '127.0.0.1'
t1 = datetime.datetime.now()
sema = threading.Semaphore(500)

# this is a coroutine definition
async def scanPort(p, loop):

	conn = asyncio.open_connection(IP, p)
	try:
		r, w = await asyncio.wait_for(conn, timeout=10)
		print (p , " open!")
	except:
		pass
	return True


# this is a coroutine definition
async def generate(loop):
	global ports
	global t1
	for i in range(1, total+1):
		#sema.acquire(1)
		tasks[i] = asyncio.ensure_future(scanPort(i, loop))
		#sema.release()

	await asyncio.wait([tasks[x] for x in range(1, total+1)])
	
	t2 = datetime.datetime.now()
	print("Total Time:               ", t2-t1)
	print ("Ports Scanned Per Second: ", ((t2-t1)/65000).total_seconds())

def main():
	global IP
	global ports
	HOSTNAME = sys.argv[1]
	try:
		IP   = socket.gethostbyname(HOSTNAME)
	except:
		IP = HOSTNAME
	print("Scanning ", IP, "...")
	t1 = datetime.datetime.now()
	loop = asyncio.get_event_loop()
	loop.run_until_complete(asyncio.ensure_future(generate(loop)))
	#print(ports)
	
main()
