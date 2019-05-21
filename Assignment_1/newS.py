#!/usr/bin/python

import thread
import time

# Define a function for the thread
def print_time( threadName, delay):
   count = 0
   while count < 5:
      time.sleep(delay)
      count += 1
      print "%s: %s" % ( threadName, time.ctime(time.time()) )

def scanPort(p):
	
for i in range(1, 65000):
	thread.start_new_thread(scanPort, (i))


while 1:
   pass
