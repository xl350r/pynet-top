import itertools
from scapy.all import *
#import libnmap
#from libnmap.process import NmapProcess

## https://libnmap.readthedocs.io/en/latest/process.html
## https://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input
default_ttl=32
conf.verb=0

## IP list creation
## edited for better Python 3 support
def ip_range(input_string):
	octets = input_string.split('.')
	chunks = [list(octet.split('-')) for octet in octets]
	ranges = [range(int(c[0]), int(c[1]) + 1) if len(c) == 2 else c for c in chunks]
	
	for address in itertools.product(*ranges):
		yield '.'.join(map(str, address))

#edited from: https://jvns.ca/blog/2013/10/31/day-20-scapy-and-traceroute/
#Changed to add timeout , and not break when reply is NONE
def trace_route(host):
	if conf.verb != 0: #Squash output.
		conf.verb=0
	ar=[] # create array that will be returned
	for i in range(1, default_ttl):
		pkt = IP(dst=host, ttl=i) / UDP(dport=33434)#ICMP() # unix Style traceroute 
		# Send the packet and get a reply
		reply = sr1(pkt, verbose=0, timeout=5)
		if reply is None:
			# Reply == none
			pkt = IP(dst=host,ttl=i) / ICMP()# try again with icmp (windows style)
			reply = sr1(pkt, verbose=0, timeout=5)
			if reply is None:
				ar.append("*") 
				print(i, " NONE")
				next
			elif reply.type == 0: #ICMP target reached reply type 
				ar.append(reply.src)
				print("ICMP",i, reply.src)
				break
			else:
				ar.append(reply.src)
				print(i, reply.src)
				next
		elif reply.type == 3: #UDP target reached reply type
			# destination
			print("UDP", i, reply.src)
			ar.append(reply.src)
			break
		else:
			# middle hop
			ar.append(reply.src)
			print(i, reply.src)
			next
	return ar


def icmp_discovery(hosts):
	if conf.verb != 0:
		conf.verb=0
	target_discovered=False #Trace_route() when host a target is found, but only for FIRST.
	ipup=[] # record who is up
	ipdown=[] # record which IPs are down
	trace =[] # store trace_route()
	for i in hosts:
		print("Checking", i)
		packet = IP(dst=i, ttl=default_ttl) / ICMP() #ICMP style ping.
		reply = sr1(packet, timeout=1)
		if not (reply is None):
			if target_discovered == False:
				target_discovered = True
				print(i, "is up")
				ipup.append(i)
				trace = trace_route(i)
			else: 
				ipup.append(i)
		else:
			ipdown.append(i)
	return ipup, ipdown, trace


#for i in ip_range("192.168.1-2.1-255"):
#	print(i)
#print(icmp_discovery(["8.8.8.8"]))
#ip = [i for i in ip_range("8.8.8.6-8")]
ip = [i for i in ip_range("192.124.249.2")]
t=icmp_discovery(ip)
print(t)