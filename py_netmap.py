import itertools
from scapy.all import *
#import libnmap
#from libnmap.process import NmapProcess

##https://libnmap.readthedocs.io/en/latest/process.html
##https://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input

## IP list creation
## edited for better Python 3 support.

conf.verb=0
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
	for i in range(1, 128):
	    pkt = IP(dst=host, ttl=i) / UDP(dport=33434) # unix Style ping
	    # Send the packet and get a reply
	    reply = sr1(pkt, verbose=0,timeout=2)
	    if reply is None:
	        # Reply == none
	        ar.append("*") 
	        print(i, " NONE")
	        next
	    elif reply.type == 3:
	    	# destination
	    	print(i, reply.src)
	    	ar.append(reply.src)
	    	break
	    else:
	        # middle hop
	       	ar.append(reply.src)
	       	print(i, reply.src)
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
		packet = IP(dst=i, ttl=128)/ICMP() #ICMP style ping.
		reply = sr1(packet, timeout=2)
		if not (reply is None):
			if target_discovered == False:
				target_discovered = True
				print(reply.dst, "is up")
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
ip = [i for i in ip_range("172.16.100.1-254")]
t=icmp_discovery(ip)
print(t)