import itertools
from scapy.all import *
import libnmap
from libnmap.process import NmapProcess

##https://libnmap.readthedocs.io/en/latest/process.html
##https://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input

## IP list creation
def ip_range(input_string):
    octets = input_string.split('.')
    chunks = [map(int, octet.split('-')) for octet in octets]
    ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]

    for address in itertools.product(*ranges):
        yield '.'.join(map(str, address))

def trace_route(host):
	for i in range(1, 128):
	    pkt = IP(dst=host, ttl=i) / UDP(dport=33434)
	    # Send the packet and get a reply
	    reply = sr1(pkt, verbose=0)
	    if reply is None:
	        # No reply =(
	        next(iterator, default)
	    elif reply.type == 3:
	        # We've reached our destination
	        return(reply.src)
	    else:
	        # We're in the middle somewhere
	        return(i , reply.src)


def icmp_discovery(hosts):
	conf.verb=0
	target_discovered=False
	num_discovered=0
	ipup=[]
	ipdown=[]
	for i in hosts:
		packet = IP(dst=i, ttl=128)/ICMP()
		reply = sr1(packet, timeout=2)
	if not (reply is None):
		num_discovered += 1
		if target_discovered == False:
			target_discovered = True
			print(reply.dst, " is up")
			ipup.append(i)
			trace_route(i)
		else: 
			ipup.append(i)
	else:
		ipdown.append(i)
	return (ipup, ipdown)

icmp_discovery(["8.8.8.8"])


