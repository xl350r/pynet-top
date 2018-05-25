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
	    reply = sr1(pkt, verbose=0, timeout=2)
	    if reply is None:
	        # Reply == none
	        next
	    elif reply.type == 3:
	        return(reply.src)
	    else:
	        # middle hop
	        return(i , reply.src)


def icmp_discovery(hosts):
	target_discovered=False # Switch for initiak Trace when host a target is found.
	ipup=[] # record who is up
	ipdown=[] # record which IPs are down
	for i in hosts:
		packet = IP(dst=i, ttl=128)/ICMP()
		reply = sr1(packet, timeout=2)
	if not (reply is None):
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


