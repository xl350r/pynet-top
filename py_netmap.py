import itertools
from scapy.all import *
#import libnmap
#from libnmap.process import NmapProcess

## https://libnmap.readthedocs.io/en/latest/process.html
## https://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input
class Pynettop:
	#default_ttl=32
	#conf.verb=0
	def __init__(self, host):
		self.default_ttl=32
		ip = [i for i in self.ip_range(host)]
		self.i=self.icmp_discovery(ip)
	## IP list creation
	## edited for better Python 3 support
	def ip_range(self, input_string):
		octets = input_string.split('.')
		chunks = [list(octet.split('-')) for octet in octets]
		ranges = [range(int(c[0]), int(c[1]) + 1) if len(c) == 2 else c for c in chunks]
		
		for address in itertools.product(*ranges):
			yield '.'.join(map(str, address))

	def trace(self, host):
		ar = []
		for i in range(1, self.default_ttl+1): #check each hop to target
			reply,src=self.test_udp(host, i) 
			if reply is None: # if no response test_icmp()
				reply, src = self.test_icmp(host, i)
				if reply is None: # if no response test_tcp()
					reply, src = self.test_tcp(host, i)
					if reply is None:# if still no response append "*"
						ar.append("*")
					elif not (reply is None): # tcp has no reply type so if response received target MUST be up.
						ar.append(src)
						if src == host:
							break # to prevent infinite loops.
						else:
							next
					else: # how the f*ck would you get here?
						ar.append("Error")
				elif reply == 0: # ICMP target reached code
					ar.append(src)
					break
				else:
					ar.append(src)
					next
			elif reply == 3: # UDP target reached code.
				ar.append(src)
				break
			else: 
				ar.append(src)
				next
		return ar


	def test_udp(self, host, ttl):
		pkt = IP(dst=host, ttl=ttl)/UDP(dport=33434) # Unix style
		reply = sr1(pkt, verbose=0, timeout=5)
		if reply is None:
			return None, None
		else:
			return reply.type, reply.src

	def test_icmp(self, host, ttl): # windows style
		pkt = IP(dst = host, ttl=ttl)/ICMP()
		reply = sr1(pkt, verbose=0, timeout=5)
		if reply is None:
			return None, None
		else:
			return reply.type, reply.src

	def test_tcp(self, host, ttl): # tcp style
		ports=[20,21,22,53,80,443,8080] # common tcp ports. at least one NEEDS to be open to respond.
		for i in ports:
			pkt=IP(dst=host, ttl=ttl)/TCP(dport=i)
			reply = sr1(pkt, verbose=0, timeout=5)
			if not (reply is None):
				return True, reply.src
			elif i == ports[-1]:
				return None, None
			else:
				next

	#edited from: https://jvns.ca/blog/2013/10/31/day-20-scapy-and-traceroute/
	#Changed to add timeout , and not break when reply is NONE


	def icmp_discovery(self, hosts):
		if conf.verb != 0:
			conf.verb=0
		target_discovered=False #trace() when host a target is found, but only for FIRST.
		ipup=[] # record who is up
		ipdown=[] # record which IPs are down
		trace =[] # store trace()
		for i in hosts:
			print("Checking", i)
			packet = IP(dst=i, ttl=self.default_ttl) / ICMP() #ICMP style ping.
			reply = sr1(packet, timeout=1)
			if not (reply is None):
				if target_discovered == False:
					target_discovered = True
					print(i, "is up")
					ipup.append(i)
					trace = self.trace(i)
				else: 
					ipup.append(i)
			else:
				ipdown.append(i)
		return ipup, ipdown, trace

test = Pynettop("8.8.8.8")
print(test.i)