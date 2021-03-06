import itertools
from scapy.all import sr1, UDP, TCP, ICMP, IP, conf
## https://stackoverflow.com/questions/20525330/python-generate-a-list-of-ip-addresses-from-user-input
class Pynettop:
	def __init__(self, host, time=0.1, ttl=32): # time= timeout as float or int, host = array of ip, ttl int time to life.
		self.default_ttl=ttl
		self.timeout=time
		ip = [i for i in self.ip_range(host)]
		self.start=self.discovery(ip) # edit to return self.discovery(ip)
	## IP list creation
	## edited for better Python 3 support
	def ip_range(self, input_string): # outputs generator save to variable with var = [i for i in ip_range(string)]
		octets = input_string.split('.')
		if 4!=len(octets): # make sure there are 4 octets.
			print("Error:", input_string, "is an invalid input.")
			exit(1)
		chunks = [list(octet.split('-')) for octet in octets]
		for i in chunks:
			if len(i) == 2: # make sure checking both parts of if split by '-'
				if int(i[0]) < 0 or int(i[0]) > 255 or int(i[1]) > 255 or int(i[1]) < 0: # check if greater than 255 or less than 0
					print("Error: Invalid Ip addressing.", input_string, "  an octet is less than 0 or greater than 255")
					exit(1) 
			elif len(i) == 1 and int(i[0]) > 255 or int(i[0]) < 0:  # check if greater than 255 or less than 0
				print("Error: Invalid Ip addressing.", input_string, "has an octet is less than 0 or greater than 255")
				exit(1)
		ranges = [range(int(c[0]), int(c[1]) + 1) if len(c) == 2 else c for c in chunks] # ternary to generate range.
		
		for address in itertools.product(*ranges):
			yield '.'.join(map(str, address))

	def trace(self, host): # accepts string as host where the string is an IP address.
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
		reply = sr1(pkt, verbose=0, timeout=self.timeout)
		if reply is None:
			return None, None
		else:
			return reply.type, reply.src

	def test_icmp(self, host, ttl): # windows style
		pkt = IP(dst = host, ttl=ttl)/ICMP()
		reply = sr1(pkt, verbose=0, timeout=self.timeout)
		if reply is None:
			return None, None
		else:
			return reply.type, reply.src

	def test_tcp(self, host, ttl): # tcp style
		ports=[20,21,22,53,80,443,1723,8080] # common tcp ports. If respong is SYN+ACK or RST will detect.
		for i in ports:
			pkt=IP(dst=host, ttl=ttl)/TCP(dport=i)
			reply = sr1(pkt, verbose=0, timeout=self.timeout)
			if not (reply is None): #looking for ANY reply
				return True, reply.src
			elif i == ports[-1]: # Break infinite looks
				return None, None
			else: # If not reply port is filtered,  and moves to next port.
				next
				# hosts : array of host(s), ports : array of ports. Time : timeout in seconds (float). ttl : time to life (int)
	def port_scanner(self, hosts, ports=[21,22,53,80,443,1723,8080], time=0.5, ttl=64): 
		HostPort_dict=dict() #Init variable to store results
		for host in hosts:
			HostPort_dict[host]=[] # create blank dict entry for host
			for i in ports:
				pkt=IP(dst=host, ttl=ttl)/TCP(dport=i)
				reply=sr1(pkt, verbose=0,timeout=time)
				if (reply is None): # host either down or firewall filtering requests.
					HostPort_dict[host].append(str(i) + " Filtered")
				elif (str(reply[TCP].flags) == "SA"): # if syn-ack port is open
					HostPort_dict[host].append(str(i)) # append to current host entry list.
					sr1(IP(dst=host, ttl=ttl)/TCP(dport=i, flags="R"), verbose=0, timeout=0)
				elif (str(reply[TCP].flags) == "RA"): # if RA port is closed
					HostPort_dict[host].append(str(i) + " Closed")
				else: # is other response assume closed/.
					HostPort_dict[host].append(str(i) + " Closed/Filtered")
		return HostPort_dict # return entire dict.

	#edited from: https://jvns.ca/blog/2013/10/31/day-20-scapy-and-traceroute/
	#Changed to add timeout , and not break when reply is NONE
	def discovery(self, hosts):
		if conf.verb != 0:
			conf.verb=0
		target_discovered=False #trace() when host a target is found, but only for FIRST.
		ipup=[] # record who is up
		ipdown=[] # record which IPs are down
		trace =[] # store trace()
		for i in hosts:
			reply,src=self.test_icmp(i, 64)
			if not (reply is None):
				if target_discovered == False:
					target_discovered = True
					#print(i, "is up")
					ipup.append(i)
					trace = self.trace(i)
				else: 
					ipup.append(i)
			elif reply is None:
				reply,src=self.test_udp(i, 64)
				if reply is None:
					reply,src = self.test_tcp(i, 64)
					if not (reply is None):
						if target_discovered == False:
							target_discovered = True
							ipup.append(i)
							trace=self.trace(i)
						else:
							ipup.append(i)
					else:
						ipdown.append(i)
				elif not (reply is None):
					if target_discovered == False:
							target_discovered = True
							ipup.append(i)
							trace=self.trace(i)
					else:
						ipup.append(i)
			else:
				ipdown.append(i)

		return ipup, ipdown, trace

if __name__ == '__main__':
	try:
		cnt=0
		scan = Pynettop("8.8.8.8", time=0.1, ttl=32)
		ipup,ipdown,trace=scan.start
		ipup=scan.port_scanner(hosts=ipup)
		for ip in ipup:
			print("\n"+ip)
			print("port", "\t", "status")
			for port_status in ipup[ip]:
				ps = port_status.split(" ")
				if len(ps) == 2:
					if len(ps[0]) < 5:
						print(ps[0]+ (" "*(5-len(ps[0]))), "\t", ps[1])
					else:
						print(ps[0], "\t", ps[1])
				else:
					if len(ps[0]) < 5:
						print(ps[0]+ (" "*(5-len(ps[0]))), "\t", "Open")
					else: 
						print(ps[0], "\t", "Open")
		if len(trace) != 0:
			print("\nTrace Route:")
			print("Hop", "\t IP")
			for t in trace:
				if len(str(cnt+1)) < 3:
					print(str(cnt+1) + (" "*(3-len(str(cnt+1)))),"\t", t)
				else:
					print(str(cnt+1),"\t", t)
				cnt += 1
		if len(ipdown) != 0:
			print(ipdown) 
		exit(0)
	except ValueError as e:
		raise e
	except NameError as e:
		raise e
	except AttributeError as e:
		print("Error: Input Is formatted Incorrectly")
		exit(1)
