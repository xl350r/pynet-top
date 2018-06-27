# pynet-top

A set of functions for CNA python course.
Uses scapy and itertools.

Author: Daniel C. Hoberecht

### Pynettop
encompasing class for functions.
usage:
```
test=Pynettop("8.8.8.6-8")
print(test.i)
```
## ip_range()
used to generate an iterable range of ip addresses. Found the original code on a stack overflow forum, but had to adjust it so it would stop breaking in python3.
usage:
```
i = [for i in ip_range("192.168.1-2.4-20")]
```


## trace()
At the moment increments ttl value until It reaches target, First with unix style UDP upon that failing attempts ICMP (windows style), upon that failing try tcp.

usage:
```
trace("8.8.8.8")
```

## discovery()

Meant to be used in conjunction with ip_range() and trace_route() if iterates across a list until it pings a discoverable host then calls trace_route() to find a path to the first discovered target. Then pings the rest on said list if any remain. It then returns the targets that replied, the ones that didn't, and the trace (ipup, ipdown, trace) as lists.
usage:
```
ip = [for i in ip_range("192.168.1-2.4-20")]
t=discovery(ip)
print(t[0], " Are up.")
```

## port_scanner()
as name describes, has a default list of ports it scans. Returns dict of {host: open_ports}.
