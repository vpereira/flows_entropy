from scapy.all import *
import scapy
from numpy import *
from entropy import kolmogorov, shannon

#We are assuming:
#1) Its an IP packet
#2) Its an UDP packet
class ICMPStream:
	def __init__(self,pkt):
		self.src = pkt.src 
		self.dst = pkt.dst
		self.sport = 0
		self.dport = 0        
		self.time = pkt.time
		self.proto = pkt.proto
		self.inter_arrival_times = [0]
		self.pkt_count = 1
		self.len = pkt.len
		self.payload = str(pkt[ICMP].payload)
		self.pkt = pkt

        def unique_flags(self):
	    seen = set()
	    for item in self.flags:
	        if item not in seen:
	            seen.add( item )
		    yield item

	def avrg_len(self):
		return self.len/self.pkt_count

	def kolmogorov(self):
		return round(kolmogorov(self.payload),4)

	def shannon(self):
		return round(shannon(self.payload),4)

	def avrg_payload_len(self):
		return len(self.payload)/self.pkt_count

	def avrg_inter_arrival_time(self):
		return round(mean(self.inter_arrival_times),4)

	def add(self,pkt):
		self.pkt_count += 1
		self.len += pkt.len
		self.inter_arrival_times.append(pkt.time - self.time)
		self.payload += str(pkt[ICMP].payload)
		self.pkt = pkt

	def remove(self,pkt):
		raise Exception('Not Implemented')
