from ip_stream import *

#We are assuming:
#1) Its an IP packet
#2) Its an UDP packet
class UDPStream(IPStream):
	def __init__(self,pkt):
		self.src = pkt.src 
		self.dst = pkt.dst
		self.sport = pkt.sport
		self.dport = pkt.dport        
		self.time = pkt.time
		self.proto = pkt.proto
		self.inter_arrival_times = [0]
		self.pkt_count = 1
		self.len = pkt.len
		self.payload = str(pkt[UDP].payload)
		self.pkt = pkt

	def add(self,pkt):
		self.pkt_count += 1
		self.len += pkt.len
		self.inter_arrival_times.append(pkt.time - self.time)
		self.payload += str(pkt[UDP].payload)
		self.pkt = pkt

	def remove(self,pkt):
		raise Exception('Not Implemented')