from ip_stream import *

#We are assuming:
#1) Its an IP packet
#2) Its an UDP packet
class UDPStream(IPStream):
	def __init__(self,pkt):
                super(UDPStream,self).__init__(pkt)
	        self.sport = pkt.sport
		self.dport = pkt.dport        
	def add(self,pkt):
		self.pkt_count += 1
		self.len += pkt.len
		self.inter_arrival_times.append(pkt.time - self.time)
		self.pkt = pkt
		self.payload += self.get_payload()

	def remove(self,pkt):
		raise Exception('Not Implemented')
