from ip_stream import *

#We are assuming:
#1) Its an IP packet
#2) Its an UDP packet
class UDPStream(IPStream):
	def __init__(self,pkt):
                super(UDPStream,self).__init__(pkt)
	        self.sport = pkt.sport
		self.dport = pkt.dport        
	def remove(self,pkt):
		raise Exception('Not Implemented')
