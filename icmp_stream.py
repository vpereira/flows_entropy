from ip_stream import *

#We are assuming:
#1) Its an IP packet
#2) Its an ICMP packet
#XXX icmp type and code as flow information?
class ICMPStream(IPStream):
	def __init__(self,pkt):
                super(ICMPStream,self).__init__(pkt)
		self.sport = 0
		self.dport = 0        
	def remove(self,pkt):
		raise Exception('Not Implemented')
