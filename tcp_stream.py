from ip_stream import *

#We are assuming:
#1) Its an IP packet
#2) Its an TCP packet
class TCPStream(IPStream):
	def __init__(self,pkt):
                super(TCPStream,self).__init__(pkt)
		self.flags = [pkt.sprintf("%TCP.flags%")]
		self.sport = pkt.sport
		self.dport = pkt.dport        

        def unique_flags(self):
	    seen = set()
	    for item in self.flags:
	        if item not in seen:
	            seen.add( item )
		    yield item

	def push_flag_ratio(self):
		return len([ f for f in self.flags if 'P' in f ]) / float(len(self.flags))

	def add(self,pkt):
                super(TCPStream,self).add(pkt)
		self.flags.append(pkt.sprintf("%TCP.flags%"))

	def remove(self,pkt):
		raise Exception('Not Implemented')
