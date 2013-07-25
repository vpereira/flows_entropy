from scapy.all import *
import scapy
from numpy import *
from entropy import kolmogorov, shannon, entropy_ideal

class IPStream(object):
  def __init__(self,pkt):
	self.src = pkt.src 
	self.dst = pkt.dst
	self.time = pkt.time
	self.proto = pkt.proto
	self.inter_arrival_times = [0]
	self.pkt_count = 1
	self.len = pkt.len
        if pkt.proto == 1:
          self.payload = str(pkt[ICMP].payload)
        elif pkt.proto == 6:
          self.payload = str(pkt[TCP].payload)
        elif pkt.proto == 17:
          self.payload = str(pkt[UDP].payload)
        else:
          raise Exception("Protocol Unknown")
	self.pkt = pkt

  def avrg_len(self):
   return self.len/self.pkt_count

  def kolmogorov(self):
   return round(kolmogorov(self.payload),4)

  def shannon(self):
   return round(shannon(self.payload),4)

  def avrg_payload_len(self):
   return len(self.payload)/self.pkt_count

  def entropy(self):
    return round(entropy_ideal(len(self.payload)),4)

  def avrg_inter_arrival_time(self):
   return round(mean(self.inter_arrival_times),4)



