from scapy.all import *
import scapy
from numpy import *
from entropy import shannon

class IPStream(object):
  def __init__(self,pkt):
	self.src = pkt.src 
	self.dst = pkt.dst
	self.time = pkt.time
	self.proto = pkt.proto
	self.inter_arrival_times = [0]
	self.pkt_count = 1
	self.len = pkt.len
        self.shannon_pkt = [shannon(self.get_payload(pkt))]

  def add(self,pkt):
	self.pkt_count += 1
	self.len += pkt.len
	self.inter_arrival_times.append(pkt.time - self.time)
	self.shannon_pkt.append(shannon(self.get_payload(pkt)))


  def avrg_len(self):
   return self.len/self.pkt_count

  def avrg_inter_arrival_time(self):
   return round(mean(self.inter_arrival_times),4)

  def avrg_shannon(self):
    return round(mean(self.shannon_pkt),4)

  def get_payload(self,pkt):
    if pkt.proto == 1:
        return str(pkt[ICMP].payload)
    elif pkt.proto == 6:
        return str(pkt[TCP].payload)
    elif pkt.proto == 17:
        return str(pkt[UDP].payload)
    else:
        return None
