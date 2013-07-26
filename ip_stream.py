from scapy.all import *
from numpy import mean,sum,std
from entropy import shannon
from scipy.stats import chisquare,np

class IPStream(object):
  def __init__(self,pkt):
	self.src = pkt.src 
	self.dst = pkt.dst
	self.time = pkt.time
	self.proto = pkt.proto
	self.pkt_count = 1
	self.len = pkt.len
        self.shannon_pkt = [shannon(self.get_payload(pkt))]

  def add(self,pkt):
	self.pkt_count += 1
	self.len += pkt.len
	self.shannon_pkt.append(shannon(self.get_payload(pkt)))

  def avrg_len(self):
   return self.len/self.pkt_count

  def entropy_sd(self):
    return std(self.shannon_pkt)

  def entropy_mean(self):
    return mean(self.shannon_pkt)

  def chi(self):
    if self.entropy_mean() <= 0.0: return (0.0,0.0)
    return (chisquare(np.array(self.shannon_pkt)))
  
  def get_payload(self,pkt):
    if pkt.proto == 1:
        return str(pkt[ICMP].payload)
    elif pkt.proto == 6:
        return str(pkt[TCP].payload)
    elif pkt.proto == 17:
        return str(pkt[UDP].payload)
    else:
        return None
