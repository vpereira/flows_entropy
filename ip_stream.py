from scapy.all import *
from numpy import mean,sum,std
from entropy import shannon
from scipy.stats import chisquare,np,chi2

class IPStream(object):
  def __init__(self,pkt):
	self.src = pkt.src 
	self.dst = pkt.dst
	self.time = pkt.time
	self.proto = pkt.proto
	self.pkt_count = 1
        self.shannon_pkt = [shannon(self.get_payload(pkt))]
        self.payload_sizes = [len(self.get_payload(pkt))]

  def add(self,pkt):
	self.pkt_count += 1
	self.shannon_pkt.append(shannon(self.get_payload(pkt)))
	self.payload_sizes.append(len(self.get_payload(pkt)))

  def entropy_sd(self):
    return std(self.shannon_pkt)

  def entropy_mean(self):
    return mean(self.shannon_pkt)

  def expected_value(self,k):
    #We expect the probability of each ASCII in a encrypted payload to be 1/256
    return (1/256.0) * self.payload_sizes[k]

  def chi(self):
    chis = sum([((o-self.expected_value(k))**2)/self.expected_value(k) for k, o in enumerate(self.shannon_pkt)]) 
    #maybe df should be 31 (32-1), the number of bins that we have.. 
    return 1-chi2.cdf(chis,len(self.payload_sizes)-1)
  
  def get_payload(self,pkt):
    if pkt.proto == 1:
        return pkt[ICMP].payload
    elif pkt.proto == 6:
        return pkt[TCP].payload
    elif pkt.proto == 17:
        return pkt[UDP].payload
    else:
        return None
