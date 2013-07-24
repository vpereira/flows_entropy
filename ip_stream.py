from scapy.all import *
import scapy
from numpy import *
from entropy import kolmogorov, shannon

class IPStream(object):
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



