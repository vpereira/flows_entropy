#!/usr/bin/env python
import sys
import hashlib
from hashlib import md5
from scapy.all import *
from tcp_stream  import TCPStream
from udp_stream  import UDPStream
from icmp_stream import ICMPStream
import argparse
from scipy.stats import chisquare

def create_forward_flow_key(pkt):
        #XXX: hack for ICMP
        if pkt.proto == 1: pkt.sport = 0;pkt.dport =0;
	return "%s:%s->%s:%s:%s"%(pkt.src,pkt.sport,pkt.dst,pkt.dport,pkt.proto)
def create_reverse_flow_key(pkt):
        #XXX: hack for ICMP
        if pkt.proto == 1: pkt.sport = 0;pkt.dport =0;
	return "%s:%s->%s:%s:%s"%(pkt.dst,pkt.dport,pkt.src,pkt.sport,pkt.proto)
def create_flow_keys(pkt):
	return create_forward_flow_key(pkt),create_reverse_flow_key(pkt)

def lookup_stream(key,reverse_key):

	if key in flows.keys():
		return key,flows[key]
	elif reverse_key in flows.keys():
		return reverse_key,flows[reverse_key]
	else: 
		return key,None


parser = argparse.ArgumentParser(description='Process a pcap file, generating the flows and output it as arff or csv')
parser.add_argument('-i',help="pcap file to be readin",required=True)
parser.add_argument('-o',help="output file to be written")
args = parser.parse_args()

pcap_file = args.i

packets=rdpcap(pcap_file)

flows = {}


for pkt in packets:
         #filtering IP,TCP an UDP
         if not IP in pkt: continue
         if not pkt[IP].proto in [1,6,17]: continue

	 flow_tuple = reverse_flow_tuple = key_to_search = None
	 flow_tuple,reverse_flow_tuple = create_flow_keys(pkt[IP])
	 flow_key,stream = lookup_stream(flow_tuple,reverse_flow_tuple)

	 if stream is None:
           if pkt[IP].proto == 6:
	       stream = TCPStream(pkt[IP])
           elif pkt[IP].proto == 17:
               stream = UDPStream(pkt[IP])
           elif pkt[IP].proto == 1:
               stream = ICMPStream(pkt[IP])
           else:
               pass
	 else:
	   stream.add(pkt[IP])

         if stream: flows[flow_key] = stream

print "flow,entropy,chi test,pvalue"
for idx,flow in enumerate(flows.values()):
  #filter flows with less than 5 packets
  #it was just used in this python script. its not how we are doing 
  #http://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.chisquare.html#scipy.stats.chisquare
  #this filter probably just make sense for TCP, but some how it drops the number of flows without an expressive p-value
  if flow.pkt_count <=5: continue
  print "{0},{1},{2!r},{3!r}".format(idx,flow.avrg_shannon(),round(flow.chi()[0],4),flow.chi()[1])
