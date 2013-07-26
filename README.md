ENTROPY METER for IP FLOWS
==========================

Proof of concept adapted from our nextgen fw. 

Requirements:

  - scipy
  - numpy
  - scapy


How to interpret the values:

 from ent(1):

 *We interpret the percentage as the degree to which the sequence tested is suspected of being non-random. 
 If the percentage is greater than 99% or less than 1%, the sequence is almost certainly not random. 
 If the percentage is between 99% and 95% or between 1% and 5%, the sequence is suspect. 
 Percentages between 90% and 95% and 5% and 10% indicate the sequence is “almost suspect”*
 
 What I want to observe:

 * using shannon as statistic, identify encrypted flows.

 * questions to be answered:

 * is chisquare cdf a good test?

 * entropy + stddev as factor to decide if it is encrypted or compressed?


