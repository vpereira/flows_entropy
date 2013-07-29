import zlib
from math import log

# Caculate shannon entropy of a set of data
def shannon (data):
    # Whithin the for statement, we determine the frequency of each byte
    # in the dataset and if this frequency is not null we use it for the
    # entropy calculation

   dataSize = len(data)
   ent = 0.0
   freq={}
   for c in data:
      if freq.has_key(c):
         freq[c] += 1
      else:
         freq[c] = 1

   # a byte can take 256 values from 0 to 255. Here we are looping 256 times
   # to determine if each possible value of a byte is in the dataset
   for key in freq.keys():
      f = float(freq[key])/dataSize+0.0
      if f > 0: # to avoid an error for log(0)
         ent = ent + f * log(f, 2)
   return -ent  if ent else 0.00

#Calculates the ideal Shannon entropy of payload with a specific len
def entropy_ideal(length):
    if length == 0: return 0.0
    prob = 1.0 / length + 0.0
    return -1.0 * length * prob * log(prob) / log(2.0)


# Reasonable approximation to the Kolmogorov Complexity
# using the compression rate
# ref.: http://lorenzoriano.wordpress.com/tag/python/
def kolmogorov(data):
   if data == None or data == '':
   	return 0.0

   l = float(len(data))
   compr = zlib.compress(data)
   c = float(len(compr))/l
   if c > 1:
     return 1.0
   else:
     return c
