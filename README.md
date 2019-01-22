# Firewall

This assignment is to filter network packets using a set of rules.

A)how you tested your solution
The solution is tested using some test cases which include cases like-

Block packets when-
1. rule is not present, 
2. port is invalid, 
3. IP not within range, 
4. invalid direction,
5. invalid protocol.

Allow packets when-
1. There is exact match,
2. IP within range,
3. Packet matches protocol, 
4. Packets match direction,
5. Ports within range. 

B) Any interesting coding, design, or algorithmic choices you’d like to point out
In order to check if the IPs lie within range-
1. IP has 4 octets. 
   Each IP is converted to an integer for range comparison with the input IP.
   
2. Ports are also parsed and range compared with input port.

3. The code is tested using a generated test file with 500K and 1M records. 
   7 calls to test packets run in 4 seconds using 500K records rules file.
   Approximately 2216 ms time is taken to scan 1M records file and filtering a packet.

C) any refinements or optimizations that you would’ve implemented if you had
   more time
   
1. I would have generated the test csv file by generating port values from 
   any random port to a value greater than the lower bound port.

2. I would have generated the test csv file by generating IP values from 
   any random IP to an IP greater than the lower bound IP.  

This will help in more realistic testing. Currently, the generated csv test file 
has port ranges from 0 to any random port, and IP ranges from 0.0.0.0 to any random 
IP.    
