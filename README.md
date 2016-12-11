Use Linux to run
have a input pcap file and a rule text available to read

1. Compile both the firewall cpp file
	
gcc firewall firewall.cpp -lpcap


2. Make sure the rule file is in this format
	<Source IP> <Dest IP> <Source port> <Dest port>
    <Source IP> <Dest IP> <Source port> <Dest port>

	EX: 10.1.1.1 10.1.1.2 5000 80
        ...
        ...
   The number of rule sets is not limited.

3. run the file 
	./firewall <rule.txt> <input.pcap> <output.pcap>

