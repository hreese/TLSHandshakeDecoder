goTLSHelloDecoder
=================

Decode a pcap file containing TLS Handshakes

Input files are created using:
```
tcpdump -nn -i any -w outfile.pcap 'tcp and port 443 and tcp[(((tcp[12:1] & 0xf0) >> 2)):1] = 0x16 and ((tcp[(((tcp[12:1] & 0xf0) >> 2)+5):1] = 0x01) or (tcp[(((tcp[12:1] & 0xf0) >> 2)+5):1] = 0x02))'
```

Short explanation: Listen to packets on port 443 (https), find offset of tcp payload and check if it starts with the TLS magic number and version SSLVv3 or TLSv1.x.
