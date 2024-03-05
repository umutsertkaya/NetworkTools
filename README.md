# NetworkTools

With this tool, network discovery can be done with arp and ping queries, and port scanning can be done with 2 methods offered separately.
Please download the necessary python libraries before use:  Scapy & nmap.
Usage:
  To perform network discovery with Arp or Ping scan (-P, -A) please specify the target ip block with --ip (e.g. 192.168.1)
  To perform port scanning, please enter the target ports e.g. (80,443) or the target port range e.g. (80-443) after (--port, --nmap_port). Afterwards, please provide   the destination ip information with the --port_ip parameter.
