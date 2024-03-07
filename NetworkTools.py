import argparse
from scapy.all import *
import nmap


try:
    def ping_query(targetip):
        ip = IP()
        icmp = ICMP()
        on_ip = []
        for i in range(1,256):
            ip.dst = targetip+f"{i}"
            pak = ip/icmp
            ans= sr1(pak, timeout = 0.5, verbose = False)
            print(pak[IP].dst," : scanned")
            if(ans):
                on_ip.append(pak[IP].dst)
            else:
                pass

        for a in on_ip:
            print(a,"active device...")

    def arp_query(arp_target):
        eth = Ether()
        arp = ARP()
        eth.dst = "ff:ff:ff:ff:ff:ff"
        arp.pdst = arp_target
        arp_pak = eth/arp
        cev,uncev = srp(arp_pak, timeout=5)
        for re, unre in cev:
            print(unre.psrc," : ",re.src)

        
                
    def port_scanner(targeti, target_ports):
        try:
            if "-" in target_ports:
                first_port, last_port = map(int, target_ports.split("-"))
                for port in range(first_port, last_port + 1):
                    port_packet = IP(dst=targeti) / TCP(dport=port, flags="S")
                    response, _ = sr(port_packet, timeout=5)

                    for send, recv in response:
                        if recv.haslayer(TCP) and recv.getlayer(TCP).flags == 0x12:
                            print(f"{send.dport} : Open - Service: {recv.sprintf('%TCP.payload%')}")
                        else:
                            print(f"{send.dport} : Close")

            else:
                print("Please enter a port range...")
                

        except Exception as error2:
            print("We encountered an error...")

    def nmap_ports(nmap_target_ip, nmap_target_ports):
        try:
            nmp = nmap.PortScanner()
            nmp.scan(nmap_target_ip, nmap_target_ports)
            for nmport in nmp[nmap_target_ip]["tcp"]:
                if nmp[nmap_target_ip]["tcp"][nmport]["state"] == "open":
                    print(f"{nmport} : Open - Services : {nmp[nmap_target_ip]['tcp'][nmport]['name']}")
        except Exception as nmap_error:
            print(nmap_error)


    if __name__ == "__main__":
        parser = argparse.ArgumentParser()
        parser.add_argument("-P","--ping", action="store_true", help="Network discovery with ping method...")
        parser.add_argument("-A","--arp", action="store_true", help="Network discovery with arp query...")
        parser.add_argument("--ip", type=str, help="Enter target IP block...")
        parser.add_argument("-p","--port", action="store_true", help="Port scan...")
    
        parser.add_argument("ports", type=str,nargs="?",help="Enter the target port range e.g. (0-80)...")
        parser.add_argument("--port_ip","-pi", type=str, help="The target ip for port scanning...")
        parser.add_argument("-np","--nmap_port", action="store_true", help="Detailed port scan with Nmap tool...")
        args = parser.parse_args()

        if args.ping:
            target_ip = args.ip+"."
            ping_query(target_ip)
        elif args.arp:
            arp_target_ip = args.ip + ".1/24"
            arp_query(arp_target_ip)
        elif args.port:

            port_scanner(args.port_ip,args.ports)

        elif args.nmap_port:
            nmap_ports(args.port_ip, args.ports)

except Exception as e :
    print("We encountered an error!...\n"+ "#"*100)
    print("To perform network discovery with Arp or Ping scan (-P, -A) please specify the target ip block with --ip (e.g. 192.168.1) \n"+"#"*100)
    print("To perform port scanning, please enter the target ports e.g. (80,443) or the target port range e.g. (80-443) after (--port, --nmap_port). Afterwards, please provide the destination ip information with the --port_ip parameter.")
