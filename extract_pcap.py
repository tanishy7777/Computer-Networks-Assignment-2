import os
from scapy.all import PcapReader, DNS, DNSQR

PCAP_FILES = {
    'PCAPs/PCAP_1_H1.pcap': 'urls_h1.txt',
    'PCAPs/PCAP_2_H2.pcap': 'urls_h2.txt',
    'PCAPs/PCAP_3_H3.pcap': 'urls_h3.txt',
    'PCAPs/PCAP_4_H4.pcap': 'urls_h4.txt',
}

def extract():
    print("Starting...")

    for pcap_file, out_file in PCAP_FILES.items():
        print(f"Processing {pcap_file}: {out_file}")
        
        unq = set()
        
        try:
            with PcapReader(pcap_file) as pcap_reader:
                for pkt in pcap_reader:
                    if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                        try:
                            qname = pkt[DNSQR].qname.decode('utf-8').rstrip('.')
                            if qname:
                                unq.add(qname)

                        except Exception:
                            pass

            with open(out_file, 'w') as f:
                for domain in sorted(unq):
                    f.write(f"{domain}\n")
            
            print(f"Done, got {len(unq)} unique domains")

        except Exception as e:
            print(f"Error processing {pcap_file}: {e}")

if __name__ == "__main__":
    extract()
