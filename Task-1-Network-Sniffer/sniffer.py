from scapy.all import sniff
from scapy.layers.inet import IP

def process_packet(packet):
    # Check if the captured packet has an IP layer (envelope)
    if packet.haslayer(IP):
        src_ip = packet[IP].src       # Who sent it
        dst_ip = packet[IP].dst       # Who is receiving it
        proto = packet[IP].proto      # The protocol number (e.g., 6 for TCP, 17 for UDP)
        
        # Determine the protocol name for better readability
        proto_name = "Other"
        if proto == 6: proto_name = "TCP"
        elif proto == 17: proto_name = "UDP"
        elif proto == 1: proto_name = "ICMP"

        print(f"[+] Protocol: {proto_name} | Source: {src_ip} -> Destination: {dst_ip}")

print("=========================================")
print("     MY BASIC NETWORK SNIFFER STARTING   ")
print("    (Press Ctrl+C in CMD to stop me)     ")
print("=========================================")

# sniff() will now run forever, and pass every packet it finds to our process_packet function
sniff(prn=process_packet, store=False)
