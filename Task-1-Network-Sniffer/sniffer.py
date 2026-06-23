from scapy.all import sniff
from scapy.layers.inet import IP
from scapy.packet import Raw

def process_packet(packet):
    # Check if the captured packet has an IP layer
    if packet.haslayer(IP):
        # Extract full length Source and Destination IP addresses
        src_ip = packet[IP].src       
        dst_ip = packet[IP].dst       
        proto = packet[IP].proto              
        
        # Determine the protocol name for better readability
        proto_name = "Other"
        if proto == 6: proto_name = "TCP"
        elif proto == 17: proto_name = "UDP"
        elif proto == 1: proto_name = "ICMP"

        # Check for data payload and calculate its full size
        payload_data = "No Payload Data"
        payload_size_str = "0 bytes (No Payload)"
        
        if packet.haslayer(Raw):
            raw_payload = packet[Raw].load
            # Calculate total payload size in bytes (shows the real full size)
            payload_size_str = f"{len(raw_payload)} bytes"
            # Grab just the first 50 characters to keep the screen presentation neat
            payload_data = repr(raw_payload)[:50] + "..."

        # Print all the data out line-by-line cleanly
        print(f"[+] Protocol: {proto_name}")
        print(f"    Source IP:       {src_ip}")
        print(f"    Destination IP:  {dst_ip}")
        print(f"    Payload Status:  {payload_size_str}")
        print(f"    Payload Preview: {payload_data}")
        print("-" * 60) # Clean separator between each packet

print("=========================================")
print("      BASIC NETWORK SNIFFER ACTIVE  ")
print("    (Press Ctrl+C in CMD to stop me)     ")
print("=========================================")

# Start sniffing live traffic
sniff(prn=process_packet, store=False)
