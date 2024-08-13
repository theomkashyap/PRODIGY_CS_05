import scapy.all as scapy

print("NETWORK PACKET ANALYZER PROGRAM")

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Source IP: {src_ip} | Destination IP: {dst_ip} | Protocol: {protocol}")

        if packet.haslayer(scapy.TCP):
            print("TCP Packet")
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"TCP Payload: {decoded_payload}")
                except UnicodeDecodeError:
                    print("Unable to decode TCP payload.")
            else:
                print("No TCP payload found.")

        elif packet.haslayer(scapy.UDP):
            print("UDP Packet")
            if packet.haslayer(scapy.Raw):
                try:
                    payload = packet[scapy.Raw].load
                    decoded_payload = payload.decode('utf-8', 'ignore')
                    print(f"UDP Payload: {decoded_payload}")
                except UnicodeDecodeError:
                    print("Unable to decode UDP payload.")
            else:
                print("No UDP payload found.")

def start_sniffing():
    scapy.sniff(store=False, prn=packet_callback, filter="ip")

start_sniffing()
