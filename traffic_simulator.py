#!/usr/bin/env python3
import csv
import random
import argparse
from scapy.all import *
from scapy.layers.inet import TCP, UDP, ICMP, IP

def generate_random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def send_packet(target_ip, target_port, packet_size, attack_mode, label, spoof_ip=False, pcap_file=None):
    try:
        source_ip = generate_random_ip() if spoof_ip else '192.168.1.100'
        source_port = random.randint(1024, 65535)
        
        if attack_mode == 'syn':
            packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=target_port, flags='S')
        elif attack_mode == 'udp':
            packet = IP(src=source_ip, dst=target_ip) / UDP(sport=source_port, dport=target_port)
        elif attack_mode == 'icmp':
            packet = IP(src=source_ip, dst=target_ip) / ICMP()
        elif attack_mode == 'http':
            payload = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(target_ip)
            packet = IP(src=source_ip, dst=target_ip) / TCP(sport=source_port, dport=80, flags='PA') / payload
        
        if pcap_file:
            wrpcap(pcap_file, packet, append=True)
        
        send(packet, verbose=False)

        # Log packet details for dataset
        with open('traffic_log13.csv', 'a', newline='') as file:
                writer = csv.writer(file)
                writer.writerow([
                    datetime.now().isoformat(), source_ip, target_ip, source_port, target_port,
                    packet_size, attack_mode, label, len(packet), packet.summary()
                ])
    except Exception as e:
        print(f"Error while sending packet: {e}")

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Simulator for ML Training")
    parser.add_argument('-t', '--target', required=True, help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=80, help='Target port number')
    parser.add_argument('-n', '--normal', type=int, default=100, help='Number of normal packets to send')
    parser.add_argument('-m', '--malicious', type=int, default=100, help='Number of malicious packets to send')
    parser.add_argument('--pcap', type=str, help='PCAP file path to save outgoing packets')

    args = parser.parse_args()
    print(args)
    # Create CSV file and write header
    with open('traffic_log13.csv', 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['timestamp', 'source_ip', 'target_ip', 'source_port', 'target_port',
                         'packet_size', 'attack_mode', 'label', 'packet_length', 'packet_summary'])

    # Send normal traffic
    for _ in range(args.normal):
        send_packet(args.target, args.port, 60, 'http', 'normal', spoof_ip=False, pcap_file=args.pcap)

    # Send malicious traffic
    for _ in range(args.malicious):
        attack_mode = random.choice(['syn', 'udp', 'icmp'])  # Randomly select an attack type
        packet_size = random.randint(40, 1500) 
        send_packet(args.target, args.port, packet_size, attack_mode, 'malicious', spoof_ip=True, pcap_file=args.pcap)

if __name__ == '__main__':
    main()
