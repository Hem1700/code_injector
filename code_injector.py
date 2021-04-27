import netfilterqueue
import scapy.all as scapy


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # This will convert the packet payload to scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
            print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+]Response")
            print(scapy_packet.show())
    packet.accept()  # This will accept the packet and forward it to the client computer allowing him to go that particular website


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
