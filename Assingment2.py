from scapy.all import *

# Define the IP address and port number for the server
ip_address = '127.0.0.1'
port = 5000

# Define the delay time in milliseconds
delay_ms = 1000

# Define the packet delay function
def delay_packet(packet):
    time.sleep(delay_ms / 1000.0)
    send(packet)

# Create a sniffing filter to capture incoming TCP packets
filter = 'tcp and dst host {} and dst port {}'.format(ip_address, port)

# Start sniffing incoming TCP packets
sniff(filter=filter, prn=delay_packet)
