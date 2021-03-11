import time

from cmd2 import with_argparser, with_category
import argparse

from prettytable import PrettyTable
from scapy.layers.inet import TCP, IP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sr1, sr
from scapy.volatile import RandShort

from framework.src.interfaces import InterfaceMixin


class NetworkScannerMixin(InterfaceMixin):
    """Mixin Class to scan the network"""

    def __init__(self):
        # list of clients in the network
        super().__init__()
        self.clients = []

    scans_parser = argparse.ArgumentParser()
    scans_parser.add_argument('-c', '--cached', help='select the results of the last network scan performed')
    scans_parser.add_argument('-c_scan', '--connect_scan',
                              help='scan the devices ports in the network with three-way handshake')

    @with_category(InterfaceMixin.CMD_CAT_BROKER_OP)
    @with_argparser(scans_parser)
    def do_scan(self, args):
        if args.cached:
            self.handle_cache()
        else:
            self.run_arp_scan()

        time.sleep(2)

        client = self.clients[0]
        self.connect_scan(client['ip'])

    def show_clients(self):

        scans_table = PrettyTable(field_names=[
            'IP Address', 'MAC Address'
        ])

        # print clients
        print("Available devices in the network:")
        for client in self.clients:
            scans_table.add_row([client['ip'], client['mac']])

        self.ppaged(msg=str(scans_table))

    def run_arp_scan(self):
        # TODO: Add retrival from file

        target_ip = "192.168.1.1/24"  # IP Address for the destination
        arp = ARP(pdst=target_ip)  # create ARP packet
        # create the Ether broadcast packet
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
        packet = ether / arp  # stack them

        result = srp(packet, timeout=5, verbose=True)[
            0]  # result is list of pairs with format (sent_packet, received_packet)

        for sent, received in result:
            # for each response, append ip and mac address to `clients` list
            self.clients.append({'ip': received.psrc, 'mac': received.hwsrc})

        self.show_clients()

    def handle_cache(self):
        # TODO: Add retrival from file
        pass

    def connect_scan(self, destination_ip):
        src_port = RandShort()
        dst_port = 80

        tcp_connect_scan_resp = sr1(IP(dst=destination_ip) / TCP(sport=src_port, dport=dst_port, flags="S"), timeout=10,
                                    verbose=True)

        if str(type(tcp_connect_scan_resp)) == "<type ‘NoneType’>":
            print("Closed")
        elif tcp_connect_scan_resp.haslayer(TCP):
            if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12:
                send_rst = sr(IP(dst=destination_ip) / TCP(sport=src_port, dport=dst_port, flags="AR"), timeout=10,
                              verbose=True)
                print("Open")
                print(send_rst)
            elif tcp_connect_scan_resp.getlayer(TCP).flags == 0x14:
                print("Closed")

    def stealth_scan(self):
        pass

    def xmas_scan(self):
        pass

    def tcp_ack_scan(self):
        pass
